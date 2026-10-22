"""Reading the XML tree of a KeePass export (`keepassxc-cli export -f xml`)."""
import base64
import gzip
import hashlib
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from .errors import KpmergeError


def _root_group(doc: ET.Element) -> ET.Element:
    root = doc.find("Root/Group")
    if root is None:
        raise KpmergeError("Invalid KeePass document: root group missing")
    return root


def _descend(root: ET.Element, parts: list[str]) -> list[ET.Element] | None:
    chain = [root]
    for part in parts:
        found = [g for g in chain[-1].findall("Group") if g.findtext("Name") == part]
        if not found:
            return None
        if len(found) > 1:
            raise KpmergeError(f"Ambiguous path: several sibling groups named '{part}' "
                               "- rename them in KeePassXC.")
        chain.append(found[0])
    return chain


def group_chain(doc: ET.Element, path: str) -> list[ET.Element]:
    """Groups from the root down to the target group, inclusive.

    The path is relative to the root; it is tried as is first, then without
    a first component equal to the root's name.
    """
    root = _root_group(doc)
    parts = [p for p in path.strip("/").split("/") if p]
    chain = _descend(root, parts)
    if chain is None and parts and parts[0] == root.findtext("Name"):
        chain = _descend(root, parts[1:])
    if chain is None:
        raise KpmergeError(f"Group not found: {path}")
    return chain


def find_group(doc: ET.Element, path: str) -> ET.Element:
    return group_chain(doc, path)[-1]


def group_path(doc: ET.Element, group: ET.Element) -> str:
    """Path in `keepassxc-cli` format (without the root's name)."""
    def walk(node: ET.Element, names: list[str]) -> list[str] | None:
        if node is group:
            return names
        for sub in node.findall("Group"):
            found = walk(sub, names + [sub.findtext("Name") or ""])
            if found is not None:
                return found
        return None

    names = walk(_root_group(doc), [])
    if names is None:
        raise KpmergeError("Group not in document")
    return "/".join(names)


def _strings(entry: ET.Element) -> dict[str, str]:
    return {s.findtext("Key") or "": s.findtext("Value") or "" for s in entry.findall("String")}


def entry_key(entry: ET.Element) -> tuple[str, str, str]:
    s = _strings(entry)
    return tuple(s.get(k, "").strip() for k in ("Title", "UserName", "URL"))  # type: ignore[return-value]


def entry_title(entry: ET.Element) -> str:
    return _strings(entry).get("Title", "")


_KDBX4_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)


def _parse_time(text: str) -> datetime:
    """ISO 8601, or KDBX 4: base64 of the seconds since 0001-01-01 UTC (int64 little-endian).

    keepassxc-cli exports ISO dates for a KDBX 3.1 database and base64 ones for KDBX 4.
    """
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raw = base64.b64decode(text, validate=True)  # binascii.Error is a ValueError
        if len(raw) != 8:
            raise ValueError("not a KDBX 4 date") from None
        return _KDBX4_EPOCH + timedelta(seconds=int.from_bytes(raw, "little", signed=True))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def mtime(element: ET.Element) -> datetime:
    text = (element.findtext("Times/LastModificationTime") or "").strip()
    try:
        return _parse_time(text)
    except (ValueError, OverflowError):
        raise KpmergeError("Unreadable modification date "
                           f"in entry '{entry_title(element)}'") from None


def load_binaries(doc: ET.Element) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for b in doc.findall("Meta/Binaries/Binary"):
        raw = base64.b64decode(b.text or "")
        if b.get("Compressed") == "True":
            raw = gzip.decompress(raw)
        out[b.get("ID", "")] = raw
    return out


def _attachments(entry: ET.Element, binaries: dict[str, bytes]) -> dict[str, bytes]:
    out = {}
    for b in entry.findall("Binary"):
        name = b.findtext("Key") or ""
        value = b.find("Value")
        ref = value.get("Ref") if value is not None else None
        if ref is None or ref not in binaries:
            raise KpmergeError(f"Unreadable attachment '{name}' "
                               f"in entry '{entry_title(entry)}'")
        out[name] = binaries[ref]
    return out


def _expiry(entry: ET.Element) -> str:
    """'False' if the entry does not expire, else the expiry date."""
    if (entry.findtext("Times/Expires") or "").strip() == "True":
        return "True:" + (entry.findtext("Times/ExpiryTime") or "")
    return "False"


def _tags(entry: ET.Element) -> str:
    return entry.findtext("Tags") or ""


def fingerprint(entry: ET.Element, binaries: dict[str, bytes]) -> bytes:
    h = hashlib.sha256()

    def put(*items: bytes) -> None:
        for item in items:
            h.update(len(item).to_bytes(8, "big"))
            h.update(item)

    strings = _strings(entry)
    put(str(len(strings)).encode())
    for k, v in sorted(strings.items()):
        put(k.encode(), v.encode())
    atts = _attachments(entry, binaries)
    put(str(len(atts)).encode())
    for name, content in sorted(atts.items()):
        put(name.encode(), hashlib.sha256(content).digest())
    put(_tags(entry).encode(), _expiry(entry).encode())
    return h.digest()


def fingerprints_with_history(group: ET.Element, binaries: dict[str, bytes]) -> Counter[bytes]:
    """Multiset of the fingerprints of the group's entries and of their history versions."""
    out: Counter[bytes] = Counter()
    for _, entry in iter_entries(group):
        out[fingerprint(entry, binaries)] += 1
        for version in entry.findall("History/Entry"):
            out[fingerprint(version, binaries)] += 1
    return out


def diff_fields(a: ET.Element, b: ET.Element, binaries: dict[str, bytes]) -> list[str]:
    """Names (never values) of the fields that differ between `a` and `b`."""
    out = []
    sa, sb = _strings(a), _strings(b)
    for k in sa.keys() | sb.keys():
        if sa.get(k) != sb.get(k):
            out.append(k)
    aa, ab = _attachments(a, binaries), _attachments(b, binaries)
    for k in aa.keys() | ab.keys():
        if aa.get(k) != ab.get(k):
            out.append(f"attachment:{k}")
    if _tags(a) != _tags(b):
        out.append("Tags")
    if _expiry(a) != _expiry(b):
        out.append("Expiry")
    return sorted(out)


def iter_entries(group: ET.Element) -> Iterator[tuple[tuple[str, ...], ET.Element]]:
    def walk(g: ET.Element, rel: tuple[str, ...]):
        for e in g.findall("Entry"):
            yield rel, e
        for sub in g.findall("Group"):
            yield from walk(sub, rel + (sub.findtext("Name") or "",))

    yield from walk(group, ())
