"""Builder of test KeePass XML documents, modelled on `keepassxc-cli export -f xml`.

Documents are built in memory only (never written to disk).
"""
import base64
import gzip
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

ROOT_NAME = "Root"
_ZERO_TIME = "2026-01-01T00:00:00Z"


@dataclass
class E:
    title: str
    username: str = ""
    url: str = ""
    password: str = ""
    notes: str = ""
    mtime: str = _ZERO_TIME
    tags: str = ""
    extra: dict[str, str] = field(default_factory=dict)
    attachments: dict[str, bytes] = field(default_factory=dict)
    history: list["E"] = field(default_factory=list)


@dataclass
class G:
    name: str
    entries: list[E] = field(default_factory=list)
    groups: list["G"] = field(default_factory=list)


def _uuid() -> str:
    return base64.b64encode(uuid.uuid4().bytes).decode()


def _sub(parent: ET.Element, tag: str, text: str | None = None, **attrib) -> ET.Element:
    el = ET.SubElement(parent, tag, attrib)
    if text is not None:
        el.text = text
    return el


def _times(parent: ET.Element, mtime: str) -> None:
    t = _sub(parent, "Times")
    _sub(t, "LastModificationTime", mtime)
    _sub(t, "CreationTime", mtime)
    _sub(t, "LastAccessTime", mtime)
    _sub(t, "ExpiryTime", mtime)
    _sub(t, "Expires", "False")
    _sub(t, "UsageCount", "0")
    _sub(t, "LocationChanged", mtime)


class _Pool:
    """Meta/Binaries pool: identical content, same identifier."""

    def __init__(self) -> None:
        self.ids: dict[bytes, str] = {}

    def ref(self, content: bytes) -> str:
        return self.ids.setdefault(content, str(len(self.ids)))


def _entry(parent: ET.Element, e: E, entry_uuid: str, pool: _Pool) -> ET.Element:
    el = _sub(parent, "Entry")
    _sub(el, "UUID", entry_uuid)
    _sub(el, "IconID", "0")
    _sub(el, "ForegroundColor")
    _sub(el, "BackgroundColor")
    _sub(el, "OverrideURL")
    _sub(el, "Tags", e.tags)
    _times(el, e.mtime)
    for key, value in (("Title", e.title), ("UserName", e.username),
                       ("Password", e.password), ("URL", e.url), ("Notes", e.notes)):
        s = _sub(el, "String")
        _sub(s, "Key", key)
        if key == "Password":
            _sub(s, "Value", value, ProtectInMemory="True")
        else:
            _sub(s, "Value", value)
    for key, value in e.extra.items():
        s = _sub(el, "String")
        _sub(s, "Key", key)
        _sub(s, "Value", value, ProtectInMemory="True")
    for name, content in e.attachments.items():
        b = _sub(el, "Binary")
        _sub(b, "Key", name)
        _sub(b, "Value", None, Ref=pool.ref(content))
    at = _sub(el, "AutoType")
    _sub(at, "Enabled", "True")
    _sub(at, "DataTransferObfuscation", "0")
    _sub(at, "DefaultSequence")
    hist = _sub(el, "History")
    for h in e.history:
        _entry(hist, h, entry_uuid, pool)
    return el


def _group(parent: ET.Element, g: G, pool: _Pool) -> ET.Element:
    el = _sub(parent, "Group")
    _sub(el, "UUID", _uuid())
    _sub(el, "Name", g.name)
    _sub(el, "Notes")
    _sub(el, "IconID", "48")
    _times(el, _ZERO_TIME)
    _sub(el, "IsExpanded", "True")
    _sub(el, "DefaultAutoTypeSequence")
    _sub(el, "EnableAutoType", "null")
    _sub(el, "EnableSearching", "null")
    _sub(el, "LastTopVisibleEntry", "AAAAAAAAAAAAAAAAAAAAAA==")
    for e in g.entries:
        _entry(el, e, _uuid(), pool)
    for sub in g.groups:
        _group(el, sub, pool)
    return el


def make_doc(groups: list[G], history_max_items: int = 10) -> bytes:
    """Complete `KeePassFile` document; `groups` are the children of the root group `Root`."""
    pool = _Pool()
    kf = ET.Element("KeePassFile")
    meta = _sub(kf, "Meta")
    _sub(meta, "Generator", "KeePassXC")
    _sub(meta, "DatabaseName", "Test")
    _sub(meta, "DatabaseDescription")
    _sub(meta, "DefaultUserName")
    _sub(meta, "MaintenanceHistoryDays", "365")
    _sub(meta, "Color")
    _sub(meta, "RecycleBinEnabled", "True")
    _sub(meta, "RecycleBinUUID", "AAAAAAAAAAAAAAAAAAAAAA==")
    _sub(meta, "HistoryMaxItems", str(history_max_items))
    _sub(meta, "HistoryMaxSize", "6291456")
    binaries_el = _sub(meta, "Binaries")  # filled once the groups are built
    cd = _sub(meta, "CustomData")
    item = _sub(cd, "Item")
    _sub(item, "Key", "KPXC_RANDOM_SLUG")
    _sub(item, "Value", "x")

    root = _sub(kf, "Root")
    rg = _sub(root, "Group")
    _sub(rg, "UUID", _uuid())
    _sub(rg, "Name", ROOT_NAME)
    _sub(rg, "Notes")
    _sub(rg, "IconID", "48")
    _times(rg, _ZERO_TIME)
    _sub(rg, "IsExpanded", "True")
    for g in groups:
        _group(rg, g, pool)
    _sub(root, "DeletedObjects")

    for content, bid in pool.ids.items():
        packed = base64.b64encode(gzip.compress(content, mtime=0)).decode()
        _sub(binaries_el, "Binary", packed, ID=bid, Compressed="True")
    return ET.tostring(kf, encoding="utf-8", xml_declaration=True)


def find_entry(doc: ET.Element, group_path: str, title: str) -> ET.Element:
    """Entry `title` located directly in group `group_path` (relative to the root)."""
    node = doc.find("Root/Group")
    for part in [p for p in group_path.strip("/").split("/") if p]:
        node = next(g for g in node.findall("Group") if g.findtext("Name") == part)
    for entry in node.findall("Entry"):
        for s in entry.findall("String"):
            if s.findtext("Key") == "Title" and s.findtext("Value") == title:
                return entry
    raise LookupError(f"{group_path}/{title}")
