"""Merging two groups of a KeePass XML export. The input trees are never modified."""
import copy
from dataclasses import dataclass, field
import xml.etree.ElementTree as ET

from . import xmltree
from .errors import KpmergeError
from .report import Conflict, Duplicate, Moved, OverLimit, Probable, Report


def _history_entries(entry: ET.Element) -> list[ET.Element]:
    return entry.findall("History/Entry")


def merge_pair(ea: ET.Element, eb: ET.Element,
               binaries: dict[str, bytes]) -> tuple[ET.Element, str, list[str]]:
    """Merge two entries with the same key: `(merged, winner "A"|"B", differing fields)`.

    The most recent one wins, B on a tie.
    """
    winner = "A" if xmltree.mtime(ea) > xmltree.mtime(eb) else "B"
    win, lose = (ea, eb) if winner == "A" else (eb, ea)
    win_fp = xmltree.fingerprint(win, binaries)
    identical = win_fp == xmltree.fingerprint(lose, binaries)

    candidates = [copy.deepcopy(h) for h in _history_entries(ea) + _history_entries(eb)]
    if not identical:
        loser = copy.deepcopy(lose)
        for old in loser.findall("History"):
            loser.remove(old)
        candidates.append(loser)

    merged = copy.deepcopy(win)
    uuid = merged.findtext("UUID")
    candidates.sort(key=xmltree.mtime)  # stable sort: A, B, loser on equal dates
    seen = {win_fp}
    kept = []
    for version in candidates:
        fp = xmltree.fingerprint(version, binaries)
        if fp in seen:
            continue
        seen.add(fp)
        for old in version.findall("History"):
            version.remove(old)
        version.find("UUID").text = uuid  # a history version carries its entry's UUID
        kept.append(version)

    for old in merged.findall("History"):
        merged.remove(old)
    hist = ET.SubElement(merged, "History")
    hist.extend(kept)

    fields = [] if identical else xmltree.diff_fields(ea, eb, binaries)
    return merged, winner, fields


def _bare_copy(group: ET.Element) -> ET.Element:
    """Copy of the group (attributes, UUID, dates...) without its entries or subgroups."""
    out = ET.Element(group.tag, group.attrib)
    out.text, out.tail = group.text, group.tail
    for child in group:
        if child.tag not in ("Entry", "Group"):
            out.append(copy.deepcopy(child))
    return out


def _name(group: ET.Element) -> str:
    return group.findtext("Name") or ""


@dataclass
class _Lonely:
    """Entry left alone after key pairing (its copy already placed in `group`)."""

    entry: ET.Element
    path: str
    group: ET.Element


@dataclass
class _Pending:
    lonely_a: list[_Lonely] = field(default_factory=list)
    lonely_b: list[_Lonely] = field(default_factory=list)


def _join(path: str, name: str) -> str:
    return f"{path}/{name}" if path else name


def _merge_level(a: ET.Element | None, b: ET.Element | None, path: str,
                 binaries: dict[str, bytes], report: Report, pending: _Pending) -> ET.Element:
    """Merge level `path`; `a` or `b` is None when the group exists on one side only."""
    out = _bare_copy(a if a is not None else b)
    entries_a = a.findall("Entry") if a is not None else []
    entries_b = b.findall("Entry") if b is not None else []

    by_key_a: dict[tuple, list[ET.Element]] = {}
    by_key_b: dict[tuple, list[ET.Element]] = {}
    for entries, index in ((entries_a, by_key_a), (entries_b, by_key_b)):
        for e in entries:
            index.setdefault(xmltree.entry_key(e), []).append(e)

    def paired(key: tuple) -> bool:
        return len(by_key_a.get(key, ())) == 1 and len(by_key_b.get(key, ())) == 1

    def duplicated(key: tuple) -> bool:
        return len(by_key_a.get(key, ())) > 1 or len(by_key_b.get(key, ())) > 1

    for key in list(by_key_a) + [k for k in by_key_b if k not in by_key_a]:
        if duplicated(key):
            report.duplicates.append(Duplicate(
                path, xmltree.entry_title((by_key_a.get(key) or by_key_b[key])[0]),
                len(by_key_a.get(key, ())), len(by_key_b.get(key, ()))))

    for side, entries, lonely in (("A", entries_a, pending.lonely_a),
                                  ("B", entries_b, pending.lonely_b)):
        for e in entries:
            key = xmltree.entry_key(e)
            if paired(key):
                if side == "B":
                    continue
                entry, winner, fields = merge_pair(e, by_key_b[key][0], binaries)
                if fields:
                    report.merged += 1
                    report.conflicts.append(
                        Conflict(path, xmltree.entry_title(entry), fields, winner))
                else:
                    report.identical += 1
                out.append(entry)
                continue
            copy_ = copy.deepcopy(e)
            out.append(copy_)
            if not duplicated(key):  # duplicate key: copied as is, no fingerprint matching
                lonely.append(_Lonely(copy_, path, out))
                if side == "A":
                    report.only_a += 1
                else:
                    report.only_b += 1

    subs_a: dict[str, ET.Element] = {}
    subs_b: dict[str, ET.Element] = {}
    for side, node, subs in (("A", a, subs_a), ("B", b, subs_b)):
        for g in node.findall("Group") if node is not None else []:
            if _name(g) in subs:
                raise KpmergeError(
                    f"Same-name sibling subgroups in {side}: {_join(path, _name(g))} "
                    "- rename them in KeePassXC before merging.")
            subs[_name(g)] = g
    names = list(subs_a) + [n for n in subs_b if n not in subs_a]
    for name in names:
        out.append(_merge_level(subs_a.get(name), subs_b.get(name), _join(path, name),
                                binaries, report, pending))
    return out


def _rescue_by_hash(pending: _Pending, binaries: dict[str, bytes], report: Report) -> None:
    """Pair the lone entries whose fingerprint is unique on each side."""
    def by_fp(items: list[_Lonely]) -> dict[bytes, list[_Lonely]]:
        index: dict[bytes, list[_Lonely]] = {}
        for item in items:
            index.setdefault(xmltree.fingerprint(item.entry, binaries), []).append(item)
        return index

    index_b = by_fp(pending.lonely_b)
    for fp, items_a in by_fp(pending.lonely_a).items():
        items_b = index_b.get(fp, [])
        if len(items_a) != 1 or len(items_b) != 1:
            continue
        la, lb = items_a[0], items_b[0]
        merged, winner, _ = merge_pair(la.entry, lb.entry, binaries)
        la.group.remove(la.entry)
        lb.group.remove(lb.entry)
        (la if winner == "A" else lb).group.append(merged)
        pending.lonely_a.remove(la)
        pending.lonely_b.remove(lb)
        report.identical += 1
        report.only_a -= 1
        report.only_b -= 1
        report.moved.append(Moved(xmltree.entry_title(merged), la.path, lb.path, winner))


def _find_probable(pending: _Pending, report: Report) -> None:
    for la in pending.lonely_a:
        for lb in pending.lonely_b:
            if xmltree.entry_key(la.entry) == xmltree.entry_key(lb.entry):
                report.probable.append(Probable(xmltree.entry_title(la.entry), la.path, lb.path))


def _history_size(entry: ET.Element, binaries: dict[str, bytes]) -> int:
    hist = entry.find("History")
    if hist is None:
        return 0
    size = len(ET.tostring(hist))
    for ref in hist.findall("Entry/Binary/Value"):
        size += len(binaries.get(ref.get("Ref", ""), b""))
    return size


def _check_history(merged: ET.Element, binaries: dict[str, bytes],
                   max_items: int, max_size: int, report: Report) -> None:
    """A negative limit (KeePass: -1) means unlimited."""
    for rel, entry in xmltree.iter_entries(merged):
        items = len(_history_entries(entry))
        if (0 <= max_items < items) or (0 <= max_size < _history_size(entry, binaries)):
            report.over_limit.append(
                OverLimit("/".join(rel), xmltree.entry_title(entry), items))


def merge_groups(a: ET.Element, b: ET.Element, binaries: dict[str, bytes],
                 history_max_items: int, history_max_size: int) -> tuple[ET.Element, Report]:
    """Return a new merged group (attributes of A) and the report.

    A negative history limit (-1 in KeePass) means unlimited.
    """
    report = Report()
    pending = _Pending()
    merged = _merge_level(a, b, "", binaries, report, pending)
    _rescue_by_hash(pending, binaries, report)
    _find_probable(pending, report)
    _check_history(merged, binaries, history_max_items, history_max_size, report)
    report.total_entries = sum(1 for _ in xmltree.iter_entries(merged))
    return merged, report
