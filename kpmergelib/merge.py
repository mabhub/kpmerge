"""Merging two groups of a KeePass XML export. The input trees are never modified."""
import copy
import xml.etree.ElementTree as ET

from . import xmltree
from .report import Conflict, Report


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


def _merge_level(a: ET.Element | None, b: ET.Element | None, path: str,
                 binaries: dict[str, bytes], report: Report) -> ET.Element:
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

    for ea in entries_a:
        key = xmltree.entry_key(ea)
        if paired(key):
            eb = by_key_b[key][0]
            entry, winner, fields = merge_pair(ea, eb, binaries)
            if fields:
                report.merged += 1
                report.conflicts.append(
                    Conflict(path, xmltree.entry_title(entry), fields, winner))
            else:
                report.identical += 1
            out.append(entry)
        else:
            # No pair (or duplicate key: handled later): copied as is.
            if key not in by_key_b:
                report.only_a += 1
            out.append(copy.deepcopy(ea))
    for eb in entries_b:
        key = xmltree.entry_key(eb)
        if paired(key):
            continue
        if key not in by_key_a:
            report.only_b += 1
        out.append(copy.deepcopy(eb))

    subs_a: dict[str, ET.Element] = {}
    subs_b: dict[str, ET.Element] = {}
    for node, subs in ((a, subs_a), (b, subs_b)):
        for g in node.findall("Group") if node is not None else []:
            subs.setdefault(_name(g), g)  # same-name subgroups on one side: not handled
    names = list(subs_a) + [n for n in subs_b if n not in subs_a]
    for name in names:
        sub_path = f"{path}/{name}" if path else name
        out.append(_merge_level(subs_a.get(name), subs_b.get(name), sub_path, binaries, report))
    return out


def merge_groups(a: ET.Element, b: ET.Element, binaries: dict[str, bytes],
                 history_max_items: int, history_max_size: int) -> tuple[ET.Element, Report]:
    """Return a new merged group (attributes of A) and the report.

    History limits are not used yet (reporting entries over the limits comes later).
    """
    report = Report()
    merged = _merge_level(a, b, "", binaries, report)
    report.total_entries = sum(1 for _ in xmltree.iter_entries(merged))
    return merged, report
