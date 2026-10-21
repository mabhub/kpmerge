import unittest
import xml.etree.ElementTree as ET

from kpmergelib import xmltree
from kpmergelib.merge import merge_groups
from kpmergelib.report import Conflict, format_report
from tests.kpxml import E, G, make_doc

T1, T2, T3, T4, T5 = (f"2026-01-0{i}T00:00:00Z" for i in range(1, 6))


def run(a: G, b: G):
    doc = ET.fromstring(make_doc([a, b]))
    ga, gb = xmltree.find_group(doc, a.name), xmltree.find_group(doc, b.name)
    merged, report = merge_groups(ga, gb, xmltree.load_binaries(doc), 10, 6291456)
    return doc, ga, gb, merged, report


def pw(entry: ET.Element) -> str:
    return next(s.findtext("Value") for s in entry.findall("String") if s.findtext("Key") == "Password")


def history(entry: ET.Element) -> list[ET.Element]:
    return entry.findall("History/Entry")


def canon(el: ET.Element) -> str:
    return ET.canonicalize(ET.tostring(el, encoding="unicode"), strip_text=True)


class MergeTest(unittest.TestCase):
    def test_identical_kept_once(self):
        e = E("site", "u", "http://x", "pw", mtime=T1)
        *_, merged, report = run(G("A", [e]), G("B", [e]))
        self.assertEqual(len(merged.findall("Entry")), 1)
        self.assertEqual(report.identical, 1)
        self.assertEqual(report.merged, 0)
        self.assertEqual(history(merged.find("Entry")), [])

    def test_conflict_newer_b_wins(self):
        doc, ga, gb, merged, report = run(
            G("A", [E("site", "u", "", "old", mtime=T1)]),
            G("B", [E("site", "u", "", "new", mtime=T2)]))
        entry = merged.find("Entry")
        self.assertEqual(pw(entry), "new")
        self.assertEqual([pw(h) for h in history(entry)], ["old"])
        self.assertEqual(report.conflicts, [Conflict("", "site", ["Password"], "B")])
        self.assertEqual(report.merged, 1)

    def test_conflict_newer_a_wins(self):
        *_, merged, report = run(
            G("A", [E("site", "u", "", "new", mtime=T2)]),
            G("B", [E("site", "u", "", "old", mtime=T1)]))
        entry = merged.find("Entry")
        self.assertEqual(pw(entry), "new")
        self.assertEqual([pw(h) for h in history(entry)], ["old"])
        self.assertEqual(report.conflicts, [Conflict("", "site", ["Password"], "A")])

    def test_tie_prefers_b(self):
        *_, merged, report = run(
            G("A", [E("site", "u", "", "from-a", mtime=T1)]),
            G("B", [E("site", "u", "", "from-b", mtime=T1)]))
        self.assertEqual(pw(merged.find("Entry")), "from-b")
        self.assertEqual(report.conflicts[0].winner, "B")

    def test_histories_united(self):
        a = E("site", "u", "", "pa", mtime=T4, history=[
            E("site", "u", "", "h1", mtime=T1), E("site", "u", "", "h2", mtime=T3)])
        b = E("site", "u", "", "pb", mtime=T5, history=[
            E("site", "u", "", "h3", mtime=T2), E("site", "u", "", "h2", mtime=T4)])
        *_, merged, report = run(G("A", [a]), G("B", [b]))
        entry = merged.find("Entry")
        self.assertEqual(pw(entry), "pb")
        hist = history(entry)
        # h2 twice (the oldest one, T3, is kept); the loser "pa" is added
        self.assertEqual([pw(h) for h in hist], ["h1", "h3", "h2", "pa"])
        times = [xmltree.mtime(h) for h in hist]
        self.assertEqual(times, sorted(times))
        self.assertEqual({h.findtext("UUID") for h in hist}, {entry.findtext("UUID")})
        self.assertTrue(all(h.find("History") is None for h in hist))

    def test_only_one_side(self):
        *_, merged, report = run(G("A", [E("a-only", "u")]), G("B", [E("b-only", "u")]))
        titles = {xmltree.entry_title(e) for e in merged.findall("Entry")}
        self.assertEqual(titles, {"a-only", "b-only"})
        self.assertEqual((report.only_a, report.only_b), (1, 1))
        self.assertEqual(report.total_entries, 2)

    def test_subgroups_matched_by_name(self):
        a = G("A", [E("r", "u", mtime=T1)], [G("Sub", [E("x", "u", "", "1", mtime=T1)])])
        b = G("B", [], [G("Sub", [E("x", "u", "", "2", mtime=T2)]), G("New", [E("n", "u")]),
                        G("Empty")])
        doc, ga, gb, merged, report = run(a, b)
        names = [g.findtext("Name") for g in merged.findall("Group")]
        self.assertEqual(sorted(names), ["Empty", "New", "Sub"])
        self.assertEqual(merged.findtext("Name"), "A")
        self.assertEqual(report.conflicts[0].path, "Sub")
        sub_group = next(g for g in merged.findall("Group") if g.findtext("Name") == "Sub")
        self.assertEqual([pw(e) for e in sub_group.findall("Entry")], ["2"])
        fresh = next(g for g in merged.findall("Group") if g.findtext("Name") == "New")
        self.assertEqual(fresh.findtext("UUID"), gb.find("Group[Name='New']/UUID").text)
        self.assertEqual(report.only_b, 1)

    def test_inputs_untouched(self):
        a = G("A", [E("x", "u", "", "1", mtime=T1, history=[E("x", "u", "", "0", mtime=T1)])],
              [G("Sub", [E("y", "u", "", "1", mtime=T1)])])
        b = G("B", [E("x", "u", "", "2", mtime=T2)],
              [G("Sub", [E("y", "u", "", "2", mtime=T2)]), G("New", [E("n", "u")])])
        doc = ET.fromstring(make_doc([a, b]))
        ga, gb = xmltree.find_group(doc, "A"), xmltree.find_group(doc, "B")
        before = canon(ga), canon(gb)
        merge_groups(ga, gb, xmltree.load_binaries(doc), 10, 6291456)
        self.assertEqual((canon(ga), canon(gb)), before)

    def test_no_user_or_secret_in_report(self):
        *_, report = run(
            G("A", [E("site", "alice-login", "", "s3cr3t-a", notes="note-a", mtime=T1)]),
            G("B", [E("site", "alice-login", "", "s3cr3t-b", notes="note-b", mtime=T2)]))
        text = repr(report) + format_report(report)
        for forbidden in ("alice-login", "s3cr3t-a", "s3cr3t-b", "note-a", "note-b"):
            self.assertNotIn(forbidden, text)
        self.assertIn("site", text)
        self.assertRegex(format_report(report), r"by A: 0.*by B: 1")


if __name__ == "__main__":
    unittest.main()
