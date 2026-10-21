import unittest
import xml.etree.ElementTree as ET

from kpmergelib import xmltree
from kpmergelib.errors import KpmergeError
from kpmergelib.merge import merge_groups
from kpmergelib.report import (Ambiguous, Conflict, Duplicate, Moved, OverLimit, Probable,
                               format_report)
from tests.kpxml import E, G, make_doc

T1, T2, T3, T4, T5 = (f"2026-01-0{i}T00:00:00Z" for i in range(1, 6))


def run(a: G, b: G, max_items: int = 10, max_size: int = 6291456):
    doc = ET.fromstring(make_doc([a, b]))
    ga, gb = xmltree.find_group(doc, a.name), xmltree.find_group(doc, b.name)
    merged, report = merge_groups(ga, gb, xmltree.load_binaries(doc), max_items, max_size)
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

    def test_homonymous_subgroups_rejected(self):
        dup = G("Personal", groups=[G("Bank", [E("x", "u")]), G("Bank", [E("y", "u")])])
        for side, a, b in (("A", G("A", groups=[dup]), G("B")),
                           ("B", G("A"), G("B", groups=[dup]))):
            with self.subTest(side=side):
                with self.assertRaises(KpmergeError) as ctx:
                    run(a, b)
                msg = str(ctx.exception)
                self.assertIn(f"in {side}: Personal/Bank", msg)


def all_entries(group: ET.Element):
    return [e for _, e in xmltree.iter_entries(group)]


class DuplicatesAndRescueTest(unittest.TestCase):
    def test_duplicate_key_not_merged(self):
        *_, merged, report = run(G("A", [E("Note", password="1"), E("Note", password="2")]),
                                 G("B", [E("Note", password="3")]))
        self.assertEqual(len(all_entries(merged)), 3)
        self.assertEqual(report.duplicates, [Duplicate("", "Note", 2, 1)])
        self.assertEqual((report.merged, report.identical, report.only_a, report.only_b), (0, 0, 0, 0))
        self.assertEqual(report.total_entries, 3)
        self.assertIn("Duplicate keys: 1", format_report(report))

    def test_moved_entry_rescued_by_hash(self):
        a = G("A", groups=[G("Personal", [E("X", "u", "", "pw", mtime=T1)])])
        b = G("B", groups=[G("Pro", [E("X", "u", "", "pw", mtime=T2)])])
        *_, merged, report = run(a, b)
        groups = {g.findtext("Name"): g for g in merged.findall("Group")}
        self.assertEqual(len(groups["Pro"].findall("Entry")), 1)
        self.assertEqual(groups["Personal"].findall("Entry"), [])
        self.assertEqual(report.moved, [Moved("X", "Personal", "Pro", "B")])
        self.assertEqual(report.identical, 1)
        self.assertEqual((report.only_a, report.only_b, report.total_entries), (0, 0, 1))

    def test_moved_entry_a_newer_goes_to_a_path(self):
        a = G("A", groups=[G("Personal", [E("X", "u", "", "pw", mtime=T2)])])
        b = G("B", groups=[G("Pro", [E("X", "u", "", "pw", mtime=T1)])])
        *_, merged, report = run(a, b)
        groups = {g.findtext("Name"): g for g in merged.findall("Group")}
        self.assertEqual(len(groups["Personal"].findall("Entry")), 1)
        self.assertEqual(report.moved[0].kept, "A")

    def test_moved_and_changed_is_probable(self):
        a = G("A", groups=[G("Personal", [E("X", "u", "", "p1", mtime=T1)])])
        b = G("B", groups=[G("Pro", [E("X", "u", "", "p2", mtime=T2)])])
        *_, merged, report = run(a, b)
        self.assertEqual(len(all_entries(merged)), 2)
        self.assertEqual(report.probable, [Probable("X", "Personal", "X", "Pro")])
        self.assertEqual(report.moved, [])
        self.assertEqual((report.only_a, report.only_b), (1, 1))

    def test_repeated_hash_not_rescued(self):
        a = G("A", groups=[G("P1", [E("X", "u", "", "pw")]), G("P2", [E("X", "u", "", "pw")])])
        b = G("B", groups=[G("Q", [E("X", "u", "", "pw")])])
        *_, merged, report = run(a, b)
        self.assertEqual(len(all_entries(merged)), 3)
        self.assertEqual(report.moved, [])
        self.assertEqual(report.identical, 0)
        self.assertEqual(report.ambiguous, [Ambiguous("X", ["P1", "P2"], ["Q"])])
        self.assertEqual(report.probable, [])  # same content: not a probable pair
        self.assertIn("X: P1, P2 (A), Q (B)", format_report(report))

    def test_repeated_hash_on_one_side_only_not_reported(self):
        a = G("A", groups=[G("P1", [E("X", "u", "", "pw")]), G("P2", [E("X", "u", "", "pw")])])
        *_, merged, report = run(a, G("B"))
        self.assertEqual(report.ambiguous, [])

    def test_renamed_entry_is_probable(self):
        *_, merged, report = run(G("A", [E("paypal", "u", "https://p", "pw")]),
                                 G("B", [E("PayPal", "u", "https://p", "pw")]))
        self.assertEqual(report.probable, [Probable("paypal", "", "PayPal", "")])
        self.assertIn("paypal: (root) (A) <-> PayPal: (root) (B)", format_report(report))

    def test_changed_url_is_probable(self):
        *_, merged, report = run(G("A", [E("S", "u", "http://s", "pw")]),
                                 G("B", [E("S", "u", "https://s", "pw")]))
        self.assertEqual(report.probable, [Probable("S", "", "S", "")])

    def test_one_common_field_not_probable(self):
        *_, merged, report = run(G("A", [E("S", "u", "http://a", "pw")]),
                                 G("B", [E("T", "u", "http://b", "pw")]))
        self.assertEqual(report.probable, [])

    def test_empty_fields_do_not_pair(self):
        *_, merged, report = run(G("A", [E("Note 1", notes="x")]), G("B", [E("Note 2", notes="y")]))
        self.assertEqual(report.probable, [])

    def test_duplicate_entries_excluded_from_rescue(self):
        a = G("A", groups=[G("P", [E("N", password="1"), E("N", password="1")])])
        b = G("B", groups=[G("Q", [E("N", password="1")])])
        *_, merged, report = run(a, b)
        self.assertEqual(len(all_entries(merged)), 3)
        self.assertEqual(report.moved, [])
        self.assertEqual(report.duplicates, [Duplicate("P", "N", 2, 0)])
        self.assertEqual((report.only_a, report.only_b), (0, 1))

    def test_history_over_limit(self):
        a = E("s", "u", "", "pa", mtime=T4, history=[E("s", "u", "", "h1", mtime=T1),
                                                     E("s", "u", "", "h2", mtime=T2)])
        b = E("s", "u", "", "pb", mtime=T5)
        *_, merged, report = run(G("A", [a]), G("B", [b]), max_items=2)
        self.assertEqual(len(history(merged.find("Entry"))), 3)
        self.assertEqual(report.over_limit, [OverLimit("", "s", 3)])

    def test_history_size_limit_and_unlimited(self):
        a = E("s", "u", "", "pa", mtime=T2, history=[E("s", "u", "", "h", mtime=T1)])
        *_, report = run(G("A", [a]), G("B"), max_items=-1, max_size=-1)
        self.assertEqual(report.over_limit, [])
        *_, report = run(G("A", [a]), G("B"), max_items=-1, max_size=10)
        self.assertEqual(report.over_limit, [OverLimit("", "s", 1)])

    def test_accents_preserved(self):
        a = G("A", groups=[G("Vault – 2026", [E("Café Zoë", "u", "", "p1", mtime=T1)])])
        b = G("B", groups=[G("Vault – 2026", [E("Café Zoë", "u", "", "p2", mtime=T2)])])
        *_, merged, report = run(a, b)
        sub = merged.find("Group")
        self.assertEqual(sub.findtext("Name"), "Vault – 2026")
        self.assertEqual(xmltree.entry_title(sub.find("Entry")), "Café Zoë")
        text = format_report(report)
        self.assertIn("Café Zoë", text)
        self.assertIn("Vault – 2026", text)

    def test_nothing_lost(self):
        dupa = [E("Note", password="n1"), E("Note", password="n2")]
        a = G("A", [E("same", "u", "", "p", mtime=T1), E("chg", "u", "", "a1", mtime=T1,
                                                        history=[E("chg", "u", "", "a0", mtime=T1)]),
                    E("onlya", "u"), *dupa],
              [G("Personal", [E("mv", "u", "", "p", mtime=T1), E("pm", "u", "", "x1")])])
        b = G("B", [E("same", "u", "", "p", mtime=T2), E("chg", "u", "", "b1", mtime=T2),
                    E("onlyb", "u"), E("Note", password="n3")],
              [G("Pro", [E("mv", "u", "", "p", mtime=T2), E("pm", "u", "", "x2")])])
        doc = ET.fromstring(make_doc([a, b]))
        ga, gb = xmltree.find_group(doc, "A"), xmltree.find_group(doc, "B")
        binaries = xmltree.load_binaries(doc)
        merged, _ = merge_groups(ga, gb, binaries, 10, 6291456)

        def prints(group):
            out = set()
            for _, e in xmltree.iter_entries(group):
                out.add(xmltree.fingerprint(e, binaries))
                out.update(xmltree.fingerprint(h, binaries) for h in history(e))
            return out

        self.assertLessEqual(prints(ga) | prints(gb), prints(merged))


if __name__ == "__main__":
    unittest.main()
