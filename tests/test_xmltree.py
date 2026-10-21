import unittest
import xml.etree.ElementTree as ET

from kpmergelib.errors import KpmergeError
from kpmergelib.xmltree import (diff_fields, find_group, fingerprint, group_chain,
                                group_path, iter_entries, load_binaries, entry_key,
                                mtime)
from tests.kpxml import E, G, find_entry, make_doc


def parse(groups):
    return ET.fromstring(make_doc(groups))


def fp(e: E) -> bytes:
    doc = parse([G("g", entries=[e])])
    return fingerprint(find_entry(doc, "g", e.title), load_binaries(doc))


class XmlTreeTest(unittest.TestCase):
    def test_find_group_variants(self):
        doc = parse([G("Vault – 2026", groups=[G("Sub-folder")])])
        a = find_group(doc, "Vault – 2026/Sub-folder")
        self.assertEqual(a.findtext("Name"), "Sub-folder")
        self.assertIs(find_group(doc, "/Vault – 2026/Sub-folder/"), a)
        self.assertIs(find_group(doc, "Root/Vault – 2026/Sub-folder"), a)

    def test_find_group_root(self):
        doc = parse([G("A")])
        root = doc.find("Root/Group")
        for p in ("", "/", "Root"):
            self.assertIs(find_group(doc, p), root)
        self.assertEqual([g.findtext("Name") for g in group_chain(doc, "A")], ["Root", "A"])

    def test_find_group_same_name_as_root_prefers_as_given(self):
        doc = parse([G("Root", groups=[G("X")])])
        top = doc.find("Root/Group/Group")
        self.assertIs(find_group(doc, "Root"), top)
        self.assertIs(find_group(doc, "Root/X"), top.find("Group"))
        self.assertIs(find_group(doc, "Root/Root/X"), top.find("Group"))

    def test_find_group_missing(self):
        doc = parse([G("A")])
        with self.assertRaises(KpmergeError) as cm:
            find_group(doc, "Absent")
        self.assertIn("Absent", str(cm.exception))

    def test_find_group_ambiguous_path(self):
        doc = parse([G("P", groups=[G("A")]), G("P", groups=[G("A")])])
        for path in ("P", "P/A"):
            with self.assertRaises(KpmergeError) as cm:
                find_group(doc, path)
            self.assertIn("Ambiguous", str(cm.exception))

    def test_group_path_roundtrip(self):
        doc = parse([G("Vault – 2026", groups=[G("Sub-folder")])])
        for p in ("Vault – 2026", "Vault – 2026/Sub-folder"):
            self.assertEqual(group_path(doc, find_group(doc, p)), p)
        self.assertEqual(group_path(doc, find_group(doc, "/")), "")

    def test_entry_key_and_mtime(self):
        doc = parse([G("g", entries=[E(" T ", username="u ", url=" x", mtime="2026-03-04T05:06:07Z")])])
        e = find_entry(doc, "g", " T ")
        self.assertEqual(entry_key(e), ("T", "u", "x"))
        self.assertEqual(mtime(e).isoformat(), "2026-03-04T05:06:07+00:00")

    def test_fingerprint_ignores_metadata(self):
        self.assertEqual(fp(E("t", password="p", mtime="2026-01-01T00:00:00Z")),
                         fp(E("t", password="p", mtime="2027-05-05T10:00:00Z")))

    def test_fingerprint_sees_content(self):
        base = fp(E("t", password="p", attachments={"a.txt": b"1"}, extra={"otp": "x"}))
        self.assertNotEqual(base, fp(E("t", password="q", attachments={"a.txt": b"1"}, extra={"otp": "x"})))
        self.assertNotEqual(base, fp(E("t", password="p", attachments={"a.txt": b"2"}, extra={"otp": "x"})))
        self.assertNotEqual(base, fp(E("t", password="p", attachments={"a.txt": b"1"}, extra={"otp": "y"})))
        self.assertNotEqual(base, fp(E("t", password="p", attachments={"a.txt": b"1"}, extra={"otp": "x"}, tags="k")))

    def test_diff_fields_names_only(self):
        doc = parse([G("g", entries=[E("t", password="SECRET1", attachments={"a.txt": b"AAA"}),
                                     E("t", password="SECRET2", attachments={"a.txt": b"BBB"})])])
        a, b = doc.findall("Root/Group/Group/Entry")
        diff = diff_fields(a, b, load_binaries(doc))
        self.assertEqual(diff, ["Password", "attachment:a.txt"])
        self.assertNotIn("SECRET", repr(diff))
        self.assertNotIn("AAA", repr(diff))

    def test_diff_fields_empty_iff_same_fingerprint(self):
        doc = parse([G("g", entries=[E("t", mtime="2026-01-01T00:00:00Z"), E("t", mtime="2027-01-01T00:00:00Z")])])
        a, b = doc.findall("Root/Group/Group/Entry")
        bins = load_binaries(doc)
        self.assertEqual(diff_fields(a, b, bins), [])
        self.assertEqual(fingerprint(a, bins), fingerprint(b, bins))

    def test_iter_entries_skips_history(self):
        hist = [E("e", password="old1"), E("e", password="old2")]
        doc = parse([G("g", groups=[G("Sub-folder", entries=[E("e", history=hist)])])])
        found = list(iter_entries(find_group(doc, "g")))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], ("Sub-folder",))

    def test_history_attachments_in_pool(self):
        doc = parse([G("g", entries=[E("e", history=[E("e", attachments={"h": b"hist"})])])])
        self.assertIn(b"hist", load_binaries(doc).values())


if __name__ == "__main__":
    unittest.main()
