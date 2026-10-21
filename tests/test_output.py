import unittest
import xml.etree.ElementTree as ET

from kpmergelib import xmltree
from kpmergelib.merge import merge_groups
from kpmergelib.output import build_import_document, renew_uuids
from tests.kpxml import E, G, make_doc

ZERO = "AAAAAAAAAAAAAAAAAAAAAA=="


def setup(dest: str = "X/Y", dest_name: str = "Merged"):
    a = G("A", [E("t1", "u", "http://x", "pa", history=[E("t1", "u", "http://x", "old")])])
    b = G("B", [E("t1", "u", "http://x", "pb", mtime="2026-02-01T00:00:00Z"), E("t2")])
    tree = [G("X", groups=[G("Y", groups=[a]), G("Other", [E("other")])]),
            b, G("Z", [E("z")])]
    doc = ET.fromstring(make_doc(tree))
    ga, gb = xmltree.find_group(doc, "X/Y/A"), xmltree.find_group(doc, "B")
    merged, _ = merge_groups(ga, gb, xmltree.load_binaries(doc), 10, 6291456)
    out = build_import_document(doc, dest, dest_name, merged)
    return doc, merged, out


def canon(el: ET.Element) -> str:
    return ET.canonicalize(ET.tostring(el, encoding="unicode"), strip_text=True)


def uuids(el: ET.Element) -> list[str]:
    return [u.text for u in el.iter("UUID")]


class BuildImportDocumentTest(unittest.TestCase):
    def test_only_chain_kept(self):
        _, _, out = setup()
        new = ET.fromstring(out)
        root = new.find("Root/Group")
        self.assertEqual(root.findtext("Name"), "Root")
        self.assertEqual(root.findall("Entry"), [])
        self.assertEqual([g.findtext("Name") for g in root.findall("Group")], ["X"])
        x = root.find("Group")
        self.assertEqual([g.findtext("Name") for g in x.findall("Group")], ["Y"])
        y = x.find("Group")
        self.assertEqual(y.findall("Entry"), [])
        self.assertEqual([g.findtext("Name") for g in y.findall("Group")], ["Merged"])
        names = [g.findtext("Name") for g in new.iter("Group")]
        for absent in ("Other", "Z", "A", "B"):
            self.assertNotIn(absent, names)

    def test_root_as_parent(self):
        _, _, out = setup(dest="")
        root = ET.fromstring(out).find("Root/Group")
        self.assertEqual([g.findtext("Name") for g in root.findall("Group")], ["Merged"])

    def test_ancestors_keep_identity(self):
        doc, _, out = setup()
        new = ET.fromstring(out)
        for path in ("", "X", "X/Y"):
            old_g = xmltree.find_group(doc, path)
            new_g = xmltree.find_group(new, path)
            self.assertEqual(new_g.findtext("UUID"), old_g.findtext("UUID"))
            self.assertEqual(canon(new_g.find("Times")), canon(old_g.find("Times")))

    def test_uuids_renewed(self):
        doc, _, out = setup()
        new = ET.fromstring(out)
        merged = xmltree.find_group(new, "X/Y/Merged")
        self.assertEqual(merged.findtext("Name"), "Merged")
        old = set(uuids(doc))
        fresh = [u.text for u in merged.iter("UUID")]
        self.assertTrue(fresh)
        self.assertFalse(old & set(fresh))
        entries = list(merged.iter("Entry"))
        for e in merged.findall("Entry"):
            for h in e.findall("History/Entry"):
                self.assertEqual(h.findtext("UUID"), e.findtext("UUID"))
        self.assertTrue(any(e.findall("History/Entry") for e in entries))

    def test_meta_untouched_and_deleted_cleared(self):
        doc, merged, _ = setup()
        doc.find("Root/DeletedObjects").append(ET.Element("DeletedObject"))
        new = ET.fromstring(build_import_document(doc, "X/Y", "Merged", merged))
        self.assertEqual(canon(new.find("Meta")), canon(doc.find("Meta")))
        self.assertEqual(len(new.find("Root/DeletedObjects")), 0)

    def test_input_doc_untouched(self):
        doc, merged, _ = setup()
        before_doc, before_merged = canon(doc), canon(merged)
        build_import_document(doc, "X/Y", "Merged", merged)
        self.assertEqual(canon(doc), before_doc)
        self.assertEqual(canon(merged), before_merged)

    def test_declaration_utf8(self):
        _, _, out = setup(dest_name="Merged é")
        self.assertTrue(out.startswith(b"<?xml"))
        self.assertIn("Merged é".encode("utf-8"), out)


class RenewUuidsTest(unittest.TestCase):
    def test_last_top_visible_reset(self):
        doc = ET.fromstring(make_doc([G("A", [E("t")], [G("S", [E("s")])])]))
        g = xmltree.find_group(doc, "A")
        g.find("LastTopVisibleEntry").text = "abc"
        renew_uuids(g)
        self.assertTrue(all(t.text == ZERO for t in g.iter("LastTopVisibleEntry")))


if __name__ == "__main__":
    unittest.main()
