import contextlib
import io
import os
import shutil
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from kpmergelib import keepass
from kpmergelib.errors import KpmergeError
from tests.kpxml import E, G, make_doc

HAS_CLI = shutil.which("keepassxc-cli") is not None
PW = b"test"


def _doc(*entries: E) -> bytes:
    return make_doc([G("Imp", entries=list(entries))])


class NoSecretInArgvTest(unittest.TestCase):
    def test_password_never_in_argv_or_env(self):
        secret = b"s3cr3t-pw"
        fake = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch("subprocess.run", return_value=fake) as run:
            keepass.export_xml(Path("/x/a.kdbx"), secret)
            keepass.import_xml(b"<a/>", Path("/x/b.kdbx"), secret)
            keepass.merge_db(Path("/x/a.kdbx"), Path("/x/b.kdbx"), secret, secret)
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list:
            args = call.args[0] if call.args else call.kwargs["args"]
            for item in args:
                self.assertNotIn(secret, os.fsencode(item))
            env = call.kwargs.get("env")
            if env:
                for k, v in env.items():
                    self.assertNotIn(secret, os.fsencode(k) + os.fsencode(v))
            self.assertIn(secret, call.kwargs["input"])

    def test_newline_in_password_rejected(self):
        with self.assertRaises(KpmergeError):
            keepass.export_xml(Path("/x/a.kdbx"), b"a\nb")

    def test_missing_cli(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(KpmergeError) as cm:
                keepass.export_xml(Path("/x/a.kdbx"), PW)
        self.assertIn("keepassxc-cli", str(cm.exception))

    def test_failure_message_drops_prompts(self):
        err = "Saisir le mot de passe pour déverrouiller a.kdbx: \nEnter password:\nError: bad\n".encode()
        fake = mock.Mock(returncode=1, stdout=b"", stderr=err)
        with mock.patch("subprocess.run", return_value=fake):
            with self.assertRaises(KpmergeError) as cm:
                keepass.export_xml(Path("/x/a.kdbx"), PW)
        self.assertTrue(str(cm.exception).endswith("Error: bad"))
        self.assertNotIn("Saisir", str(cm.exception))  # French keepassxc-cli prompt
        self.assertNotIn("Enter password", str(cm.exception))


@unittest.skipUnless(HAS_CLI, "keepassxc-cli not found")
class IntegrationTest(unittest.TestCase):
    def test_export_import_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "t.kdbx"
            keepass.import_xml(_doc(E("One", attachments={"f.txt": b"hello"})), db, PW)
            out = keepass.export_xml(db, PW)
        root = ET.fromstring(out)
        titles = [s.findtext("Value") for s in root.iter("String") if s.findtext("Key") == "Title"]
        self.assertIn("One", titles)
        self.assertEqual(len(root.findall(".//Entry/Binary")), 1)
        self.assertEqual(root.find(".//Entry/Binary/Key").text, "f.txt")

    def test_merge_adds_entries(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.kdbx", Path(d) / "b.kdbx"
            keepass.import_xml(_doc(E("One")), a, PW)
            keepass.import_xml(_doc(E("Two")), b, PW)
            keepass.merge_db(a, b, PW, PW)
            doc = ET.fromstring(keepass.export_xml(a, PW))
            titles = {s.findtext("Value") for s in doc.iter("String") if s.findtext("Key") == "Title"}
            self.assertEqual(titles, {"One", "Two"})

    def test_wrong_password_message(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "t.kdbx"
            keepass.import_xml(_doc(E("One")), db, PW)
            with self.assertRaises(KpmergeError) as cm:
                keepass.export_xml(db, b"wrong")
        msg = str(cm.exception)
        self.assertTrue(msg.strip())
        self.assertNotIn("exit code", msg)  # the reason given by keepassxc-cli is kept
        for line in msg.splitlines():
            self.assertFalse(line.rstrip().endswith(":"), line)
            self.assertNotIn("Saisi", line)  # French keepassxc-cli prompt


class SecureTempdirTest(unittest.TestCase):
    def test_secure_tempdir_cleanup(self):
        with keepass.secure_tempdir() as p:
            self.assertTrue(p.is_dir())
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
            self.assertEqual(p.parent, Path("/dev/shm"))
            (p / "x").write_bytes(b"1")
        self.assertFalse(p.exists())
        with self.assertRaises(RuntimeError):
            with keepass.secure_tempdir() as p2:
                raise RuntimeError("boom")
        self.assertFalse(p2.exists())

    def test_cleanup_failure_warns(self):
        err = io.StringIO()
        with mock.patch("shutil.rmtree"), contextlib.redirect_stderr(err):
            with keepass.secure_tempdir() as p:
                pass
        self.addCleanup(os.rmdir, p)
        self.assertIn("Warning", err.getvalue())
        self.assertIn(str(p), err.getvalue())

    def test_missing_dev_shm(self):
        with mock.patch("os.path.isdir", return_value=False):
            with self.assertRaises(KpmergeError):
                with keepass.secure_tempdir():
                    pass


if __name__ == "__main__":
    unittest.main()
