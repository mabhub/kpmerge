import contextlib
import hashlib
import io
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from kpmergelib import cli, keepass, xmltree
from kpmergelib.errors import KpmergeError
from tests.kpxml import E, G, make_doc

HAS_CLI = shutil.which("keepassxc-cli") is not None
PW = "test"
REPO = Path(__file__).resolve().parent.parent
SHM = Path("/dev/shm")

# Expected merge: Common (conflict), Only A, Only B, Sub/Sub A, Sub/Sub B.
EXPECTED_ENTRIES = 5


def _doc() -> bytes:
    return make_doc([
        G("Imp A", entries=[
            E("Common", "jdoe", "https://x", password="old", mtime="2026-01-01T00:00:00Z"),
            E("Only A"),
        ], groups=[G("Sub", entries=[E("Sub A")])]),
        G("Imp B", entries=[
            E("Common", "jdoe", "https://x", password="new", mtime="2026-02-01T00:00:00Z"),
            E("Only B"),
        ], groups=[G("Sub", entries=[E("Sub B")])]),
        G("Archive"),
    ])


def _canonical(group: ET.Element) -> str:
    return ET.canonicalize(ET.tostring(group, encoding="unicode"), strip_text=True)


def _count(group: ET.Element) -> int:
    return sum(1 for _ in xmltree.iter_entries(group))


def _shm_kpmerge() -> set[str]:
    return {n for n in os.listdir(SHM) if n.startswith("kpmerge-")}


def _refuse_confirm(prompt: str) -> str:
    raise AssertionError("confirmation asked unexpectedly")


class CliTestBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.db = self.dir / "t.kdbx"

    def run_main(self, *argv, password=PW, confirm=lambda _: "y"):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("kpmergelib.cli.harden_process", return_value=[]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(self.db), *argv], password_reader=lambda _: password,
                            confirm=confirm)
        return code, out.getvalue(), err.getvalue()


@unittest.skipUnless(HAS_CLI, "keepassxc-cli not found")
class CliIntegrationTest(CliTestBase):
    def setUp(self):
        super().setUp()
        keepass.import_xml(_doc(), self.db, PW.encode())

    def export(self) -> ET.Element:
        return ET.fromstring(keepass.export_xml(self.db, PW.encode()))

    def digest(self) -> str:
        return hashlib.sha256(self.db.read_bytes()).hexdigest()

    def backups(self) -> list[Path]:
        return sorted(self.dir.glob("t.kdbx.bak-*"))

    def assert_untouched(self, before: str):
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.backups(), [])

    def test_end_to_end(self):
        before = self.export()
        code, out, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 0, err)
        after = self.export()
        merged = xmltree.find_group(after, "Imp A (merged)")
        self.assertIs(xmltree.group_chain(after, "Imp A (merged)")[-2], after.find("Root/Group"))
        self.assertEqual(_count(merged), EXPECTED_ENTRIES)
        for path in ("Imp A", "Imp B"):
            self.assertEqual(_canonical(xmltree.find_group(after, path)),
                             _canonical(xmltree.find_group(before, path)), path)
        backups = self.backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        self.assertIn("Imp A (merged)", out)
        self.assertIn(str(backups[0]), out)
        for secret in ("old", "new", "jdoe", PW):
            self.assertNotIn(secret, out + err)

    def test_dry_run_writes_nothing(self):
        before = self.digest()
        code, out, err = self.run_main("Imp A", "Imp B", "--dry-run", confirm=_refuse_confirm)
        self.assertEqual(code, 0, err)
        self.assertIn("Total entries after merge: 5", out)
        self.assert_untouched(before)

    def test_dest_option(self):
        code, _, err = self.run_main("Imp A", "Imp B", "--yes", "--dest", "Archive/Merged")
        self.assertEqual(code, 0, err)
        after = self.export()
        self.assertEqual(_count(xmltree.find_group(after, "Archive/Merged")), EXPECTED_ENTRIES)
        with self.assertRaises(KpmergeError):
            xmltree.find_group(after, "Imp A (merged)")

    def test_dest_exists_refused(self):
        code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 0, err)
        before, backups = self.digest(), self.backups()
        code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("Imp A (merged)", err)
        self.assertEqual(self.digest(), before)
        self.assertEqual(self.backups(), backups)

    def test_dest_parent_missing_refused(self):
        before = self.digest()
        code, _, err = self.run_main("Imp A", "Imp B", "--yes", "--dest", "Nowhere/Merged")
        self.assertEqual(code, 1)
        self.assertIn("Nowhere", err)
        self.assert_untouched(before)

    def test_dest_inside_a_or_b_refused(self):
        before = self.digest()
        for dest in ("Imp A", "Imp B", "Imp A/Merged", "Imp B/Sub/Merged"):
            with self.subTest(dest=dest):
                code, _, err = self.run_main("Imp A", "Imp B", "--yes", "--dest", dest)
                self.assertEqual(code, 1)
                self.assertTrue(err.strip())
                self.assert_untouched(before)

    def test_nested_or_same_groups_refused(self):
        before = self.digest()
        for a, b in (("Imp A", "Imp A"), ("Imp A", "Imp A/Sub"), ("Imp A/Sub", "Imp A")):
            with self.subTest(a=a, b=b):
                code, _, err = self.run_main(a, b, "--yes")
                self.assertEqual(code, 1)
                self.assertTrue(err.strip())
                self.assert_untouched(before)

    def test_wrong_password(self):
        before = self.digest()
        code, out, err = self.run_main("Imp A", "Imp B", "--yes", password="wrong")
        self.assertEqual(code, 1)
        self.assertTrue(err.strip())
        self.assertNotIn("wrong", out + err)
        self.assertNotIn("internal error", err)
        self.assert_untouched(before)
        self.assertEqual(_shm_kpmerge(), set())

    def test_no_trace_left(self):
        files, shm = set(os.listdir(self.dir)), _shm_kpmerge()
        code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 0, err)
        added = set(os.listdir(self.dir)) - files
        self.assertEqual(len(added), 1)
        self.assertTrue(added.pop().startswith("t.kdbx.bak-"))
        self.assertEqual(_shm_kpmerge(), shm)

        seen = []

        def fail_after_import(exc):
            def merge_db(db, src, *args, **kwargs):
                seen.append(src.exists())
                raise exc
            return merge_db

        for n, (exc, expected) in enumerate(((KpmergeError("forced failure"), 1),
                                             (KeyboardInterrupt(), 130))):
            with self.subTest(exc=type(exc).__name__):
                for backup in self.backups():  # same second: same backup name
                    backup.unlink()
                before = self.digest()
                with mock.patch("kpmergelib.keepass.merge_db", fail_after_import(exc)):
                    code, _, err = self.run_main("Imp A", "Imp B", "--yes",
                                                 "--dest", f"Archive/Try {n}")
                self.assertEqual(code, expected, err)
                self.assertEqual(seen, [True] * (n + 1))  # the temporary database did exist
                self.assertEqual(_shm_kpmerge(), shm)
                self.assertEqual(self.digest(), before)
                self.assertTrue(all(name.startswith("t.kdbx.bak-")
                                    for name in set(os.listdir(self.dir)) - files))

    def test_verification_failure_names_backup(self):
        with mock.patch("kpmergelib.keepass.merge_db"):
            code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("Verification failed", err)
        self.assertIn(str(self.backups()[0]), err)

    def test_verification_detects_change_outside_merged_group(self):
        real_export = cli._export
        calls = []

        def export_without_archive(db, password):
            doc = real_export(db, password)
            calls.append(1)
            if len(calls) > 1:  # re-export for the verification
                root = doc.find("Root/Group")
                root.remove(xmltree.find_group(doc, "Archive"))
            return doc

        with mock.patch("kpmergelib.cli._export", export_without_archive):
            code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("database modified outside", err)
        self.assertIn(str(self.backups()[0]), err)

    def test_confirmation_declined(self):
        before = self.digest()
        code, out, err = self.run_main("Imp A", "Imp B", confirm=lambda _: "n")
        self.assertEqual(code, 0, err)
        self.assertIn("Close or lock the database in KeePassXC", out)
        self.assertIn("Aborted, nothing written.", out)
        self.assert_untouched(before)


def _history_doc() -> bytes:
    versions = [E("Rich", "jdoe", "https://x", password=f"v{n}", mtime=f"2026-01-0{n}T00:00:00Z",
                  attachments={"old.txt": f"content {n}".encode()}) for n in (1, 2, 3)]
    return make_doc([
        G("Imp A", entries=[
            E("Rich", "jdoe", "https://x", password="a-current", mtime="2026-03-01T00:00:00Z",
              extra={"otp": "otpauth://totp/x?secret=ABC", "Token": "token-a"},
              attachments={"key.bin": b"\x00\x01binary"}, history=versions)]),
        G("Imp B", entries=[
            E("Rich", "jdoe", "https://x", password="b-current", mtime="2026-02-01T00:00:00Z",
              extra={"otp": "otpauth://totp/x?secret=DEF"},
              attachments={"key.bin": b"\x00\x01binary"}, history=versions[:1])]),
    ], history_max_items=2)


@unittest.skipUnless(HAS_CLI, "keepassxc-cli not found")
class CliHistoryIntegrationTest(CliTestBase):
    def backups(self) -> list[Path]:
        return sorted(self.dir.glob("t.kdbx.bak-*"))

    def test_nothing_lost_through_import_and_merge(self):
        keepass.import_xml(_history_doc(), self.db, PW.encode())
        before = ET.fromstring(keepass.export_xml(self.db, PW.encode()))
        target = cli._resolve(before, "Imp A", "Imp B", None)
        merged, report = cli._merge(before, target)
        self.assertEqual(len(report.over_limit), 1)  # history beyond the limit
        want = xmltree.fingerprints_with_history(merged, xmltree.load_binaries(before))
        self.assertGreaterEqual(sum(want.values()), 5)

        code, out, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 0, err)
        after = ET.fromstring(keepass.export_xml(self.db, PW.encode()))
        dest = xmltree.find_group(after, "Imp A (merged)")
        self.assertEqual(xmltree.fingerprints_with_history(dest, xmltree.load_binaries(after)),
                         want)
        for secret in ("a-current", "b-current", "token-a", "ABC", "content 1"):
            self.assertNotIn(secret, out + err)

    def test_verification_detects_missing_history_version(self):
        keepass.import_xml(_history_doc(), self.db, PW.encode())
        real_export = cli._export
        calls = []

        def export_without_history(db, password):
            doc = real_export(db, password)
            calls.append(1)
            if len(calls) > 1:  # re-export for the verification
                dest = xmltree.find_group(doc, "Imp A (merged)")
                for _, entry in xmltree.iter_entries(dest):
                    hist = entry.find("History")
                    hist.remove(hist.find("Entry"))
            return doc

        with mock.patch("kpmergelib.cli._export", export_without_history):
            code, out, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("Verification failed", err)
        self.assertIn(str(self.backups()[0]), err)
        self.assertNotIn("a-current", out + err)

def _kdbx4_doc() -> bytes:
    """`_doc()` plus an entry CustomData, a KDBX 4 feature: the import then writes a
    KDBX 4 file, whose export gives the dates in base64 instead of ISO 8601."""
    doc = ET.fromstring(_doc())
    item = ET.SubElement(ET.SubElement(doc.find(".//Entry"), "CustomData"), "Item")
    ET.SubElement(item, "Key").text = "k"
    ET.SubElement(item, "Value").text = "v"
    return ET.tostring(doc)


@unittest.skipUnless(HAS_CLI, "keepassxc-cli not found")
class CliKdbx4IntegrationTest(CliTestBase):
    def test_end_to_end_with_base64_dates(self):
        keepass.import_xml(_kdbx4_doc(), self.db, PW.encode())
        before = ET.fromstring(keepass.export_xml(self.db, PW.encode()))
        self.assertTrue(before.findtext(".//LastModificationTime").endswith("="))
        code, out, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 0, err)
        after = ET.fromstring(keepass.export_xml(self.db, PW.encode()))
        merged = xmltree.find_group(after, "Imp A (merged)")
        self.assertEqual(_count(merged), EXPECTED_ENTRIES)
        common = next(e for _, e in xmltree.iter_entries(merged)
                      if xmltree.entry_title(e) == "Common")
        password = next(s.findtext("Value") for s in common.findall("String")
                        if s.findtext("Key") == "Password")
        self.assertEqual(password, "new")  # the most recent (B) wins


class CliUnitTest(CliTestBase):
    def test_canonical_ignores_custom_data_order(self):
        # keepassxc-cli exports CustomData items in a random order on each run
        # and sets _LAST_MODIFIED to the time of the export itself
        def root(*items):
            data = "".join(f"<Item><Key>{k}</Key><Value>{v}</Value></Item>" for k, v in items)
            return ET.fromstring(f"<Root><Group><Entry><CustomData>{data}</CustomData>"
                                 "</Entry></Group></Root>")
        a, b, c = ("a", "1"), ("b", "2"), ("c", "3")
        self.assertEqual(cli._canonical(root(a, b)), cli._canonical(root(b, a)))
        self.assertEqual(cli._canonical(root(a, ("_LAST_MODIFIED", "10:00:00"))),
                         cli._canonical(root(("_LAST_MODIFIED", "10:00:01"), a)))
        self.assertNotEqual(cli._canonical(root(a, b)), cli._canonical(root(a, c)))
        self.assertNotEqual(cli._canonical(root(a, b)), cli._canonical(root(a, ("b", "9"))))

    def test_backup_private_from_creation(self):
        src = self.dir / "s.kdbx"
        src.write_bytes(b"data")
        src.chmod(0o644)
        with mock.patch("os.chmod"):  # mode must not depend on a later chmod
            backup = cli._backup(src)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(backup.read_bytes(), b"data")

    def test_backup_never_overwritten(self):
        src = self.dir / "s.kdbx"
        src.write_bytes(b"data")
        fixed = mock.Mock(wraps=cli.datetime)
        fixed.now.return_value = cli.datetime(2026, 1, 2, 3, 4, 5)
        with mock.patch("kpmergelib.cli.datetime", fixed):
            backup = cli._backup(src)
            backup.write_bytes(b"older backup")
            with self.assertRaises(KpmergeError):
                cli._backup(src)
        self.assertEqual(backup.read_bytes(), b"older backup")

    def test_termination_signals_interrupt_cleanly(self):
        for sig in (signal.SIGTERM, signal.SIGHUP):
            caught = []

            def sentinel(signum, frame):  # stands for the default action, which kills
                caught.append(signum)

            previous = signal.signal(sig, sentinel)
            self.addCleanup(signal.signal, sig, previous)

            def reader(_prompt):
                os.kill(os.getpid(), sig)
                return PW

            with mock.patch("kpmergelib.cli.harden_process", return_value=[]), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = cli.main([str(self.db), "Imp A", "Imp B"], password_reader=reader)
            self.assertEqual(code, 130)
            self.assertEqual(caught, [])
            self.assertIs(signal.getsignal(sig), sentinel)  # handler restored

    def test_internal_error_hides_message(self):
        with mock.patch("kpmergelib.keepass.export_xml", return_value=_doc()), \
                mock.patch("kpmergelib.cli.merge_groups",
                           side_effect=ValueError("secret-value")):
            code, out, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 1)
        self.assertEqual(err.strip(), "internal error: ValueError")
        self.assertNotIn("secret-value", out + err)

    def test_eof_at_password_prompt(self):
        def eof(_):
            raise EOFError

        with mock.patch("kpmergelib.cli.harden_process", return_value=[]), \
                mock.patch("kpmergelib.keepass.export_xml") as export, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main([str(self.db), "Imp A", "Imp B"], password_reader=eof)
        self.assertEqual(code, 1)
        self.assertIn("No password entered.", err.getvalue())
        self.assertNotIn("internal error", err.getvalue())
        export.assert_not_called()

    def test_reminder_printed_with_yes_not_with_dry_run(self):
        reminder = "Close or lock the database in KeePassXC"
        with mock.patch("kpmergelib.keepass.export_xml", return_value=_doc()), \
                mock.patch("kpmergelib.cli._backup", return_value=Path("backup.bak")), \
                mock.patch("kpmergelib.cli._write"), mock.patch("kpmergelib.cli._verify"):
            _, out, _ = self.run_main("Imp A", "Imp B", "--yes")
            self.assertIn(reminder, out)
            _, out, _ = self.run_main("Imp A", "Imp B", "--dry-run")
            self.assertNotIn(reminder, out)

    def test_interrupt_during_verification(self):
        with mock.patch("kpmergelib.keepass.export_xml", return_value=_doc()), \
                mock.patch("kpmergelib.cli._backup", return_value=Path("backup.bak")), \
                mock.patch("kpmergelib.cli._write"), \
                mock.patch("kpmergelib.cli._verify", side_effect=KeyboardInterrupt):
            code, _, err = self.run_main("Imp A", "Imp B", "--yes")
        self.assertEqual(code, 130)
        self.assertIn("the merge was written", err)
        self.assertIn("Imp A (merged)", err)
        self.assertIn("backup.bak", err)

    def test_invalid_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["only-a-database"]), 2)

    def test_hardening_warnings_on_stderr(self):
        err = io.StringIO()
        with mock.patch("kpmergelib.cli.harden_process", return_value=["alert"]), \
                mock.patch("kpmergelib.keepass.export_xml", return_value=_doc()), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = cli.main([str(self.db), "Imp A", "Imp B", "--dry-run"],
                            password_reader=lambda _: PW)
        self.assertEqual(code, 0)
        self.assertIn("alert", err.getvalue())

    def test_launcher_via_symlink(self):
        link = self.dir / "kpmerge"
        link.symlink_to(REPO / "kpmerge")
        r = subprocess.run([str(link), "--help"], capture_output=True, text=True, cwd=self.dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--dry-run", r.stdout)

    def _run_launcher_as(self, attr, value):
        """Run the launcher under this interpreter with sys.<attr> faked."""
        code = ("import runpy, sys; sys.%s = %r; sys.argv = ['kpmerge', '--help']; "
                "runpy.run_path(%r, run_name='__main__')" % (attr, value, str(REPO / "kpmerge")))
        return subprocess.run([sys.executable, "-I", "-c", code],
                              capture_output=True, text=True, cwd=self.dir)

    def test_launcher_rejects_old_python(self):
        r = self._run_launcher_as("version_info", (3, 9, 18))
        self.assertEqual(r.returncode, 1)
        self.assertIn("Error: kpmerge requires Python 3.10 or later", r.stderr)
        self.assertIn("is Python 3.9", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_launcher_accepts_python_3_10(self):
        r = self._run_launcher_as("version_info", (3, 10, 0))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--dry-run", r.stdout)

    def test_launcher_rejects_non_linux(self):
        r = self._run_launcher_as("platform", "darwin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("Error: kpmerge runs on Linux only (this system is darwin)", r.stderr)

    def test_launcher_copied_without_package(self):
        copy = self.dir / "kpmerge"
        shutil.copy(REPO / "kpmerge", copy)
        r = subprocess.run([sys.executable, "-I", str(copy), "--help"],
                           capture_output=True, text=True, cwd=self.dir)
        self.assertEqual(r.returncode, 1)
        self.assertIn("kpmergelib package was not found", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
