"""Command-line interface: arguments, orchestration, backup, verification."""
import argparse
import contextlib
import copy
import getpass
import os
import secrets
import shutil
import signal
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import keepass, xmltree
from .errors import KpmergeError
from .hardening import harden_process
from .merge import merge_groups
from .output import build_import_document
from .report import Report, format_report


@dataclass
class Target:
    """Groups A and B, and destination of the merged group (paths in `keepassxc-cli` format)."""

    path_a: str
    path_b: str
    parent_path: str
    name: str

    @property
    def dest_path(self) -> str:
        return f"{self.parent_path}/{self.name}" if self.parent_path else self.name


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kpmerge",
        description="Merge two groups of a KeePassXC database into a third group, "
                    "without modifying the two original groups.")
    parser.add_argument("db", type=Path, help="KeePassXC database (.kdbx)")
    parser.add_argument("group_a", help="path of group A (e.g. 'Imp A')")
    parser.add_argument("group_b", help="path of group B")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the report without writing anything")
    parser.add_argument("--dest", metavar="PATH",
                        help="full path of the group to create "
                             "(default: '<name of A> (merged)' next to A)")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    return parser.parse_args(argv)


def _export(db: Path, password: bytes) -> ET.Element:
    return ET.fromstring(keepass.export_xml(db, password))


def _contains(outer: ET.Element, inner: ET.Element) -> bool:
    return any(g is inner for g in outer.iter("Group"))


def _resolve(doc: ET.Element, arg_a: str, arg_b: str, dest: str | None) -> Target:
    """Checks made before any write: distinct groups, free destination outside A and B."""
    a, b = xmltree.find_group(doc, arg_a), xmltree.find_group(doc, arg_b)
    path_a, path_b = xmltree.group_path(doc, a), xmltree.group_path(doc, b)
    if a is b:
        raise KpmergeError(f"A and B are the same group: {path_a}")
    if _contains(a, b) or _contains(b, a):
        raise KpmergeError(f"One group contains the other: {path_a}, {path_b}")

    if dest is None:  # A is not the root, otherwise it would contain B
        parent, name = xmltree.group_chain(doc, arg_a)[-2], f"{a.findtext('Name')} (merged)"
    else:
        parent_arg, _, name = dest.strip("/").rpartition("/")
        if not name:
            raise KpmergeError(f"Invalid destination: {dest}")
        try:
            parent = xmltree.find_group(doc, parent_arg)
        except KpmergeError:
            raise KpmergeError(f"Destination parent group not found: {parent_arg}") from None

    target = Target(path_a, path_b, xmltree.group_path(doc, parent), name)
    if any(g.findtext("Name") == name for g in parent.findall("Group")):
        raise KpmergeError(f"Destination already exists: {target.dest_path}")
    if _contains(a, parent) or _contains(b, parent):
        raise KpmergeError(f"Destination cannot be inside A or B: {target.dest_path}")
    return target


def _meta_int(doc: ET.Element, tag: str) -> int:
    """History limit of the database; missing = unlimited (-1)."""
    text = (doc.findtext(f"Meta/{tag}") or "").strip()
    return int(text) if text else -1


def _merge(doc: ET.Element, target: Target) -> tuple[ET.Element, Report]:
    return merge_groups(xmltree.find_group(doc, target.path_a),
                        xmltree.find_group(doc, target.path_b),
                        xmltree.load_binaries(doc),
                        _meta_int(doc, "HistoryMaxItems"), _meta_int(doc, "HistoryMaxSize"))


def _confirmed(db: Path, target: Target, confirm: Callable[[str], str]) -> bool:
    try:
        answer = confirm(f"Create group '{target.dest_path}' in {db}? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _backup(db: Path) -> Path:
    backup = db.with_name(db.name + datetime.now().strftime(".bak-%Y%m%d-%H%M%S"))
    with open(db, "rb") as src:
        try:  # private from creation, never overwrites an older backup
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise KpmergeError(f"Backup already exists: {backup}") from None
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(src, out)
    return backup


def _write(db: Path, password: bytes, doc: ET.Element, target: Target,
           merged: ET.Element) -> None:
    """Import the merged group into an in-memory temporary database, then `merge` it into `db`."""
    xml = build_import_document(doc, target.parent_path, target.name, merged)
    with keepass.secure_tempdir() as tmp:
        tmp_db, tmp_password = tmp / "import.kdbx", secrets.token_urlsafe(32).encode()
        keepass.import_xml(xml, tmp_db, tmp_password)
        keepass.merge_db(db, tmp_db, password, tmp_password)


def _canonical(group: ET.Element) -> str:
    """keepassxc-cli exports CustomData items in a random order, and sets `_LAST_MODIFIED`
    to the time of the export itself: sort the items by key, drop `_LAST_MODIFIED`."""
    group = copy.deepcopy(group)
    for data in list(group.iter("CustomData")):
        data[:] = sorted((item for item in data if item.findtext("Key") != "_LAST_MODIFIED"),
                         key=lambda item: item.findtext("Key") or "")
    return ET.canonicalize(ET.tostring(group, encoding="unicode"), strip_text=True)


def _verify(db: Path, password: bytes, before: ET.Element, target: Target,
            merged: ET.Element, expected: int, backup: Path) -> None:
    after = _export(db, password)
    problems = []
    try:
        chain = xmltree.group_chain(after, target.dest_path)
        dest = chain[-1]
        count = sum(1 for _ in xmltree.iter_entries(dest))
        if count != expected:
            problems.append(f"{count} entries in {target.dest_path} instead of {expected}")
        # fingerprints in memory only, never printed
        want = xmltree.fingerprints_with_history(merged, xmltree.load_binaries(before))
        got = xmltree.fingerprints_with_history(dest, xmltree.load_binaries(after))
        if want != got:
            problems.append(f"content of {target.dest_path} differs from the merge: "
                            f"{sum((want - got).values())} entries or history versions "
                            f"missing or modified, {sum((got - want).values())} extra")
        chain[-2].remove(dest)  # what remains must equal the database before the merge
    except KpmergeError:
        problems.append(f"group {target.dest_path} missing")
    if _canonical(after.find("Root")) != _canonical(before.find("Root")):
        problems.append(f"database modified outside {target.dest_path} (groups A and B included)")
    if problems:
        raise KpmergeError("Verification failed: " + "; ".join(problems)
                           + f". The original database is in the backup {backup}")


def _run(args: argparse.Namespace, password_reader: Callable[[str], str],
         confirm: Callable[[str], str]) -> int:
    for warning in harden_process():
        print(f"Warning: {warning}", file=sys.stderr)
    try:
        password = password_reader(f"Password for {args.db}: ").encode("utf-8")
    except EOFError:
        raise KpmergeError("No password entered.") from None
    doc = _export(args.db, password)
    target = _resolve(doc, args.group_a, args.group_b, args.dest)
    merged, report = _merge(doc, target)
    print(format_report(report))
    if args.dry_run:
        print("\nDry run: nothing written.")
        return 0
    print("\nClose or lock the database in KeePassXC before continuing.")
    if not args.yes and not _confirmed(args.db, target, confirm):
        print("Aborted, nothing written.")
        return 0
    backup = _backup(args.db)
    print(f"Backup: {backup}")
    _write(args.db, password, doc, target, merged)
    try:
        _verify(args.db, password, doc, target, merged, report.total_entries, backup)
    except KeyboardInterrupt:
        print("\nInterrupted during the final check: the merge was written "
              f"to {args.db} (group '{target.dest_path}'), but it was not verified. "
              f"Backup: {backup}", file=sys.stderr)
        return 130
    print(f"Group created: {target.dest_path}")
    print(f"Delete groups '{target.path_a}' and '{target.path_b}' "
          "by hand once checked.")
    return 0


@contextlib.contextmanager
def _termination_as_interrupt():
    """SIGTERM and SIGHUP (terminal closed) clean up like Ctrl-C instead of killing."""
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None,
         password_reader: Callable[[str], str] = getpass.getpass,
         confirm: Callable[[str], str] = input) -> int:
    """Exit codes: 0 success, 1 error, 2 invalid arguments, 130 Ctrl-C."""
    try:
        args = _parse_args(argv)
    except SystemExit as exc:  # --help or invalid arguments
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with _termination_as_interrupt():
            return _run(args, password_reader, confirm)
    except KpmergeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # the message and traceback could contain secrets
        print(f"internal error: {type(exc).__name__}", file=sys.stderr)
        return 1
