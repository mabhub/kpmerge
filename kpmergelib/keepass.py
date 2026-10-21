"""Calls to `keepassxc-cli`: passwords only go through stdin."""
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

from kpmergelib.errors import KpmergeError

# keepassxc-cli prompts in a French locale; prompts in other locales end with ":"
_PROMPT_PREFIXES = ("Saisir le mot de passe", "Saisissez", "Confirmer")
_SHM = "/dev/shm"


def _check_password(password: bytes) -> None:
    if b"\n" in password:
        raise KpmergeError("The password must not contain a newline.")


def _error_text(stderr: bytes) -> str:
    lines = []
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.endswith(":") or line.startswith(_PROMPT_PREFIXES):
            continue
        lines.append(line)
    return "\n".join(lines)


def _run(args: list[str], stdin: bytes, pass_fds: tuple[int, ...] = ()) -> bytes:
    try:
        result = subprocess.run(["keepassxc-cli", *args], input=stdin, capture_output=True,
                                pass_fds=pass_fds)
    except FileNotFoundError:
        raise KpmergeError("keepassxc-cli not found in PATH.") from None
    if result.returncode != 0:
        detail = _error_text(result.stderr) or f"exit code {result.returncode}"
        raise KpmergeError(f"keepassxc-cli {args[0]} failed: {detail}")
    return result.stdout


def export_xml(db: Path, password: bytes) -> bytes:
    _check_password(password)
    return _run(["export", "-f", "xml", str(db)], password + b"\n")  # no -q: keeps the error message


def import_xml(xml: bytes, dest: Path, password: bytes) -> None:
    _check_password(password)
    fd = os.memfd_create("kpmerge")
    try:
        view = memoryview(xml)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        _run(["import", "-q", "-p", f"/dev/fd/{fd}", str(dest)],
             password + b"\n" + password + b"\n", pass_fds=(fd,))
    finally:
        os.close(fd)


def merge_db(db: Path, src: Path, password: bytes, src_password: bytes) -> None:
    _check_password(password)
    _check_password(src_password)
    _run(["merge", str(db), str(src)], password + b"\n" + src_password + b"\n")


@contextlib.contextmanager
def secure_tempdir() -> Iterator[Path]:
    if not os.path.isdir(_SHM):
        raise KpmergeError(f"{_SHM} is missing: cannot create an in-memory temporary directory.")
    path = tempfile.mkdtemp(prefix="kpmerge-", dir=_SHM)
    try:
        os.chmod(path, 0o700)
        yield Path(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)
        if os.path.exists(path):
            print(f"Warning: temporary directory not removed, delete it by hand: {path} "
                  "(it only holds an encrypted database)", file=sys.stderr)
