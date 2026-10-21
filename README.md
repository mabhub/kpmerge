# kpmerge

Merges two groups of a KeePassXC database into a third group of the same database.

Use case: a Bitwarden vault imported twice gives two nearly identical groups. `keepassxc-cli merge` and the merge in the graphical interface pair entries by UUID, but each import generates new UUIDs. `kpmerge` pairs entries by their content.

Python 3, standard library only. Only `keepassxc-cli` is called to read and write the database. Tested with KeePassXC 2.7.12.

## Installation

```
ln -s "$PWD/kpmerge" ~/bin/kpmerge   # from the repository root
```

The launcher follows the link to find `kpmergelib/`.

## Usage

```
kpmerge [--dry-run] [--dest PATH] [--yes] base.kdbx GROUP_A GROUP_B
```

Group paths follow the `keepassxc-cli` format: `Imp A`, `Imp A/Subgroup`, separator `/`. The root group's name is optional.

First a dry run. It prints the report and writes nothing:

```
kpmerge --dry-run ~/Documents/base.kdbx "Imp A" "Imp B"
```

Then the actual merge:

```
kpmerge ~/Documents/base.kdbx "Imp A" "Imp B"
```

Options:

- `--dry-run`: report only, no write.
- `--dest PATH`: full path of the group to create. Defaults to `<name of A> (merged)` next to A.
- `--yes`: do not ask for confirmation.

The master password is asked once, without echo. It is passed to `keepassxc-cli` through stdin only.

Before writing, the script reminds you to close or lock the database in KeePassXC (even with `--yes`), then asks for confirmation (`y` or `yes`). Any other answer aborts without any change.

Exit codes:

- `0`: success, dry run, or abort at the confirmation.
- `1`: error (message prefixed with `Error:`).
- `2`: invalid arguments.
- `130`: interrupted by Ctrl-C, `SIGTERM` or `SIGHUP` (terminal closed).

## What the script does

1. Asks for the master password with `getpass`.
2. Exports the database to XML with `keepassxc-cli export`. The output stays in memory.
3. Checks that A and B are distinct, that neither contains the other and that the destination does not exist. Nothing is written if one of these checks fails.
4. Merges A and B on the XML tree, in memory, and prints the report.
5. Builds a reduced XML: the original `<Meta>`, the chain of the destination's ancestor groups and the merged group. All groups and entries of the merged group, histories included, get new UUIDs. Otherwise `merge` would recognise the entries of A and B and move them instead of adding copies.
6. Copies the database to `base.kdbx.bak-YYYYMMDD-HHMMSS` (mode `0600`) before any write.
7. Writes this XML to a `memfd` (an anonymous file in RAM, never present in a file system) and passes it to `keepassxc-cli import` through `/dev/fd/N`. The import creates an encrypted temporary database, with a random password, in a `0700` directory under `/dev/shm`.
8. Runs `keepassxc-cli merge base.kdbx <temporary database>`.
9. Deletes the temporary database and directory, including after an error, a Ctrl-C, a `SIGTERM` or a `SIGHUP`. If the directory cannot be deleted, a warning gives its path.
10. Exports the database again and checks that the merged group exists with the right number of entries, that its entries and their history versions (attachments included) match the computed merge exactly, and that the rest of the database, A and B included, is unchanged. Comparisons use fingerprints in memory, nothing is printed. On failure, the error gives the path of the backup.

## Merge rules

- Subgroups are paired by name, level by level. The merged group takes the icon and notes of A. A subgroup present only in B keeps those of B.
- Two subgroups with the same name under the same parent, in A or in B, cause an error. Rename them in KeePassXC before running again.
- The same goes for the paths of A, B and the destination: if a group of the path has a sibling with the same name, the script stops instead of guessing.
- Entries are paired by title + username + URL, compared exactly after stripping leading and trailing spaces.
- The compared content covers text fields (standard, custom, TOTP), attachments (name and content), tags and expiry. Dates, UUID, history, icon, auto-type and colours are ignored.
- Identical entries: only one is kept, the most recent. The histories of both sides are combined.
- Different entries: the one with the most recent `LastModificationTime` wins. The other version is stored in the winner's history.
- The final history combines those of A and B and the losing version. It is sorted by date, with no duplicate content.
- Dates are reliable: the KeePassXC Bitwarden importer uses `revisionDate` as the modification date, not the import date.
- An entry present on one side only is copied as is.
- Fingerprint matching: an entry moved to another folder with no other change is left alone on each side after key pairing. Lone entries are compared by a SHA-256 fingerprint of their content, across the whole tree of A and B. If the fingerprint is unique on each side, the two entries are merged as identical.
- The matched entry is placed in the subgroup of the most recent one, or of B on a tie.
- If a fingerprint appears several times on one side, nothing is merged and the case is reported.
- Duplicate key within a group: no merge for this key. All entries from both sides are copied and the report says so. This is typical of Bitwarden secure notes and cards, which have neither username nor URL.
- If the destination already exists, the script stops before any write.

## Report

It is always printed and is the only output of `--dry-run`. It contains no secret value and no `UserName`: only titles, group paths and field names. You can paste it into a conversation.

- Counters: identical, merged (with the number of winners on side A and side B), only in A, only in B, duplicate keys, total after merge.
- Conflicts: path, title and names of the differing fields (`Password`, `Notes`, `otp`, `attachment:x.pdf`...).
- Duplicate keys: path, title and number of entries on each side.
- Moved entries matched by fingerprint: title, subgroup in A, subgroup in B, subgroup kept.
- Probable pairs: an entry only in A and an entry only in B have the same key, different subgroups and a different content. They were moved and modified. They are not merged, it is up to you to decide.
- Entries whose history exceeds the database limits.

## Security guarantees

- No plaintext file on disk, `/tmp` included. The XML goes through a `memfd`.
- The only database written besides the target is the temporary one, encrypted with a random password, in a `0700` directory under `/dev/shm`. It is deleted on exit, error, Ctrl-C, `SIGTERM` and `SIGHUP`. Only a `SIGKILL` or a power failure can leave it behind, still encrypted.
- The master password appears neither in `argv` nor in the process environment, it goes through stdin.
- No secret value in the output. An unexpected error only prints the exception name (`internal error: ...`), never a traceback.
- No core dump: `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`. The process cannot be inspected with `ptrace` by another process of the same user either.
- `keepassxc-cli` disables its own core dumps. Its `/proc` files belong to root, so `apport` cannot capture it.
- The Python process is locked in RAM with `mlockall`. If that is not possible, a warning is printed. Locking needs a locked-memory limit of at least 1 GiB (`ulimit -l`, in KiB), while many distributions default to 8 MiB. To raise it, add `<user> - memlock 1048576` to `/etc/security/limits.conf` and log in again.
- The launcher uses `python3 -I`: no import from the current directory or from `PYTHONPATH`.
- Groups A and B, and the rest of the database, are never modified or deleted. The final check verifies it.
- A backup of the database is made before any write. It has mode `0600` from its creation and never overwrites an older one.

## Residual risks

- If KeePassXC has the database open with unsaved changes, there will be a conflict on the next save. Close or lock the database before running the script.
- The `keepassxc-cli` child process is not locked in memory: `mlockall` does not survive `exec`. The plaintext XML it handles may therefore be written to swap.
- Kernel memory and the memory of `keepassxc-cli` are beyond the script's control.
- Python cannot wipe its own memory: the master password and the plaintext XML stay in the memory of the process until it exits.
- These protections target other users and crash dumps, not a malicious program running under your own account. Such a program could replace the launcher or put a fake `keepassxc-cli` first in `PATH`.
- `/dev/shm` may be swapped out, but it only holds an encrypted database.
- The `memfd` holding the plaintext XML during the import is also stored in shared memory (shmem), so it may be swapped out like `/dev/shm`. The plaintext XML stays there for the duration of the import, so `/dev/shm` is not the only exposed place. An encrypted or disabled swap removes this risk.
- Field references `{REF:...}` pointing to a UUID of A or B no longer resolve in the merged copies, because the merged group gets new UUIDs.
- The history of a merged entry may exceed the database limits (see below). KeePassXC truncates it on the next change to the entry.
- The script does not modify the database `<Meta>`, so the history limits remain those of the database.

## After the merge

1. Open the database in KeePassXC and check the created group: entries, subgroups, attachments, TOTP.
2. Handle by hand the probable pairs and duplicate keys of the report.
3. If the report lists entries beyond the history limits, raise them before editing these entries: Database → Database Settings → History, then increase "Maximum history items" and the maximum history size. Otherwise KeePassXC truncates the history on the next change and the losing version disappears.
4. Delete groups A and B by hand, once everything is checked.
5. Delete the `base.kdbx.bak-*` backup when everything is fine. It is encrypted, but it still holds the old state.

## Tests

From the repository root:

```
python3 -m unittest discover -t . -s tests
```

Tests work on dummy databases in a temporary directory, with a test password. Integration tests are skipped if `keepassxc-cli` is missing.
