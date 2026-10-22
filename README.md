# kpmerge

Merges two groups of a KeePassXC database into a third group of the same database.

Use case: a Bitwarden vault imported twice gives two nearly identical groups. `keepassxc-cli merge` and the merge in the graphical interface pair entries by UUID, but each import generates new UUIDs. `kpmerge` pairs entries by their content.

## Requirements

- Linux: the script needs `memfd_create` and `/dev/shm`. It also uses `prctl` and `mlockall`, and only prints a warning if they fail.
- Python 3.10 or later, standard library only.
- `keepassxc-cli` from KeePassXC 2.7 or later, in `PATH`. Tested with 2.7.12. It is the only tool used to read and write the database.
- A database protected by a password only (no key file, no hardware key). With a key file or a hardware key, the first export fails with the same "invalid credentials" error as a wrong password.
- An `env` that supports `-S` (GNU coreutils 8.30 or later) for the launcher's shebang. Otherwise, for example on Alpine (BusyBox), run `python3 -I kpmerge ...`.

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

A must be the older export and B the newer one: the entries of A missing from B are archived (see "Entries deleted upstream").

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
- An entry present in B only is copied as is. An entry present in A only is archived or kept, see below.
- Fingerprint matching: an entry moved to another folder with no other change is left alone on each side after key pairing. Lone entries are compared by a SHA-256 fingerprint of their content, across the whole tree of A and B. If the fingerprint is unique on each side, the two entries are merged as identical.
- The matched entry is placed in the subgroup of the most recent one, or of B on a tie.
- If a fingerprint appears several times on one side, nothing is merged and the report lists it under "Identical entries not merged".
- Duplicate key within a group: no merge for this key. All entries from both sides are copied and the report says so. This is typical of Bitwarden secure notes and cards, which have neither username nor URL.
- If the destination already exists, the script stops before any write.

## Entries deleted upstream

B is taken as a newer export of the same vault. An entry of A still alone after pairing by key and by fingerprint was most likely deleted in the vault between the two exports: Bitwarden exports leave the trash out.

- Such an entry goes to the `Deleted upstream (archive)` subgroup of the merged group, under its original path: `Deleted upstream (archive)/Subfolder/Entry`.
- Date guard: an entry modified after the most recent modification date of B's entries cannot have been deleted before B was exported. It stays among the live entries and the report lists it.
- Swapped A and B are only partly caught. The entries added between the two exports are dated after the newest entry of the older export, so the date guard keeps them live. But an added entry that carries an older date, for example restored from the trash or imported with its original dates, is archived, and the entries deleted between the two exports stay live. Check the "Archived" list of the dry-run report.
- If B holds no entry at all, there is no reference date and nothing is archived.
- The A side of a probable pair is archived too. The report still lists the pair.
- A subgroup present in A only, and emptied by the archiving, is removed from the live tree. A subgroup already empty in A stays.
- Entries with a duplicate key are copied as is, never archived.
- Like the recycle bin, the archive and its subgroups are left out of search, browser integration and auto-type, and the archive shows the trash icon. To find an archived entry, open the archive group.

The merged group then becomes A of the next merge. Its archive is carried over:

- A `Deleted upstream (archive)` subgroup directly under the root of A or B is not merged like the others. Its content is copied as is into the archive of the result, subfolders united by name, so archives never nest. Its entries are left out of the date guard. Lower in the tree, a group with this name is an ordinary folder.
- An archived entry whose key (title + username + URL) is back among B's entries, for example restored in the vault, is only reported. Nothing moves. A key made of the title alone, like a Bitwarden note, counts only with the same content.

## Report

It is always printed and is the only output of `--dry-run`. It contains no secret value and no `UserName`: only titles, group paths and field names. You can paste it into a conversation.

- Counters: identical, merged (with the number of winners on side A and side B), only in A (kept live), only in B, archived (new and carried over), duplicate keys, total after merge. The total includes the archive.
- Conflicts: path, title and names of the differing fields (`Password`, `Notes`, `otp`, `attachment:x.pdf`...).
- Duplicate keys: path, title and number of entries on each side.
- Moved entries matched by fingerprint: title, subgroup in A, subgroup in B, subgroup kept.
- Probable pairs: an entry only in A and an entry only in B share at least two identical, non-empty fields among title, username and URL, and have a different content. They were moved and modified, or renamed, or their URL or username changed. They are not merged, it is up to you to decide. Both titles are shown when they differ.
- Identical entries not merged: same content in A and in B, but in several copies on at least one side. The report gives the subgroup of each copy.
- Archived entries: original path and title of the entries newly moved to the archive. The carried-over ones are only counted.
- Entries only in A kept live by the date guard.
- Archived entries back in B, with their path in the archive.
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
2. Handle by hand the probable pairs, identical entries not merged, duplicate keys and archived entries back in B of the report.
3. Check `Deleted upstream (archive)`. Delete it, or keep it: the next merge carries it over.
4. If the report lists entries beyond the history limits, raise them before editing these entries: Database → Database Settings → History, then increase "Maximum history items" and the maximum history size. Otherwise KeePassXC truncates the history on the next change and the losing version disappears.
5. Delete groups A and B by hand, once everything is checked.
6. Delete the `base.kdbx.bak-*` backup when everything is fine. It is encrypted, but it still holds the old state.

## Tests

From the repository root:

```
python3 -m unittest discover -t . -s tests
```

Tests work on dummy databases in a temporary directory, with a test password. Integration tests are skipped if `keepassxc-cli` is missing.

## License

MIT, see [LICENSE](LICENSE). The software is provided without warranty: keep the backup until you have checked the merged group.
