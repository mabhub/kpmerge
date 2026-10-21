"""Merge report: no secret value and no `UserName`, only titles, paths and field names."""
from dataclasses import dataclass, field


@dataclass
class Conflict:
    path: str
    title: str
    fields: list[str]
    winner: str  # "A" or "B"


@dataclass
class Duplicate:
    path: str
    title: str
    count_a: int
    count_b: int


@dataclass
class Moved:
    title: str
    path_a: str
    path_b: str
    kept: str


@dataclass
class Probable:
    title_a: str
    path_a: str
    title_b: str
    path_b: str


@dataclass
class Ambiguous:
    """Same content on both sides, but in several copies on at least one side."""

    title: str
    paths_a: list[str]
    paths_b: list[str]


@dataclass
class OverLimit:
    path: str
    title: str
    history_items: int


@dataclass
class Report:
    """Paths are relative to the merged group; `""` is its root."""

    identical: int = 0
    merged: int = 0
    only_a: int = 0
    only_b: int = 0
    conflicts: list[Conflict] = field(default_factory=list)
    duplicates: list[Duplicate] = field(default_factory=list)
    moved: list[Moved] = field(default_factory=list)
    probable: list[Probable] = field(default_factory=list)
    ambiguous: list[Ambiguous] = field(default_factory=list)
    over_limit: list[OverLimit] = field(default_factory=list)
    total_entries: int = 0


def _where(path: str) -> str:
    return path or "(root)"


def format_report(r: Report) -> str:
    won_a = sum(1 for c in r.conflicts if c.winner == "A")
    won_b = sum(1 for c in r.conflicts if c.winner == "B")
    lines = [
        f"Identical entries: {r.identical}",
        f"Merged entries: {r.merged} (won by A: {won_a}, by B: {won_b})",
        f"Only in A: {r.only_a}",
        f"Only in B: {r.only_b}",
        f"Duplicate keys: {len(r.duplicates)}",
        f"Total entries after merge: {r.total_entries}",
    ]
    if r.conflicts:
        lines += ["", "Conflicts:"]
        lines += [f"  {_where(c.path)} / {c.title}: {', '.join(c.fields)} (winner: {c.winner})"
                  for c in r.conflicts]
    if r.duplicates:
        lines += ["", "Duplicate keys:"]
        lines += [f"  {_where(d.path)} / {d.title}: {d.count_a} in A, {d.count_b} in B"
                  " (copied without merging)" for d in r.duplicates]
    if r.moved:
        lines += ["", "Moved entries (matched by fingerprint):"]
        lines += [f"  {m.title}: {_where(m.path_a)} (A), {_where(m.path_b)} (B)"
                  f" -> kept in {m.kept}" for m in r.moved]
    if r.probable:
        lines += ["", "Probable pairs (to resolve by hand):"]
        lines += [f"  {p.title_a}: {_where(p.path_a)} (A), {_where(p.path_b)} (B)"
                  if p.title_a == p.title_b else
                  f"  {p.title_a}: {_where(p.path_a)} (A) <-> {p.title_b}: {_where(p.path_b)} (B)"
                  for p in r.probable]
    if r.ambiguous:
        lines += ["", "Identical entries not merged (several copies on one side):"]
        lines += [f"  {x.title}: {', '.join(map(_where, x.paths_a))} (A),"
                  f" {', '.join(map(_where, x.paths_b))} (B)" for x in r.ambiguous]
    if r.over_limit:
        lines += ["", "History beyond the database limits (raise them before editing these entries):"]
        lines += [f"  {_where(o.path)} / {o.title}: {o.history_items} versions"
                  for o in r.over_limit]
    return "\n".join(lines)
