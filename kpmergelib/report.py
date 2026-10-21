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
    title: str
    path_a: str
    path_b: str


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
        f"Total entries after merge: {r.total_entries}",
    ]
    if r.conflicts:
        lines += ["", "Conflicts:"]
        lines += [f"  {_where(c.path)} / {c.title}: {', '.join(c.fields)} (winner: {c.winner})"
                  for c in r.conflicts]
    return "\n".join(lines)
