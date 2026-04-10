from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any


def build_search_text(row: Any) -> str:
    if is_dataclass(row):
        row = asdict(row)
    if isinstance(row, dict):
        row = " ".join(build_search_text(v) for v in row.values())
    elif isinstance(row, (list, tuple, set)):
        row = " ".join(build_search_text(v) for v in row)
    else:
        row = str(row)
    return row.lower()


class FilterIndex:
    def __init__(self) -> None:
        self._rows: list[str] = []

    def append(self, row: Any) -> None:
        self._rows.append(build_search_text(row))

    def extend(self, rows: list[Any]) -> None:
        self._rows.extend(build_search_text(r) for r in rows)

    def query(self, text: str) -> list[int]:
        q = text.strip().lower()
        if not q:
            return list(range(len(self._rows)))
        return [i for i, row in enumerate(self._rows) if q in row]
