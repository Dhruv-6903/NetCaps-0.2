"""Search index for fast text-based searching."""

from typing import Dict, List, Set


class SearchIndex:
    def __init__(self) -> None:
        self._index: Dict[str, str] = {}

    def index(self, entity_id: str, text: str) -> None:
        self._index[entity_id] = text.lower()

    def search(self, query: str) -> List[str]:
        words = query.lower().split()
        if not words:
            return list(self._index.keys())
        results = []
        for entity_id, text in self._index.items():
            if all(w in text for w in words):
                results.append(entity_id)
        return results

    def clear(self) -> None:
        self._index.clear()

    def remove(self, entity_id: str) -> None:
        self._index.pop(entity_id, None)
