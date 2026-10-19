"""
Bounded In-Memory Incident Store.
Provides thread-safe LRU cache with anti-DoS memory bounding.
"""

from __future__ import annotations

from collections import OrderedDict
from threading import Lock
from typing import Optional

from backend.models.evidence import IncidentEvidence


class BoundedIncidentStore:
    """Thread-safe bounded in-memory incident cache with LRU eviction."""

    def __init__(self, max_capacity: int = 1000):
        self.max_capacity = max_capacity
        self._store: OrderedDict[str, IncidentEvidence] = OrderedDict()
        self._lock = Lock()

    def get(self, incident_id: str) -> Optional[IncidentEvidence]:
        with self._lock:
            if incident_id in self._store:
                self._store.move_to_end(incident_id)
                return self._store[incident_id]
            return None

    def set(self, incident_id: str, evidence: IncidentEvidence) -> None:
        with self._lock:
            if incident_id in self._store:
                self._store.move_to_end(incident_id)
            self._store[incident_id] = evidence
            if len(self._store) > self.max_capacity:
                self._store.popitem(last=False)

    def __contains__(self, incident_id: str) -> bool:
        with self._lock:
            return incident_id in self._store

    def __getitem__(self, incident_id: str) -> IncidentEvidence:
        with self._lock:
            return self._store[incident_id]

    def __setitem__(self, incident_id: str, evidence: IncidentEvidence) -> None:
        self.set(incident_id, evidence)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


# Global bounded store instance
incident_store = BoundedIncidentStore(max_capacity=1000)
