"""Job ID persistence for r7-cli.

Stores active export jobs in ``~/.r7-cli/jobs.json`` so that the CLI can
auto-select the most recent job when ``--job-id`` is omitted.
"""
from __future__ import annotations

import json
from pathlib import Path

from r7cli.models import JobEntry

JOBS_FILE = Path.home() / ".r7-cli" / "jobs.json"


class JobStore:
    """CRUD operations on the local jobs ledger."""

    def __init__(self, path: Path = JOBS_FILE) -> None:
        self._path = path

    # -- internal helpers ---------------------------------------------------

    def _load(self) -> list[dict]:
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _save(self, entries: list[dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        # Atomic write: write to temp file then rename (atomic on POSIX)
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=self._path.parent,
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            json.dump(entries, tmp, indent=2)
            tmp.flush()
            import os
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        tmp_path.replace(self._path)

    # -- public API ---------------------------------------------------------

    def add(self, entry: JobEntry) -> None:
        """Append a new job entry to the store."""
        entries = self._load()
        entries.append({
            "job_id": entry.job_id,
            "export_type": entry.export_type,
            "created_at": entry.created_at,
            "status": entry.status,
        })
        self._save(entries)

    def get_latest(self, export_type: str) -> JobEntry | None:
        """Return the entry with the most recent ``created_at`` for *export_type*."""
        matches = [
            e for e in self._load() if e["export_type"] == export_type
        ]
        if not matches:
            return None
        best = max(matches, key=lambda e: e["created_at"])
        return JobEntry(**best)

    def get_active(self, export_type: str) -> list[JobEntry]:
        """Return all entries with ``status == 'ACTIVE'`` for *export_type*."""
        return [
            JobEntry(**e)
            for e in self._load()
            if e["export_type"] == export_type and e["status"] == "ACTIVE"
        ]

    def remove(self, job_id: str) -> None:
        """Delete the entry matching *job_id*."""
        entries = [e for e in self._load() if e["job_id"] != job_id]
        self._save(entries)

    def mark_terminal(self, job_id: str, status: str) -> None:
        """Remove the entry from active jobs (effectively deletes it)."""
        self.remove(job_id)
