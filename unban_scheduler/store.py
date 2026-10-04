"""SQLite store of scheduled unbans.

One row per (incident, source). Life cycle: ``scheduled`` -> ``processing`` ->
``done``; on failure the row goes back to ``scheduled`` with a later
``expires_at`` so it is retried instead of being lost.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_unbans (
    incident_id      INTEGER NOT NULL,
    source           TEXT    NOT NULL,
    expires_at       INTEGER NOT NULL,              -- epoch seconds (UTC)
    status           TEXT    NOT NULL DEFAULT 'scheduled',
    last_error       TEXT,
    ip_address       TEXT,                          -- comma-separated IPs on the EDL
    bluecoat_domain  TEXT,                          -- comma-separated domains on the proxy policy
    prisma_domain    TEXT,                          -- comma-separated domains in the Prisma URL category
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    PRIMARY KEY (incident_id, source)
);
CREATE INDEX IF NOT EXISTS idx_scheduled_unbans_due ON scheduled_unbans(status, expires_at);
"""


@dataclass(frozen=True)
class DueUnban:
    incident_id: int
    source: str
    ip_address: str | None
    bluecoat_domain: str | None
    prisma_domain: str | None


class UnbanStore:
    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        with self.session() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """Autocommit connection that is closed afterwards."""
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def schedule(
        self,
        incident_id: int,
        source: str,
        minutes: int,
        ip_address: str | None = None,
        bluecoat_domain: str | None = None,
        prisma_domain: str | None = None,
        now: int | None = None,
    ) -> int:
        """Insert or extend a ban; returns the expiry (epoch seconds).

        Re-scheduling an existing row moves its expiry, keeps targets that are
        not given again and re-opens rows that were already done.
        """
        now = int(now if now is not None else time.time())
        expires_at = now + int(minutes) * 60
        with self.session() as conn:
            conn.execute(
                """
                INSERT INTO scheduled_unbans (incident_id, source, expires_at, status, last_error,
                                              ip_address, bluecoat_domain, prisma_domain, created_at, updated_at)
                VALUES (?, ?, ?, 'scheduled', NULL, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id, source) DO UPDATE SET
                    expires_at      = excluded.expires_at,
                    status          = CASE WHEN scheduled_unbans.status = 'done' THEN 'scheduled' ELSE scheduled_unbans.status END,
                    last_error      = NULL,
                    ip_address      = COALESCE(excluded.ip_address, scheduled_unbans.ip_address),
                    bluecoat_domain = COALESCE(excluded.bluecoat_domain, scheduled_unbans.bluecoat_domain),
                    prisma_domain   = COALESCE(excluded.prisma_domain, scheduled_unbans.prisma_domain),
                    updated_at      = excluded.updated_at
                """,
                (
                    incident_id,
                    source,
                    expires_at,
                    ip_address,
                    bluecoat_domain,
                    prisma_domain,
                    now,
                    now,
                ),
            )
        return expires_at

    def claim_due(self, limit: int = 300, now: int | None = None) -> list[DueUnban]:
        """Expired rows, switched to ``processing`` in the same transaction so parallel runners do not double-process."""
        now = int(now if now is not None else time.time())
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """
                SELECT incident_id, source, ip_address, bluecoat_domain, prisma_domain
                  FROM scheduled_unbans
                 WHERE status = 'scheduled' AND expires_at <= ?
                 ORDER BY expires_at
                 LIMIT ?
                """,
                (now, limit),
            ).fetchall()
            conn.executemany(
                "UPDATE scheduled_unbans SET status = 'processing', updated_at = ? WHERE incident_id = ? AND source = ?",
                [(now, row[0], row[1]) for row in rows],
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return [DueUnban(*row) for row in rows]

    def mark_done(self, incident_id: int, source: str, note: str | None = None) -> None:
        with self.session() as conn:
            conn.execute(
                "UPDATE scheduled_unbans SET status = 'done', last_error = ?, updated_at = ? WHERE incident_id = ? AND source = ?",
                (note, int(time.time()), incident_id, source),
            )

    def mark_error(self, incident_id: int, source: str, error: str, retry_in: int = 600) -> None:
        now = int(time.time())
        with self.session() as conn:
            conn.execute(
                """
                UPDATE scheduled_unbans
                   SET status = 'scheduled', expires_at = ?, last_error = ?, updated_at = ?
                 WHERE incident_id = ? AND source = ?
                """,
                (now + retry_in, (error or "")[:500], now, incident_id, source),
            )

    def rows(self, status: str | None = None) -> list[dict]:
        conn = self.connect()
        conn.row_factory = sqlite3.Row
        try:
            if status:
                result = conn.execute(
                    "SELECT * FROM scheduled_unbans WHERE status = ? ORDER BY expires_at", (status,)
                )
            else:
                result = conn.execute("SELECT * FROM scheduled_unbans ORDER BY expires_at")
            return [dict(row) for row in result]
        finally:
            conn.close()
