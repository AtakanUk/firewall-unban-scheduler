"""Clean-up of orphaned bans.

Orphans are
* active rows (scheduled/processing) without any target: they can never be
  executed and would be retried forever, and
* IPs on the block list that no active row refers to: they were added by hand
  or their row was lost, so nothing would ever remove them.

Dry run by default. ``--max-changes`` aborts an apply that would touch more
items than expected (a typo in the DB path would otherwise empty the block list).
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime

from .backends import IpBlockList, split_targets
from .store import UnbanStore

log = logging.getLogger(__name__)


@dataclass
class PurgePlan:
    db_orphans: list[tuple[int, str]] = field(default_factory=list)
    ip_orphans: list[str] = field(default_factory=list)
    ip_keep: list[str] = field(default_factory=list)

    @property
    def changes(self) -> int:
        return len(self.db_orphans) + len(self.ip_orphans)


def plan(store: UnbanStore, ip_list: IpBlockList, component: str = "all") -> PurgePlan:
    result = PurgePlan()
    with store.session() as conn:
        if component in ("db", "all"):
            result.db_orphans = conn.execute(
                """SELECT incident_id, source FROM scheduled_unbans
                    WHERE status IN ('scheduled', 'processing')
                      AND ip_address IS NULL AND bluecoat_domain IS NULL AND prisma_domain IS NULL"""
            ).fetchall()
        if component in ("ip", "all"):
            live = set()
            for (raw,) in conn.execute(
                "SELECT ip_address FROM scheduled_unbans WHERE status IN ('scheduled', 'processing') AND ip_address IS NOT NULL"
            ):
                live.update(split_targets(raw))
            for entry in ip_list.read():
                (result.ip_keep if entry in live else result.ip_orphans).append(entry)
    return result


def apply(
    store: UnbanStore, ip_list: IpBlockList, purge: PurgePlan, max_changes: int | None = None
) -> str | None:
    """Apply the plan; returns the backup path of the block list if it was rewritten."""
    if max_changes is not None and purge.changes > max_changes:
        raise RuntimeError(
            f"{purge.changes} changes exceed --max-changes {max_changes}, nothing applied"
        )

    if purge.db_orphans:
        now = int(time.time())
        with store.session() as conn:
            conn.executemany(
                "UPDATE scheduled_unbans SET status = 'done', last_error = 'purged as orphan', updated_at = ? "
                "WHERE incident_id = ? AND source = ?",
                [(now, incident_id, source) for incident_id, source in purge.db_orphans],
            )
        log.info("Closed %d orphaned row(s)", len(purge.db_orphans))

    backup = None
    if purge.ip_orphans:
        backup = f"{ip_list.path}.bak-{datetime.now():%Y%m%d-%H%M%S}"
        shutil.copy2(ip_list.path, backup)
        ip_list.write(purge.ip_keep)
        log.info(
            "Removed %d orphaned IP(s) from the block list (backup: %s)",
            len(purge.ip_orphans),
            backup,
        )
    return backup
