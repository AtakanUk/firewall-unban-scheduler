"""Executes expired bans (run from cron, e.g. every minute)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .store import DueUnban, UnbanStore

log = logging.getLogger(__name__)

# Text of the SOAR 404 response; a deleted incident must not be retried forever.
INCIDENT_GONE_MARKER = "Unable to find Incident"


@dataclass
class RunSummary:
    done: int = 0
    gone: int = 0
    failed: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


class Dispatcher:
    """Routes a due row to the backend that holds the ban.

    Priority: Prisma URL category > BlueCoat policy > IP block list. Rows
    without any target use the legacy flow: the SOAR incident is flagged and a
    SOAR workflow performs the unban. After a direct unban the SOAR flag is still
    set for metrics, but failures there are ignored because the unban itself
    already happened.
    """

    def __init__(self, ip_list=None, bluecoat=None, prisma=None, soar=None) -> None:
        self.ip_list = ip_list
        self.bluecoat = bluecoat
        self.prisma = prisma
        self.soar = soar

    def _require(self, backend: Any, name: str) -> Any:
        if backend is None:
            raise RuntimeError(f"{name} backend is not configured")
        return backend

    def unban(self, row: DueUnban) -> dict[str, Any]:
        if row.prisma_domain:
            flow, result = "prisma", self._require(self.prisma, "Prisma").remove(row.prisma_domain)
        elif row.bluecoat_domain:
            flow, result = (
                "bluecoat",
                self._require(self.bluecoat, "BlueCoat").remove(row.bluecoat_domain),
            )
        elif row.ip_address:
            flow, result = "ip", self._require(self.ip_list, "IP list").remove(row.ip_address)
        else:
            self._require(self.soar, "SOAR").mark_unbanned(row.incident_id, row.source)
            return {"flow": "soar"}

        metric = "skipped"
        if self.soar is not None:
            try:
                self.soar.mark_unbanned(row.incident_id, row.source)
                metric = "ok"
            except Exception as exc:
                log.warning(
                    "Metric flag for incident %s not set (unban already done): %s",
                    row.incident_id,
                    exc,
                )
        return {"flow": flow, "result": result, "soar_flag": metric}


def run(
    store: UnbanStore, dispatcher: Dispatcher, batch_limit: int = 300, retry_in: int = 600
) -> RunSummary:
    summary = RunSummary()
    due = store.claim_due(limit=batch_limit)
    log.info("%d unban(s) due", len(due))
    for row in due:
        context = f"incident={row.incident_id} source={row.source}"
        try:
            result = dispatcher.unban(row)
            store.mark_done(row.incident_id, row.source)
            summary.done += 1
            summary.results.append({"incident_id": row.incident_id, "source": row.source, **result})
            log.info("Unbanned %s via %s", context, result["flow"])
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            if INCIDENT_GONE_MARKER in str(exc):
                store.mark_done(row.incident_id, row.source, note="incident deleted in SOAR")
                summary.gone += 1
                log.warning("%s: incident no longer exists, not retried", context)
            else:
                store.mark_error(row.incident_id, row.source, error, retry_in=retry_in)
                summary.failed += 1
                log.error("Unban failed for %s, retry in %ds: %s", context, retry_in, error)
    log.info("Run finished: done=%d gone=%d failed=%d", summary.done, summary.gone, summary.failed)
    return summary


def build_dispatcher(settings, soar_client: Any | None = None) -> Dispatcher:
    from .backends import BlueCoatPolicy, IpBlockList, PrismaUrlCategory, SoarFlags

    prisma = (
        PrismaUrlCategory(settings)
        if settings.prisma_client_id and settings.prisma_category_id
        else None
    )
    bluecoat = BlueCoatPolicy(settings) if settings.bluecoat_url else None
    if soar_client is None and settings.soar_host:
        import resilient

        soar_client = resilient.get_client(settings.soar_options())
    return Dispatcher(
        ip_list=IpBlockList(settings.ip_list_path),
        bluecoat=bluecoat,
        prisma=prisma,
        soar=SoarFlags(soar_client) if soar_client is not None else None,
    )
