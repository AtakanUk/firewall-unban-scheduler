"""Command line.

python -m unban_scheduler schedule --incident-id 2101 --source ip-block --minutes 1440 --ip 198.51.100.7
python -m unban_scheduler run                 # from cron, every minute
python -m unban_scheduler list [--status scheduled]
python -m unban_scheduler purge [--apply] [--component db|ip|all] [--max-changes N]
python -m unban_scheduler block-ip 198.51.100.7,198.51.100.8
python -m unban_scheduler unblock-ip 198.51.100.7
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime

from . import alerts
from .backends import IpBlockList
from .config import Settings
from .store import UnbanStore

log = logging.getLogger("unban_scheduler")


def _print(data) -> None:
    json.dump(data, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="unban_scheduler", description="Time-limited blocks with automatic unban"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)

    schedule = commands.add_parser(
        "schedule", help="register (or extend) a ban that expires after N minutes"
    )
    schedule.add_argument("--incident-id", type=int, required=True)
    schedule.add_argument(
        "--source", required=True, help="what created the ban, e.g. 'ip-block' or 'proxy-block'"
    )
    schedule.add_argument("--minutes", type=int, required=True)
    schedule.add_argument("--ip", help="comma-separated IPs on the block list")
    schedule.add_argument(
        "--bluecoat-domain", help="comma-separated domains on the BlueCoat policy"
    )
    schedule.add_argument(
        "--prisma-domain", help="comma-separated domains in the Prisma URL category"
    )

    commands.add_parser("run", help="execute expired bans")
    listing = commands.add_parser("list", help="show scheduled bans")
    listing.add_argument("--status", choices=["scheduled", "processing", "done"])

    purge = commands.add_parser("purge", help="report or remove orphaned bans")
    purge.add_argument("--apply", action="store_true")
    purge.add_argument("--component", choices=["db", "ip", "all"], default="all")
    purge.add_argument("--max-changes", type=int)

    for name in ("block-ip", "unblock-ip"):
        sub = commands.add_parser(
            name, help=f"{'add to' if name == 'block-ip' else 'remove from'} the IP block list"
        )
        sub.add_argument("ips", help="comma-separated IP addresses")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    settings = Settings()
    if args.command in ("block-ip", "unblock-ip"):
        ip_list = IpBlockList(settings.ip_list_path)
        _print(ip_list.add(args.ips) if args.command == "block-ip" else ip_list.remove(args.ips))
        return 0

    store = UnbanStore(settings.db_path)
    if args.command == "schedule":
        expires = store.schedule(
            args.incident_id,
            args.source,
            args.minutes,
            args.ip,
            args.bluecoat_domain,
            args.prisma_domain,
        )
        _print(
            {
                "incident_id": args.incident_id,
                "source": args.source,
                "expires_at": datetime.fromtimestamp(expires, UTC).isoformat(),
            }
        )
        return 0
    if args.command == "list":
        _print(store.rows(args.status))
        return 0

    handler = alerts.install()
    try:
        if args.command == "run":
            from .runner import build_dispatcher, run

            summary = run(
                store, build_dispatcher(settings), settings.batch_limit, settings.retry_seconds
            )
            return 1 if summary.failed else 0

        from . import purge as purger

        ip_list = IpBlockList(settings.ip_list_path)
        plan = purger.plan(store, ip_list, args.component)
        _print(
            {
                "db_orphans": plan.db_orphans,
                "ip_orphans": plan.ip_orphans,
                "ip_kept": len(plan.ip_keep),
            }
        )
        if not args.apply:
            log.info("Dry run, nothing changed. Re-run with --apply.")
            return 0
        try:
            purger.apply(store, ip_list, plan, args.max_changes)
        except RuntimeError as exc:
            log.error("%s", exc)
            return 2
        return 0
    except Exception:
        log.exception("%s failed", args.command)
        raise
    finally:
        alerts.flush(handler, f"{args.command} @ {datetime.now():%Y-%m-%d %H:%M}")


if __name__ == "__main__":
    raise SystemExit(main())
