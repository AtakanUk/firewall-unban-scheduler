"""Entry point for cron without installing the package: ``python firewall_unban_scheduler.py run``."""

from unban_scheduler.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
