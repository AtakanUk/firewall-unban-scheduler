"""Settings from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _verify(name: str) -> bool | str:
    value = _env(name, "true")
    return {"true": True, "false": False}.get(value.lower(), value)


@dataclass(frozen=True)
class Settings:
    db_path: str = field(default_factory=lambda: _env("UNBAN_DB_PATH", "unban_scheduler.db"))
    retry_seconds: int = field(default_factory=lambda: int(_env("UNBAN_RETRY_SECONDS", "600")))
    batch_limit: int = field(default_factory=lambda: int(_env("UNBAN_BATCH_LIMIT", "300")))

    # Text file published as an external dynamic list (EDL) for the firewalls
    ip_list_path: str = field(default_factory=lambda: _env("IP_BLOCK_LIST_PATH", "ip_list.txt"))

    # Symantec / BlueCoat Edge SWG policy content
    bluecoat_url: str = field(default_factory=lambda: _env("BLUECOAT_CONTENT_URL"))
    bluecoat_token: str = field(default_factory=lambda: _env("BLUECOAT_TOKEN"))
    bluecoat_state_path: str = field(
        default_factory=lambda: _env("BLUECOAT_STATE_PATH", "bluecoat_domains.json")
    )
    bluecoat_verify: bool | str = field(default_factory=lambda: _verify("BLUECOAT_VERIFY_SSL"))

    # Prisma Access (Strata Cloud Manager) URL category
    prisma_client_id: str = field(default_factory=lambda: _env("PRISMA_CLIENT_ID"))
    prisma_client_secret: str = field(default_factory=lambda: _env("PRISMA_CLIENT_SECRET"))
    prisma_tsg_id: str = field(default_factory=lambda: _env("PRISMA_TSG_ID"))
    prisma_category_id: str = field(default_factory=lambda: _env("PRISMA_CATEGORY_ID"))

    # IBM QRadar SOAR (legacy unban flag and metrics)
    soar_host: str = field(default_factory=lambda: _env("SOAR_HOST"))
    soar_port: int = field(default_factory=lambda: int(_env("SOAR_PORT", "443")))
    soar_org: str = field(default_factory=lambda: _env("SOAR_ORG"))
    soar_api_key_id: str = field(default_factory=lambda: _env("SOAR_API_KEY_ID"))
    soar_api_key_secret: str = field(default_factory=lambda: _env("SOAR_API_KEY_SECRET"))
    soar_cafile: str = field(default_factory=lambda: _env("SOAR_CAFILE"))

    def soar_options(self) -> dict[str, object]:
        options: dict[str, object] = {
            "host": self.soar_host,
            "port": self.soar_port,
            "org": self.soar_org,
            "api_key_id": self.soar_api_key_id,
            "api_key_secret": self.soar_api_key_secret,
        }
        if self.soar_cafile:
            options["cafile"] = self.soar_cafile
        return options
