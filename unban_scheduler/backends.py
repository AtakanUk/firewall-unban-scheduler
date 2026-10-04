"""Enforcement points a ban can live on, each with add/remove operations."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import tempfile
from collections.abc import Callable, Iterable
from typing import Any

import requests

from .config import Settings

log = logging.getLogger(__name__)


def split_targets(raw: str | Iterable[str] | None) -> list[str]:
    if raw is None:
        return []
    items = raw.split(",") if isinstance(raw, str) else raw
    return [item.strip() for item in items if item and item.strip()]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def write_atomic(path: str, text: str) -> None:
    """Write via a temp file in the same directory and rename, so readers never see a half-written list."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


class IpBlockList:
    """Plain-text IP list served to the firewalls as an external dynamic list (one IP per line)."""

    def __init__(self, path: str) -> None:
        self.path = path

    def read(self) -> list[str]:
        try:
            with open(self.path, encoding="utf-8") as handle:
                return [line.strip() for line in handle if line.strip()]
        except FileNotFoundError:
            return []

    def write(self, entries: list[str]) -> None:
        write_atomic(self.path, "".join(f"{entry}\n" for entry in entries))

    def add(self, raw: str | Iterable[str]) -> dict[str, Any]:
        requested = split_targets(raw)
        invalid = [item for item in requested if not is_ip(item)]
        current = self.read()
        added = [item for item in dict.fromkeys(requested) if is_ip(item) and item not in current]
        if added:
            self.write(current + added)
        return {"added": added, "invalid": invalid, "total": len(current) + len(added)}

    def remove(self, raw: str | Iterable[str]) -> dict[str, Any]:
        requested = split_targets(raw)
        targets = {item for item in requested if is_ip(item)}
        current = self.read()
        remaining = [entry for entry in current if entry not in targets]
        removed = [entry for entry in current if entry in targets]
        if removed:
            self.write(remaining)
        return {
            "removed": removed,
            "invalid": [item for item in requested if not is_ip(item)],
            "not_listed": sorted(targets - set(removed)),
            "remaining": len(remaining),
        }


class BlueCoatPolicy:
    """Symantec (BlueCoat) Edge SWG policy content holding the blocked domains.

    The full URL list is kept in a local JSON file (the format the policy API
    expects, ``{"content": {"urls": [{"url": ...}, ...]}}``) and pushed as a whole
    after each change.
    """

    def __init__(self, settings: Settings, post: Callable[..., Any] = requests.post) -> None:
        self.settings = settings
        self._post = post

    def remove(self, raw: str) -> dict[str, Any]:
        targets = split_targets(raw)
        with open(self.settings.bluecoat_state_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        urls = payload.setdefault("content", {}).setdefault("urls", [])
        before = len(urls)
        payload["content"]["urls"] = [entry for entry in urls if entry.get("url") not in targets]
        removed = sorted({entry.get("url") for entry in urls} & set(targets))

        write_atomic(self.settings.bluecoat_state_path, json.dumps(payload, indent=2))
        response = self._post(
            self.settings.bluecoat_url,
            headers={
                "X-Auth-Token": self.settings.bluecoat_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
            verify=self.settings.bluecoat_verify,
            timeout=60,
        )
        response.raise_for_status()
        return {
            "removed": removed,
            "not_found": sorted(set(targets) - set(removed)),
            "total_before": before,
            "total_after": len(payload["content"]["urls"]),
        }


class PrismaUrlCategory:
    """Custom URL category in Prisma Access (Strata Cloud Manager configuration API)."""

    AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    API_URL = "https://api.sase.paloaltonetworks.com/sse/config/v1/url-categories"
    LIST_KEYS = ("list", "items", "urls", "url_list", "sites", "members")

    def __init__(self, settings: Settings, session: requests.Session | None = None) -> None:
        self.settings = settings
        self.session = session or requests.Session()

    def _token(self) -> str:
        response = self.session.post(
            self.AUTH_URL,
            data={
                "grant_type": "client_credentials",
                "scope": f"tsg_id:{self.settings.prisma_tsg_id}",
            },
            auth=(self.settings.prisma_client_id, self.settings.prisma_client_secret),
            timeout=30,
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("Prisma Access token response has no access_token")
        return token

    @classmethod
    def list_key(cls, category: dict[str, Any]) -> str:
        for key in cls.LIST_KEYS:
            if isinstance(category.get(key), list):
                return key
        for key, value in category.items():
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                return key
        raise RuntimeError("URL category has no URL list field")

    def remove(self, raw: str) -> dict[str, Any]:
        targets = set(split_targets(raw))
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        url = f"{self.API_URL}/{self.settings.prisma_category_id}"

        response = self.session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        body = response.json()
        category = body["data"] if isinstance(body.get("data"), dict) else body
        key = self.list_key(category)
        current = set(category.get(key, []))
        category[key] = sorted(current - targets)

        response = self.session.put(
            url, headers={**headers, "Content-Type": "application/json"}, json=category, timeout=30
        )
        response.raise_for_status()
        return {
            "removed": sorted(current & targets),
            "not_found": sorted(targets - current),
            "total_before": len(current),
            "total_after": len(category[key]),
        }


class SoarFlags:
    """Incident fields that drive the in-SOAR unban workflow and the ban/unban metrics."""

    def __init__(self, rest_client: Any) -> None:
        self.client = rest_client

    def mark_unbanned(self, incident_id: int, source: str) -> Any:
        import resilient

        uri = f"/incidents/{incident_id}"
        patch = resilient.Patch(self.client.get(uri))
        patch.add_value("unban_action_control", "Yes")
        patch.add_value("scheduler_source", str(source))
        return self.client.patch(uri, patch)
