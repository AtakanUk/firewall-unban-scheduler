import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from unban_scheduler import purge
from unban_scheduler.backends import BlueCoatPolicy, IpBlockList, PrismaUrlCategory
from unban_scheduler.config import Settings
from unban_scheduler.runner import Dispatcher, run
from unban_scheduler.store import UnbanStore


@pytest.fixture
def store(tmp_path):
    return UnbanStore(str(tmp_path / "unban.db"))


@pytest.fixture
def ip_list(tmp_path):
    path = tmp_path / "ip_list.txt"
    path.write_text("192.0.2.1\n192.0.2.2\n192.0.2.3\n")
    return IpBlockList(str(path))


def test_schedule_upsert_keeps_targets_and_reopens_done(store):
    store.schedule(1, "ip-block", 10, ip_address="192.0.2.1", now=1000)
    store.mark_done(1, "ip-block")
    store.schedule(1, "ip-block", 20, now=2000)
    row = store.rows()[0]
    assert (row["status"], row["expires_at"], row["ip_address"]) == (
        "scheduled",
        2000 + 1200,
        "192.0.2.1",
    )


def test_claim_due_marks_processing_once(store):
    store.schedule(1, "a", 1, ip_address="192.0.2.1", now=0)
    store.schedule(2, "a", 999, ip_address="192.0.2.2", now=0)
    assert [row.incident_id for row in store.claim_due(now=120)] == [1]
    assert store.claim_due(now=120) == []
    assert store.rows("processing")[0]["incident_id"] == 1


def test_ip_block_list_add_remove(ip_list):
    assert ip_list.add("192.0.2.3, 192.0.2.9, bad")["added"] == ["192.0.2.9"]
    result = ip_list.remove("192.0.2.1,192.0.2.77,nope")
    assert (
        result["removed"] == ["192.0.2.1"]
        and result["not_listed"] == ["192.0.2.77"]
        and result["invalid"] == ["nope"]
    )
    assert ip_list.read() == ["192.0.2.2", "192.0.2.3", "192.0.2.9"]


def test_runner_dispatch_retry_and_gone(store, ip_list):
    store.schedule(1, "ip-block", 0, ip_address="192.0.2.1", now=0)
    store.schedule(2, "proxy-block", 0, prisma_domain="bad.example", now=0)
    store.schedule(3, "legacy", 0, now=0)
    store.schedule(4, "legacy", 0, now=0)

    prisma = MagicMock()
    prisma.remove.side_effect = RuntimeError("token expired")
    soar = MagicMock()

    def flag(incident_id, source):
        if incident_id == 4:
            raise RuntimeError("404 Unable to find Incident 4")

    soar.mark_unbanned.side_effect = flag
    summary = run(store, Dispatcher(ip_list=ip_list, prisma=prisma, soar=soar), retry_in=600)

    assert (summary.done, summary.gone, summary.failed) == (2, 1, 1)
    assert "192.0.2.1" not in ip_list.read()
    statuses = {row["incident_id"]: (row["status"], row["last_error"]) for row in store.rows()}
    assert statuses[2][0] == "scheduled" and "token expired" in statuses[2][1]
    assert statuses[4] == ("done", "incident deleted in SOAR")


def test_metric_flag_failure_does_not_fail_direct_unban(store, ip_list):
    store.schedule(1, "ip-block", 0, ip_address="192.0.2.2", now=0)
    soar = MagicMock()
    soar.mark_unbanned.side_effect = RuntimeError("SOAR down")
    summary = run(store, Dispatcher(ip_list=ip_list, soar=soar))
    assert summary.done == 1 and summary.results[0]["soar_flag"] == "skipped"


def test_bluecoat_remove_pushes_full_list(tmp_path, monkeypatch):
    state = tmp_path / "bluecoat.json"
    state.write_text(
        json.dumps({"content": {"urls": [{"url": "a.example"}, {"url": "b.example"}]}})
    )
    monkeypatch.setenv("BLUECOAT_STATE_PATH", str(state))
    monkeypatch.setenv(
        "BLUECOAT_CONTENT_URL", "https://proxy.example.com:8082/api/policies/x/content"
    )
    post = MagicMock()
    result = BlueCoatPolicy(Settings(), post=post).remove("a.example,c.example")
    assert result["removed"] == ["a.example"] and result["not_found"] == ["c.example"]
    assert post.call_args.kwargs["json"]["content"]["urls"] == [{"url": "b.example"}]


def test_prisma_list_key_detection():
    assert PrismaUrlCategory.list_key({"name": "x", "list": ["a"]}) == "list"
    assert PrismaUrlCategory.list_key({"name": "x", "domains": []}) == "domains"


def test_purge_plan_and_apply(store, ip_list):
    store.schedule(1, "ip-block", 60, ip_address="192.0.2.2")
    store.schedule(2, "legacy", 60)
    plan = purge.plan(store, ip_list)
    assert plan.db_orphans == [(2, "legacy")]
    assert plan.ip_orphans == ["192.0.2.1", "192.0.2.3"]

    with pytest.raises(RuntimeError):
        purge.apply(store, ip_list, plan, max_changes=2)

    backup = purge.apply(store, ip_list, plan)
    assert ip_list.read() == ["192.0.2.2"]
    assert Path(backup).read_text().count("\n") == 3
    assert {row["incident_id"]: row["status"] for row in store.rows()}[2] == "done"
