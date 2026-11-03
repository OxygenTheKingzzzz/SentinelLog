"""Read-only file tail: one import, replay dedup, and rotation that keeps new lines."""

import pytest
from sqlalchemy import func, select

from sentinellog.config import get_settings
from sentinellog.live.journald import journald_availability
from sentinellog.live.paths import PathRejected, resolve_allowed_path
from sentinellog.live.service import authorize_file, poll_collector
from sentinellog.models import LiveCollector, LogEvent, LogSource

LINE_A = "Nov  3 08:00:01 testhost app[1]: live alpha\n"
LINE_B = "Nov  3 08:00:02 testhost app[1]: live beta\n"
LINE_C = "Nov  3 08:00:03 testhost app[2]: live gamma\n"


def _events(db, source_id) -> list[LogEvent]:
    return list(
        db.scalars(
            select(LogEvent).where(LogEvent.source_id == source_id).order_by(LogEvent.line_number)
        ).all()
    )


def test_paths_reject_traversal_and_escape(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "secret.log"
    outside.write_text("secret\n")
    roots = [allowed]
    with pytest.raises(PathRejected):
        resolve_allowed_path(str(allowed / ".." / "secret.log"), roots)
    with pytest.raises(PathRejected):
        resolve_allowed_path(str(outside), roots)
    with pytest.raises(PathRejected):
        resolve_allowed_path("relative.log", roots)
    with pytest.raises(PathRejected):
        resolve_allowed_path("/tmp/nope\x00.log", roots)
    link = allowed / "escape.log"
    link.symlink_to(outside)
    with pytest.raises(PathRejected):
        resolve_allowed_path(str(link), roots)
    outside_dir = tmp_path / "secret-dir"
    outside_dir.mkdir()
    hidden = outside_dir / "hidden.log"
    hidden.write_text("hidden\n")
    link_dir = allowed / "linked"
    link_dir.symlink_to(outside_dir)
    with pytest.raises(PathRejected):
        resolve_allowed_path(str(link_dir / "hidden.log"), roots)
    inside = allowed / "app.log"
    inside.write_text("")
    assert resolve_allowed_path(str(inside), roots) == inside.resolve()


def test_tail_imports_once_dedups_replay_and_keeps_rotated_lines(db, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "live_allow_roots", str(tmp_path))
    path = tmp_path / "app.log"
    path.write_text("")
    collector = authorize_file(
        db,
        actor="test",
        name="live-app",
        path=str(path),
        description=None,
        source_year=2026,
    )
    source = db.get(LogSource, collector.source_id)
    assert source is not None
    assert source.kind == "live_file"
    assert source.name != "linux-2k"

    path.write_text(LINE_A + LINE_B)
    assert poll_collector(db, collector.id) == 2
    rows = _events(db, source.id)
    assert [row.content for row in rows] == ["live alpha", "live beta"]
    assert {row.origin for row in rows} == {"live_file"}
    assert (
        db.scalar(select(func.count()).select_from(LogSource).where(LogSource.kind == "historical"))
        == 0
    )

    with path.open("a") as handle:
        handle.write(LINE_A)
    assert poll_collector(db, collector.id) == 0
    assert len(_events(db, source.id)) == 2

    saved = db.get(LiveCollector, collector.id)
    assert saved is not None
    saved.byte_offset = 0
    saved.partial = ""
    db.commit()
    assert poll_collector(db, collector.id) == 0
    assert len(_events(db, source.id)) == 2
    saved = db.get(LiveCollector, collector.id)
    assert saved is not None
    assert saved.duplicates_skipped >= 2

    rotated = tmp_path / "app.log.1"
    path.rename(rotated)
    path.write_text(LINE_C)
    assert poll_collector(db, collector.id) == 1
    rows = _events(db, source.id)
    assert [row.content for row in rows] == ["live alpha", "live beta", "live gamma"]
    assert rows[-1].line_number == 3


def test_truncate_and_recreate_is_not_dropped(db, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "live_allow_roots", str(tmp_path))
    path = tmp_path / "trunc.log"
    path.write_text(LINE_A + LINE_B)
    collector = authorize_file(
        db,
        actor="test",
        name="live-trunc",
        path=str(path),
        description=None,
        source_year=2026,
    )
    assert poll_collector(db, collector.id) == 2
    path.write_text(LINE_C)
    saved = db.get(LiveCollector, collector.id)
    assert saved is not None
    assert saved.byte_offset > path.stat().st_size
    assert poll_collector(db, collector.id) == 1
    rows = _events(db, collector.source_id)
    assert rows[-1].content == "live gamma"
    assert len(rows) == 3


def test_partial_line_waits_for_newline(db, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "live_allow_roots", str(tmp_path))
    path = tmp_path / "partial.log"
    path.write_text(LINE_A[:-1])
    collector = authorize_file(
        db,
        actor="test",
        name="live-partial",
        path=str(path),
        description=None,
        source_year=2026,
    )
    assert poll_collector(db, collector.id) == 0
    assert len(_events(db, collector.source_id)) == 0
    with path.open("a") as handle:
        handle.write("\n")
    assert poll_collector(db, collector.id) == 1
    assert _events(db, collector.source_id)[0].content == "live alpha"


def test_api_rejects_unauthorized_paths_and_reports_journald(client, monkeypatch, tmp_path):
    monkeypatch.setattr(get_settings(), "live_allow_roots", str(tmp_path))
    denied = client.post("/api/v1/live/files", json={"name": "nope", "path": "/etc/passwd"})
    assert denied.status_code == 400
    traversal = client.post(
        "/api/v1/live/files",
        json={"name": "nope", "path": str(tmp_path / ".." / "passwd")},
    )
    assert traversal.status_code == 400
    available, detail = journald_availability()
    status = client.get("/api/v1/live/status")
    assert status.status_code == 200
    body = status.json()
    assert body["implemented"] is True
    assert body["journald_available"] is available
    assert body["journald_detail"] == detail
    assert available is False
