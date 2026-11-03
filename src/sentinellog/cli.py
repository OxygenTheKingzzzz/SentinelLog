"""Command line import for the bundled dataset and a local API server."""

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

from sentinellog.config import get_settings
from sentinellog.db import SessionLocal
from sentinellog.ingestion.service import (
    create_source,
    import_raw_log,
    import_structured_csv,
    import_template_csv,
)
from sentinellog.ingestion.validation import FileRejected
from sentinellog.jsonlog import configure_logging
from sentinellog.models import LogSource


def _dataset_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    return Path(__file__).resolve().parents[2] / "datasets"


def _dataset_file(directory: Path, name: str) -> Path:
    root = directory.resolve()
    path = (root / name).resolve()
    if path.parent != root or not path.is_file():
        raise FileRejected(f"dataset file is not available: {name}")
    return path


def _job_counts(job) -> dict[str, object]:
    return {
        "job_id": str(job.id),
        "status": job.status,
        "lines_total": job.lines_total,
        "lines_parsed": job.lines_parsed,
        "lines_errored": job.lines_errored,
        "duplicates_skipped": job.duplicates_skipped,
        "conflicts": job.conflicts,
        "stats": job.stats,
    }


def _import_bundled(args: argparse.Namespace) -> int:
    configure_logging(get_settings().log_level)
    try:
        root = _dataset_root(args.dataset_dir)
        template_path = _dataset_file(root, "Linux_2k.log_templates.csv")
        raw_path = _dataset_file(root, "Linux_2k.log")
        structured_path = _dataset_file(root, "Linux_2k.log_structured.csv")
    except FileRejected as exc:
        print(str(exc), file=sys.stderr)
        return 2

    session = SessionLocal()
    try:
        source = session.scalar(select(LogSource).where(LogSource.name == args.source_name))
        if source is None:
            year = args.year if args.year is not None else get_settings().source_year
            source = create_source(
                session,
                name=args.source_name,
                description="Loghub Linux_2k historical syslog. No ground-truth labels.",
                source_year=year,
            )
        elif args.year is not None and source.source_year != args.year:
            print(
                "source already exists with a different source_year; refusing to change it",
                file=sys.stderr,
            )
            return 2
        templates = import_template_csv(
            session,
            source_id=source.id,
            filename=template_path.name,
            data=template_path.read_bytes(),
            actor="cli",
        )
        raw = import_raw_log(
            session,
            source_id=source.id,
            filename=raw_path.name,
            data=raw_path.read_bytes(),
            actor="cli",
        )
        validated = import_structured_csv(
            session,
            source_id=source.id,
            filename=structured_path.name,
            data=structured_path.read_bytes(),
            actor="cli",
            mode="validate",
        )
    except FileRejected as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        session.close()

    summary = {
        "source_id": str(source.id),
        "source_name": source.name,
        "source_year": source.source_year,
        "templates": _job_counts(templates),
        "raw": _job_counts(raw),
        "structured_validate": _job_counts(validated),
    }
    print(json.dumps(summary, indent=2))
    if raw.status != "completed" or validated.status != "completed":
        return 1
    if raw.lines_errored or validated.lines_errored or raw.conflicts or validated.conflicts:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinellog")
    sub = parser.add_subparsers(dest="command", required=True)

    bundled = sub.add_parser(
        "import-bundled",
        help="import datasets/ and validate against the structured CSV",
    )
    bundled.add_argument("--source-name", default="linux-2k")
    bundled.add_argument("--year", type=int, default=None)
    bundled.add_argument("--dataset-dir", type=Path, default=None)

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)
    if args.command == "import-bundled":
        return _import_bundled(args)
    if args.command == "serve":
        import uvicorn

        uvicorn.run("sentinellog.main:app", host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
