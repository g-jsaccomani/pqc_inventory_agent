#!/usr/bin/env python3
"""CLI entrypoint for safe, idempotent SQLite + JSON/JSONL to PostgreSQL data migration (DB-04).

Usage (staging / disposable database):
    python scripts/migrate_sqlite_to_postgres.py \
        --source-sqlite ./legacy_backup/pqc_sessions.db \
        --source-data-dir ./legacy_backup/data \
        --target-db-url "$DATABASE_URL" \
        --dry-run \
        --report-json ./migration_report.json \
        --report-md ./migration_report.md

Original SQLite and JSON/JSONL files are opened read-only and verified via SHA-256 checksums before and after
execution; they are never modified or deleted automatically.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pqc_agent.migration_tool import migrate_legacy_persistence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Idempotent, non-destructive PQC Workspace migration from SQLite + JSON/JSONL to PostgreSQL."
    )
    parser.add_argument(
        "--source-sqlite",
        default=None,
        help="Path to legacy ADK SQLite database file (opened read-only).",
    )
    parser.add_argument(
        "--source-data-dir",
        default=None,
        help="Path to legacy JSON/JSONL data directory (opened read-only).",
    )
    parser.add_argument(
        "--target-db-url",
        default=os.getenv("DATABASE_URL") or os.getenv("SESSION_DB_URL") or "",
        help="Target PostgreSQL SQLAlchemy URL (defaults to $DATABASE_URL / $SESSION_DB_URL).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate, reconcile, and check referential integrity inside a rolled-back transaction.",
    )
    parser.add_argument(
        "--allow-production-target",
        action="store_true",
        help="Explicit operator confirmation required when PQC_PRODUCTION_MODE / K_SERVICE is active.",
    )
    parser.add_argument(
        "--report-json",
        default=None,
        help="Optional output path for structured JSON migration report.",
    )
    parser.add_argument(
        "--report-md",
        default=None,
        help="Optional output path for Markdown migration report.",
    )
    args = parser.parse_args(argv)

    if not args.target_db_url:
        parser.error("--target-db-url (or $DATABASE_URL) is required.")

    report = migrate_legacy_persistence(
        target_db_url=args.target_db_url,
        source_sqlite_path=args.source_sqlite,
        source_data_dir=args.source_data_dir,
        dry_run=args.dry_run,
        allow_production_target=args.allow_production_target,
        report_json_path=args.report_json,
        report_markdown_path=args.report_md,
    )
    print(report.to_markdown())
    return 0 if report.status in ("SUCCESS", "DRY_RUN_OK") else 2


if __name__ == "__main__":
    raise SystemExit(main())
