#!/usr/bin/env python3
"""Explicit Alembic database schema migration runner and verifier for PQC Workspace Portal.

Security & Operational Guarantees (DB-01):
1. Executes ``alembic upgrade head`` as a dedicated, explicit pre-deployment step — NEVER automatically during
   application container startup.
2. Acquires a PostgreSQL session advisory lock so migrations can never execute concurrently across runners.
3. Verifies ``EXPECTED_ALEMBIC_REVISION`` and all required PQC + ADK v1 tables immediately after upgrade.
4. Supports ``--verify-only`` (read-only startup/health gate) and ``--require-postgres`` (enforces PostgreSQL target).
"""

from __future__ import annotations

import argparse
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sqlalchemy.engine import make_url  # noqa: E402

from pqc_agent import auth_guard, auth_store  # noqa: E402
from pqc_agent.migration_tool import run_alembic_upgrade_head  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run or verify explicit Alembic schema migrations for the PQC Workspace Portal."
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="Target SQLAlchemy database URL (defaults to DATABASE_URL / SESSION_DB_URL / Cloud SQL env vars).",
    )
    parser.add_argument(
        "--require-postgres",
        action="store_true",
        help="Fail closed unless the resolved target database backend is PostgreSQL.",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Perform read-only verification of the current Alembic revision without applying migrations.",
    )
    args = parser.parse_args(argv)

    must_be_postgres = bool(args.require_postgres or auth_guard.is_production_environment())
    resolved_url = auth_store.resolve_configured_database_url(args.db_url, async_driver=False)
    backend = make_url(resolved_url).get_backend_name()
    if must_be_postgres and backend != "postgresql":
        print(
            f"ERROR: PostgreSQL target is required for schema migration; got backend '{backend}' "
            f"({auth_store.redact_db_url(resolved_url)}).",
            file=sys.stderr,
        )
        return 2

    if args.verify_only:
        engine = auth_store.build_sync_sqlalchemy_engine(resolved_url)
        try:
            rev = auth_store.verify_alembic_schema_on_engine(engine)
        finally:
            engine.dispose()
        print(
            f"OK: Verified Alembic schema revision '{rev}' on {auth_store.redact_db_url(resolved_url)}."
        )
        return 0

    verified_rev = run_alembic_upgrade_head(resolved_url, require_postgres=must_be_postgres)
    print(
        f"OK: Applied Alembic migrations and verified revision '{verified_rev}' on "
        f"{auth_store.redact_db_url(resolved_url)}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
