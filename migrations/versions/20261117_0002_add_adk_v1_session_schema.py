"""Add Google ADK v1 session persistence tables under Alembic authority.

Revision ID: 20261117_0002
Revises: 20261117_0001
Create Date: 2026-11-17 23:10:00+00:00
"""

from __future__ import annotations

import datetime
from typing import Sequence, Union

from alembic import op
from google.adk.sessions.schemas.shared import (
    DEFAULT_MAX_KEY_LENGTH,
    DEFAULT_MAX_VARCHAR_LENGTH,
    DynamicJSON,
    PreciseTimestamp,
)
import sqlalchemy as sa

revision: str = "20261117_0002"
down_revision: Union[str, None] = "20261117_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ADK_SCHEMA_VERSION_KEY = "schema_version"
ADK_SCHEMA_VERSION_V1 = "1"


def upgrade() -> None:
    ctx = op.get_context()
    is_offline = bool(getattr(ctx, "as_sql", False))
    existing_tables: set[str] = set()
    if not is_offline:
        existing_tables = set(sa.inspect(op.get_bind()).get_table_names())

    if "adk_internal_metadata" not in existing_tables:
        op.create_table(
            "adk_internal_metadata",
            sa.Column("key", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("value", sa.String(length=DEFAULT_MAX_VARCHAR_LENGTH), nullable=False),
            sa.PrimaryKeyConstraint("key"),
        )

    if "sessions" not in existing_tables:
        op.create_table(
            "sessions",
            sa.Column("app_name", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("user_id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("state", DynamicJSON(), nullable=False),
            sa.Column("create_time", PreciseTimestamp(), nullable=False),
            sa.Column("update_time", PreciseTimestamp(), nullable=False),
            sa.PrimaryKeyConstraint("app_name", "user_id", "id"),
        )

    if "events" not in existing_tables:
        op.create_table(
            "events",
            sa.Column("id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("app_name", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("user_id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("session_id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("invocation_id", sa.String(length=DEFAULT_MAX_VARCHAR_LENGTH), nullable=False),
            sa.Column("timestamp", PreciseTimestamp(), nullable=False),
            sa.Column("event_data", DynamicJSON(), nullable=True),
            sa.ForeignKeyConstraint(
                ["app_name", "user_id", "session_id"],
                ["sessions.app_name", "sessions.user_id", "sessions.id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", "app_name", "user_id", "session_id"),
        )
        op.create_index(
            "idx_events_app_user_session_ts_id",
            "events",
            ["app_name", "user_id", "session_id", sa.desc("timestamp"), sa.desc("id")],
            unique=False,
        )

    if "app_states" not in existing_tables:
        op.create_table(
            "app_states",
            sa.Column("app_name", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("state", DynamicJSON(), nullable=False),
            sa.Column("update_time", PreciseTimestamp(), nullable=False),
            sa.PrimaryKeyConstraint("app_name"),
        )

    if "user_states" not in existing_tables:
        op.create_table(
            "user_states",
            sa.Column("app_name", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("user_id", sa.String(length=DEFAULT_MAX_KEY_LENGTH), nullable=False),
            sa.Column("state", DynamicJSON(), nullable=False),
            sa.Column("update_time", PreciseTimestamp(), nullable=False),
            sa.PrimaryKeyConstraint("app_name", "user_id"),
        )

    adk_meta_table = sa.table(
        "adk_internal_metadata",
        sa.column("key", sa.String),
        sa.column("value", sa.String),
    )
    if is_offline:
        op.bulk_insert(
            adk_meta_table,
            [{"key": ADK_SCHEMA_VERSION_KEY, "value": ADK_SCHEMA_VERSION_V1}],
        )
    else:
        bind = op.get_bind()
        current_adk_ver = bind.execute(
            sa.select(adk_meta_table.c.value).where(adk_meta_table.c.key == ADK_SCHEMA_VERSION_KEY)
        ).scalar_one_or_none()
        if current_adk_ver is None:
            bind.execute(
                adk_meta_table.insert().values(
                    key=ADK_SCHEMA_VERSION_KEY,
                    value=ADK_SCHEMA_VERSION_V1,
                )
            )
        elif current_adk_ver != ADK_SCHEMA_VERSION_V1:
            bind.execute(
                adk_meta_table.update()
                .where(adk_meta_table.c.key == ADK_SCHEMA_VERSION_KEY)
                .values(value=ADK_SCHEMA_VERSION_V1)
            )

    pqc_meta_table = sa.table(
        "pqc_schema_metadata",
        sa.column("key", sa.String),
        sa.column("value", sa.String),
        sa.column("updated_at", sa.String),
    )
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    op.execute(
        pqc_meta_table.update()
        .where(pqc_meta_table.c.key == "schema_version")
        .values(value=revision, updated_at=now_iso)
    )


def downgrade() -> None:
    pqc_meta_table = sa.table(
        "pqc_schema_metadata",
        sa.column("key", sa.String),
        sa.column("value", sa.String),
        sa.column("updated_at", sa.String),
    )
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    op.execute(
        pqc_meta_table.update()
        .where(pqc_meta_table.c.key == "schema_version")
        .values(value="20261117_0001", updated_at=now_iso)
    )

    op.drop_index("idx_events_app_user_session_ts_id", table_name="events")
    op.drop_table("events")
    op.drop_table("user_states")
    op.drop_table("app_states")
    op.drop_table("sessions")
    op.drop_table("adk_internal_metadata")
