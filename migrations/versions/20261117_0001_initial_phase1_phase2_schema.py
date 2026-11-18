"""Initial Phase 1 and Phase 2 distributed PostgreSQL persistence schema.

Revision ID: 20261117_0001
Revises: None
Create Date: 2026-11-17 21:30:00+00:00
"""

from __future__ import annotations

import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20261117_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pqc_schema_metadata",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "pqc_oauth_transactions",
        sa.Column("state_id", sa.String(length=128), nullable=False),
        sa.Column("flow_mode", sa.String(length=32), nullable=False),
        sa.Column("client_type", sa.String(length=32), nullable=False),
        sa.Column("code_verifier", sa.String(length=256), nullable=False),
        sa.Column("oidc_nonce", sa.String(length=128), nullable=False),
        sa.Column("browser_binding_hash", sa.String(length=64), nullable=False),
        sa.Column("initiating_user_id", sa.String(length=320), nullable=True),
        sa.Column("initiating_session_jti", sa.String(length=128), nullable=True),
        sa.Column("app_session_id", sa.String(length=128), nullable=True),
        sa.Column("target_scope", sa.String(length=512), nullable=True),
        sa.Column("redirect_uri", sa.String(length=1024), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column("timezone", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("consumed_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("state_id"),
        sa.UniqueConstraint("oidc_nonce"),
    )
    op.create_index(
        "ix_pqc_oauth_transactions_initiating_user_id",
        "pqc_oauth_transactions",
        ["initiating_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_oauth_transactions_expires_at",
        "pqc_oauth_transactions",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "pqc_consumed_nonces",
        sa.Column("nonce_key", sa.String(length=160), nullable=False),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("nonce_key"),
    )
    op.create_index(
        "ix_pqc_consumed_nonces_expires_at",
        "pqc_consumed_nonces",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "pqc_auth_sessions",
        sa.Column("jti", sa.String(length=128), nullable=False),
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("auth_method", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("revoked_at", sa.Float(), nullable=True),
        sa.Column("revocation_reason", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_index(
        "ix_pqc_auth_sessions_token_sha256",
        "pqc_auth_sessions",
        ["token_sha256"],
        unique=True,
    )
    op.create_index(
        "ix_pqc_auth_sessions_user_id",
        "pqc_auth_sessions",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_auth_sessions_expires_at",
        "pqc_auth_sessions",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_auth_sessions_user_active",
        "pqc_auth_sessions",
        ["user_id", "revoked_at", "expires_at"],
        unique=False,
    )

    op.create_table(
        "pqc_tenant_users",
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("tenant_domain", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("timezone", sa.String(length=128), nullable=False),
        sa.Column("auth_method", sa.String(length=64), nullable=False),
        sa.Column("picture", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("last_login_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index(
        "ix_pqc_tenant_users_tenant_domain",
        "pqc_tenant_users",
        ["tenant_domain"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_tenant_users_last_login_at",
        "pqc_tenant_users",
        ["last_login_at"],
        unique=False,
    )

    op.create_table(
        "pqc_session_metadata",
        sa.Column("session_id", sa.String(length=128), nullable=False),
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("tenant_domain", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=False),
        sa.Column("model_id", sa.String(length=128), nullable=True),
        sa.Column("model_label", sa.String(length=255), nullable=True),
        sa.Column("message_count", sa.Integer(), nullable=False),
        sa.Column("attachments_json", sa.Text(), nullable=False),
        sa.Column("turn_telemetry_json", sa.Text(), nullable=False),
        sa.Column("fallback_messages_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["pqc_tenant_users.user_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("session_id"),
    )
    op.create_index(
        "ix_pqc_session_metadata_user_id",
        "pqc_session_metadata",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_session_metadata_tenant_domain",
        "pqc_session_metadata",
        ["tenant_domain"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_session_metadata_updated_at",
        "pqc_session_metadata",
        ["updated_at"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_session_meta_owner_updated",
        "pqc_session_metadata",
        ["user_id", "updated_at"],
        unique=False,
    )

    op.create_table(
        "pqc_user_connections",
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("tenant_domain", sa.String(length=255), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("organization_id", sa.String(length=128), nullable=False),
        sa.Column("project_id", sa.String(length=255), nullable=False),
        sa.Column("location", sa.String(length=128), nullable=False),
        sa.Column("impersonated_service_account", sa.String(length=320), nullable=False),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("user_id"),
    )
    op.create_index(
        "ix_pqc_user_connections_tenant_domain",
        "pqc_user_connections",
        ["tenant_domain"],
        unique=False,
    )

    op.create_table(
        "pqc_oauth_client_configs",
        sa.Column("config_key", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=512), nullable=False),
        sa.Column("encrypted_client_secret", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=True),
        sa.Column("updated_at", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("config_key"),
    )

    op.create_table(
        "pqc_calibration_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_uuid", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=512), nullable=False),
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("tenant_domain", sa.String(length=255), nullable=False),
        sa.Column("industry_sector", sa.String(length=64), nullable=False),
        sa.Column("sector_label", sa.String(length=255), nullable=False),
        sa.Column("confidentiality_years_x", sa.Float(), nullable=False),
        sa.Column("migration_years_y", sa.Float(), nullable=False),
        sa.Column("crqc_horizon_years_z", sa.Float(), nullable=False),
        sa.Column("gateway_header_limit_kb", sa.Integer(), nullable=False),
        sa.Column("entry_json", sa.Text(), nullable=False),
        sa.Column("timestamp_utc", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_pqc_calibration_events_event_uuid",
        "pqc_calibration_events",
        ["event_uuid"],
        unique=True,
    )
    op.create_index(
        "ix_pqc_calibration_events_scope",
        "pqc_calibration_events",
        ["scope"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_calibration_events_user_id",
        "pqc_calibration_events",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_calibration_events_tenant_domain",
        "pqc_calibration_events",
        ["tenant_domain"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_calibration_events_timestamp_utc",
        "pqc_calibration_events",
        ["timestamp_utc"],
        unique=False,
    )

    op.create_table(
        "pqc_delegated_credentials",
        sa.Column("credential_id", sa.String(length=128), nullable=False),
        sa.Column("app_name", sa.String(length=128), nullable=False),
        sa.Column("tenant_domain", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.String(length=320), nullable=False),
        sa.Column("credential_key", sa.String(length=128), nullable=False),
        sa.Column("kek_provider", sa.String(length=32), nullable=False),
        sa.Column("kms_key_name", sa.String(length=512), nullable=True),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=False),
        sa.Column("payload_nonce_b64", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_b64", sa.Text(), nullable=False),
        sa.Column("aad_sha256", sa.String(length=64), nullable=False),
        sa.Column("has_refresh_token", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("revoked_at", sa.Float(), nullable=True),
        sa.Column("revocation_reason", sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint("credential_id"),
        sa.UniqueConstraint(
            "app_name",
            "tenant_domain",
            "user_id",
            "credential_key",
            name="uq_pqc_delegated_cred_owner",
        ),
    )
    op.create_index(
        "ix_pqc_delegated_credentials_tenant_domain",
        "pqc_delegated_credentials",
        ["tenant_domain"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_delegated_credentials_user_id",
        "pqc_delegated_credentials",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_pqc_delegated_credentials_expires_at",
        "pqc_delegated_credentials",
        ["expires_at"],
        unique=False,
    )

    schema_table = sa.table(
        "pqc_schema_metadata",
        sa.column("key", sa.String),
        sa.column("value", sa.String),
        sa.column("updated_at", sa.String),
    )
    op.bulk_insert(
        schema_table,
        [
            {
                "key": "schema_version",
                "value": revision,
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_pqc_delegated_credentials_expires_at", table_name="pqc_delegated_credentials")
    op.drop_index("ix_pqc_delegated_credentials_user_id", table_name="pqc_delegated_credentials")
    op.drop_index("ix_pqc_delegated_credentials_tenant_domain", table_name="pqc_delegated_credentials")
    op.drop_table("pqc_delegated_credentials")

    op.drop_index("ix_pqc_calibration_events_timestamp_utc", table_name="pqc_calibration_events")
    op.drop_index("ix_pqc_calibration_events_tenant_domain", table_name="pqc_calibration_events")
    op.drop_index("ix_pqc_calibration_events_user_id", table_name="pqc_calibration_events")
    op.drop_index("ix_pqc_calibration_events_scope", table_name="pqc_calibration_events")
    op.drop_index("ix_pqc_calibration_events_event_uuid", table_name="pqc_calibration_events")
    op.drop_table("pqc_calibration_events")

    op.drop_table("pqc_oauth_client_configs")

    op.drop_index("ix_pqc_user_connections_tenant_domain", table_name="pqc_user_connections")
    op.drop_table("pqc_user_connections")

    op.drop_index("ix_pqc_session_meta_owner_updated", table_name="pqc_session_metadata")
    op.drop_index("ix_pqc_session_metadata_updated_at", table_name="pqc_session_metadata")
    op.drop_index("ix_pqc_session_metadata_tenant_domain", table_name="pqc_session_metadata")
    op.drop_index("ix_pqc_session_metadata_user_id", table_name="pqc_session_metadata")
    op.drop_table("pqc_session_metadata")

    op.drop_index("ix_pqc_tenant_users_last_login_at", table_name="pqc_tenant_users")
    op.drop_index("ix_pqc_tenant_users_tenant_domain", table_name="pqc_tenant_users")
    op.drop_table("pqc_tenant_users")

    op.drop_index("ix_pqc_auth_sessions_user_active", table_name="pqc_auth_sessions")
    op.drop_index("ix_pqc_auth_sessions_expires_at", table_name="pqc_auth_sessions")
    op.drop_index("ix_pqc_auth_sessions_user_id", table_name="pqc_auth_sessions")
    op.drop_index("ix_pqc_auth_sessions_token_sha256", table_name="pqc_auth_sessions")
    op.drop_table("pqc_auth_sessions")

    op.drop_index("ix_pqc_consumed_nonces_expires_at", table_name="pqc_consumed_nonces")
    op.drop_table("pqc_consumed_nonces")

    op.drop_index("ix_pqc_oauth_transactions_expires_at", table_name="pqc_oauth_transactions")
    op.drop_index("ix_pqc_oauth_transactions_initiating_user_id", table_name="pqc_oauth_transactions")
    op.drop_table("pqc_oauth_transactions")

    op.drop_table("pqc_schema_metadata")
