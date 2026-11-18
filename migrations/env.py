"""Alembic migration environment for PQC Inventory Agent (PostgreSQL / Cloud SQL primary)."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from pqc_agent import auth_store

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = auth_store.PqcPersistenceBase.metadata


def _resolve_migration_url() -> str:
    """Resolves the target SQLAlchemy sync URL from ``-x db_url=...``, ``alembic.ini``, or PQC environment variables."""
    x_args = context.get_x_argument(as_dictionary=True)
    explicit = (x_args.get("db_url") or config.get_main_option("sqlalchemy.url") or "").strip()
    if explicit:
        auth_store.validate_production_postgres_only(explicit)
        return auth_store.normalize_sync_db_url(explicit)
    return auth_store.resolve_configured_database_url(async_driver=False)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emits deterministic DDL SQL without opening a live socket)."""
    url = _resolve_migration_url()
    is_sqlite = url.startswith("sqlite:")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        transactional_ddl=not is_sqlite,
        render_as_batch=is_sqlite,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode inside an atomic database transaction."""
    connectable = config.attributes.get("connection", None)
    if connectable is not None:
        is_sqlite = connectable.dialect.name == "sqlite"
        context.configure(
            connection=connectable,
            target_metadata=target_metadata,
            transactional_ddl=not is_sqlite,
            render_as_batch=is_sqlite,
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    url = _resolve_migration_url()
    engine = auth_store.build_sync_sqlalchemy_engine(url)
    # Migrations use NullPool for one-shot DDL execution so connections close deterministically.
    if engine.dialect.name != "sqlite":
        engine.dispose()
        from sqlalchemy import create_engine

        engine = create_engine(url, poolclass=pool.NullPool, future=True)

    try:
        with engine.connect() as connection:
            is_sqlite = connection.dialect.name == "sqlite"
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                transactional_ddl=not is_sqlite,
                render_as_batch=is_sqlite,
            )
            with context.begin_transaction():
                context.run_migrations()
            if connection.in_transaction():
                connection.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
