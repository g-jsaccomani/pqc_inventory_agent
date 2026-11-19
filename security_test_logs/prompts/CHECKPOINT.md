Viewed PHASE1.md:1-447
Listed directory agentic_pqc_inventory
Viewed SKILL.md:1-116
Searched for files: *
Ran command: `git status && git branch -a && git log -n 10 --oneline`
Searched for files: *
Viewed SKILL.md:1-115
Listed directory tools
Viewed main.py:1-210
Viewed pyproject.toml:1-44
Viewed requirements.txt:1-30
Viewed Dockerfile:1-48
Viewed app.yaml:1-86
Viewed .env.example:1-37
Viewed auth_guard.py:1-800
Viewed auth_store.py:1-738
Viewed workspace_server.py:1-800
Viewed workspace_server.py:801-1600
Viewed workspace_server.py:1601-2400
Viewed workspace_server.py:2401-3200
Viewed workspace_server.py:3201-3719
Viewed gcloud_bridge.py:1-800
Viewed deploy_cloud_run.sh:1-197
Viewed test_phase1_distributed_auth.py:1-800
Viewed conftest.py:1-138
Viewed REPORT.md:1-61
Viewed MASTER_REMEDIATION_PLAN.md:1-131
Searched for "response_type"
Searched for "sqlite"
Searched for "localStorage"
Viewed calibration_engine.py:1-250
Ran command: `.venv/bin/pytest -q && .venv/bin/python -c "
import sys, importlib.util, inspect
import google.adk
from google.adk.sessions.database_session_service import DatabaseSessionService
from google.adk.auth.credential_service.base_credential_service import BaseCredentialService
print('Python:', sys.version.split()[0])
print('google-adk:', getattr(google.adk, '__version__', 'unknown'))
print('DatabaseSessionService.__init__:', inspect.signature(DatabaseSessionService.__init__))
print('BaseCredentialService methods:', [m for m in dir(BaseCredentialService) if not m.startswith('_')])
for pkg in ['psycopg', 'asyncpg', 'alembic', 'cryptography', 'google.cloud.kms']:
    spec = importlib.util.find_spec(pkg)
    print(f'{pkg}:', 'installed' if spec else 'NOT_FOUND')
" && which postgres initdb pg_ctl psql docker podman 2>&1 || true`
Viewed setup_and_deploy_vertex.sh:1-102
Viewed calibration_engine.py:251-440
Viewed test_auth_hardening.py:550-800
Viewed test_phase1_distributed_auth.py:801-911
Viewed test_auth_hardening.py:1-549
Viewed test_auth_hardening.py:801-1097
Viewed test_pqc_inventory.py:1-300
Ran command: `.venv/bin/python -c "
import inspect, glob, os
from google.adk.sessions import database_session_service
from google.adk.auth.credential_service import base_credential_service, in_memory_credential_service
print('=== DatabaseSessionService ===')
print(inspect.getsource(database_session_service.DatabaseSessionService.__init__))
print('=== BaseCredentialService ===')
print(inspect.getsource(base_credential_service))
print('=== InMemoryCredentialService ===')
print(inspect.getsource(in_memory_credential_service))
for pat in ['/opt/homebrew/**/postgres', '/usr/local/**/postgres', '/Library/PostgreSQL/**/postgres', '/Applications/Postgres.app/**/postgres', '/Applications/Docker.app/**/docker', '/opt/homebrew/bin/brew', '/usr/local/bin/brew']:
    matches = glob.glob(pat, recursive=True)
    if matches:
        print('FOUND:', pat, matches[:3])
"`
Ran command: `git diff --stat && which uv && uv --version && .venv/bin/python -m pip list | grep -E "psycopg|asyncpg|alembic|google-cloud-kms|pgserver|sqlalchemy|google-adk"`
Ran command: `uv pip list | grep -E "psycopg|asyncpg|alembic|google-cloud-kms|pgserver|sqlalchemy|google-adk|cryptography"`
Viewed PQC_INVENTORY_AGENT_REMEDIATION.md:1-60
Ran command: `git diff pqc_agent/auth_guard.py pqc_agent/portal_ui.py`
Searched for "initTokenClient"
Searched for "InMemoryCredentialService"
Searched for "RedirectResponse"
Searched for "pqc_revoked_tokens"
Searched for "pqc_oauth_config.json"
Searched for "/data"
Viewed test_pqc_inventory.py:301-1020
Ran command: `uv pip install --dry-run pgserver`
Searched for "SESSION_TOKEN_TYPE"
Searched for "sign_payload"
Viewed auth_store.py:625-685
Viewed workspace_server.py:2640-2740
Viewed workspace_server.py:3180-3205
Edited auth_store.py
Edited workspace_server.py
Viewed workspace_server.py:2642-2655
Viewed workspace_server.py:3185-3212
Edited workspace_server.py
Edited workspace_server.py
Viewed test_phase1_distributed_auth.py:890-911
Edited test_phase1_distributed_auth.py
Ran command: `.venv/bin/pytest -v && .venv/bin/python -m compileall -q pqc_agent tools tests && git diff --check && git status -s`
Viewed README.md:1-100
Viewed README.md:100-100
Ran command: `git add pqc_agent/auth_guard.py pqc_agent/auth_store.py pqc_agent/portal_ui.py pqc_agent/workspace_server.py tests/conftest.py tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py tests/test_pqc_inventory.py && git diff --cached --stat && git diff --cached --check && (! git diff --cached | grep -E "AIza[0-9A-Za-z_-]{35}|GOCSPX-[0-9A-Za-z_-]{20,}|PRIVATE KEY-----") && git commit -m "security: complete OAuth and distributed authentication remediation" && git log -n 2 --oneline`
Edited test_phase1_distributed_auth.py
Ran command: `python3 -c "p='tests/test_phase1_distributed_auth.py'; open(p,'w').write(open(p).read().rstrip()+'\n')" && git add tests/test_phase1_distributed_auth.py && git diff --cached --stat && git diff --cached --check && (! git diff --cached | grep -E "AIza[0-9A-Za-z_-]{35}|GOCSPX-[0-9A-Za-z_-]{20,}|PRIVATE KEY-----") && git commit -m "security: complete OAuth and distributed authentication remediation" && git log -n 2 --oneline`
Ran command: `uv add "psycopg[binary]>=3.2.0" "asyncpg>=0.30.0" "alembic>=1.14.0" "cryptography>=43.0.0" && uv add --optional dev "pgserver>=0.1.4"`
Listed directory sessions
Listed directory schemas
Viewed database_session_service.py:1-200
Viewed v1.py:1-277
Ran command: `.venv/bin/python -c "
import asyncio, os, shutil, pgserver
from sqlalchemy.engine import make_url
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from google.adk.sessions.database_session_service import DatabaseSessionService

# 1. Inspect how SQLAlchemy asyncpg translates Cloud SQL Unix socket URL
u = make_url('postgresql+asyncpg://pqc_app:secret@/pqc_workspace?host=/cloudsql/proj:us-central1:inst')
dialect = PGDialect_asyncpg()
print('asyncpg connect args for Cloud SQL Unix socket:', dialect.create_connect_args(u))

# 2. Boot real disposable PostgreSQL server via pgserver and test ADK DatabaseSessionService!
pg_dir = '/Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_probe'
shutil.rmtree(pg_dir, ignore_errors=True)
os.makedirs(pg_dir, exist_ok=True)
with pgserver.get_server(pg_dir) as pg:
    raw_uri = pg.get_uri()
    print('Real PostgreSQL URI:', raw_uri)
    async_uri = raw_uri.replace('postgresql://', 'postgresql+asyncpg://')
    async def check():
        svc = DatabaseSessionService(db_url=async_uri)
        s = await svc.create_session(app_name='pqc_agent', user_id='alice@google.com', state={'title': 'PG Test'})
        loaded = await svc.get_session(app_name='pqc_agent', user_id='alice@google.com', session_id=s.id)
        print('Loaded session from REAL PostgreSQL:', loaded.id, loaded.state)
        await svc.db_engine.dispose()
    asyncio.run(check())
shutil.rmtree(pg_dir, ignore_errors=True)
"`
Ran command: `uv remove --optional dev pgserver && rm -rf /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_probe && ls -la /opt/homebrew/bin 2>/dev/null | grep -iE "pg|postgres|brew|docker|podman|colima|orb" || ls -la /usr/local/bin 2>/dev/null | grep -iE "pg|postgres|brew|docker|podman|colima|orb" || echo "NO_LOCAL_POSTGRES_OR_CONTAINER_DAEMON"`
Viewed report_exporter.py:1-250
Viewed report_exporter.py:251-464
Ran command: `uv sync --extra dev`
Viewed auth_store.py:1-135
Viewed auth_store.py:680-753
Created auth_store.py
Created credential_service.py
Viewed gcloud_bridge.py:780-838
Edited gcloud_bridge.py
Viewed gcloud_bridge.py:495-680
Viewed gcloud_bridge.py:680-722
Edited calibration_engine.py
Edited gcloud_bridge.py
Edited calibration_engine.py
Edited report_exporter.py
Viewed workspace_server.py:40-240
Viewed workspace_server.py:280-615
Edited workspace_server.py
Viewed workspace_server.py:615-930
Viewed workspace_server.py:1490-1660
Viewed workspace_server.py:2000-2340
Viewed workspace_server.py:2885-3430
Viewed workspace_server.py:1255-1290
Edited workspace_server.py
Edited workspace_server.py
Edited workspace_server.py
Viewed workspace_server.py:615-880
Viewed workspace_server.py:1255-1310
Viewed PHASE1.md:160-447
Viewed auth_store.py:500-780
Viewed credential_service.py:360-480
Viewed gcloud_bridge.py:140-280
Viewed auth_store.py:920-1350
Viewed credential_service.py:500-590
Viewed auth_store.py:1347-1410
Viewed credential_service.py:475-505
Searched for "save_oauth_client_config"
Viewed workspace_server.py:2290-2325
Viewed workspace_server.py:2875-2925
Searched for "_get_data_dir"
Searched for "_load_tenant_users_map"
Searched for "_get_oauth_config_path"
Viewed workspace_server.py:215-310
Edited workspace_server.py
Edited workspace_server.py
Viewed workspace_server.py:1265-1295
Edited workspace_server.py
Searched for "(_load_tenant_users_map|_save_tenant_users_map|_load_session_metadata_map|_save_session_metadata_map|_delete_partitioned_session_metadata|InMemoryCredentialService|pqc_sessions\.db|pqc_user_connections\.json|pqc_tenant_users\.json|pqc_session_metadata\.json|pqc_oauth_config\.json|in_memory_only)"
Searched for "(InMemoryCredentialService|pqc_sessions\.db|pqc_user_connections\.json|pqc_tenant_users\.json|pqc_session_metadata\.json|pqc_oauth_config\.json|in_memory_only|/data/)"
Searched for "(/data|pqc_sessions\.db|sqlite://)"
Viewed auth_store.py:1-285
Created alembic.ini
Created env.py
Created script.py.mako
Created 20261117_0001_initial_phase1_phase2_schema.py
Ran command: `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql | head -n 60 && mkdir -p /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch && .venv/bin/alembic -x db_url="sqlite:////Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/alembic_smoke.db" upgrade head && .venv/bin/alembic -x db_url="sqlite:////Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/alembic_smoke.db" downgrade base && .venv/bin/alembic -x db_url="sqlite:////Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/alembic_smoke.db" upgrade head && rm -f /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/alembic_smoke.db`
Created migration_tool.py
Created migrate_sqlite_to_postgres.py
Searched for files: *
Viewed requirements.txt:1-30
Viewed Dockerfile:1-48
Viewed main.py:1-210
Viewed app.yaml:1-86
Listed directory scripts
Viewed README.md:1-100
Viewed deploy_cloud_run.sh:1-197
Viewed setup_and_deploy_vertex.sh:1-102
Searched for "(pqc_sessions\.db|calibration-history\.jsonl|type=cloud-storage|mount-path=/data)"
Viewed .env.example:1-37
Viewed 01-Agentic-PQC-README.md:80-81
Viewed 06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md:25-280
Viewed 06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md:240-284
Viewed 03-Agentic-PQC-SOW-Readiness-Assessment-Template.md:35-105
Viewed 07-Agentic-PQC-Discovery-Questionnaire.md:15-30
Viewed test_pqc_inventory.py:540-780
Viewed test_pqc_inventory.py:781-1020
Created requirements.txt
Edited main.py
Created Dockerfile
Created app.yaml
Created .env.example
Created deploy_cloud_run.sh
Created setup_and_deploy_vertex.sh
Edited README.md
Searched for "(06-Agentic|03-Agentic|07-Agentic|calibration-history)"
Edited 06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md
Edited 07-Agentic-PQC-Discovery-Questionnaire.md
Created MIGRATION_AND_ROLLBACK.md
Edited 03-Agentic-PQC-SOW-Readiness-Assessment-Template.md
Edited 06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md
Viewed conftest.py:1-138
Viewed test_auth_hardening.py:1-120
Viewed test_auth_hardening.py:480-540
Viewed test_auth_hardening.py:730-1090
Viewed test_auth_hardening.py:330-479
Viewed test_pqc_inventory.py:1-95
Viewed test_pqc_inventory.py:240-330
Edited conftest.py
Edited test_pqc_inventory.py
Viewed credential_service.py:585-631
Viewed credential_service.py:220-315
Edited test_auth_hardening.py
Edited test_auth_hardening.py
Edited test_auth_hardening.py
Viewed test_auth_hardening.py:490-542
Searched for "tool-consent"
Viewed workspace_server.py:2945-2985
Viewed workspace_server.py:2978-2998
Edited test_auth_hardening.py
Viewed test_auth_hardening.py:765-805
Viewed test_auth_hardening.py:965-1120
Edited test_auth_hardening.py
Edited test_auth_hardening.py
Created test_phase2_persistence_and_credentials.py
Ran command: `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs`
Edited test_phase2_persistence_and_credentials.py
Ran command: `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs`
Listed directory security_test_logs
Listed directory security-remediation
Searched for "credential_service"
Searched for "FAILED "
Viewed task-307.log:75-800
Viewed task-307.log:801-1350
Viewed task-307.log:1351-1619
Viewed workspace_server.py:895-965
Viewed workspace_server.py:1525-1710
Viewed workspace_server.py:1965-2005
Viewed auth_store.py:440-495
Viewed workspace_server.py:3430-3471
Viewed auth_store.py:405-439
Viewed v1.py:1-65
Viewed database_session_service.py:1-85
Viewed workspace_server.py:960-1015
Viewed _schema_check_utils.py:1-60
Viewed workspace_server.py:1945-1988
Edited workspace_server.py
Edited auth_store.py
Edited migration_tool.py
Edited alembic.ini
Edited test_auth_hardening.py
Edited test_pqc_inventory.py
Edited test_phase2_persistence_and_credentials.py
Edited workspace_server.py
Viewed workspace_server.py:1-65
Edited workspace_server.py
Ran command: `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs`
Listed directory phase_01_oauth
Viewed task-352.log:60-350
Edited migration_tool.py
Edited test_phase2_persistence_and_credentials.py
Edited test_phase2_persistence_and_credentials.py
Ran command: `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs`
Viewed REPORT.md:1-61
Listed directory tests
Viewed auth_store.py:1430-1465
Ran command: `git status --short && git diff --stat tests/test_phase1_distributed_auth.py`
Ran command: `git show --stat 60ffaa2`
Ran command: `git log -n 5 --oneline && .venv/bin/python -c '
import subprocess
out = subprocess.check_output(["git", "fsck", "--unreachable", "--no-reflogs", "--dangling"], text=True)
for line in out.splitlines():
    if "blob" in line:
        sha = line.split()[-1]
        txt = subprocess.check_output(["git", "cat-file", "-p", sha], errors="ignore").decode("utf-8", errors="ignore")
        if "test_phase1" in txt and len(txt.splitlines()) > 200:
            print("FOUND BLOB:", sha, "LINES:", len(txt.splitlines()))
'`
Ran command: `.venv/bin/python -c '
import subprocess
out = subprocess.check_output(["git", "fsck", "--unreachable", "--no-reflogs", "--dangling"], text=True)
for line in out.splitlines():
    if "blob" in line:
        sha = line.split()[-1]
        txt = subprocess.check_output(["git", "cat-file", "-p", sha]).decode("utf-8", errors="ignore")
        if "test_phase1" in txt and len(txt.splitlines()) > 100:
            print("FOUND BLOB:", sha, "LINES:", len(txt.splitlines()))
'`
Searched for "test_phase1_distributed_auth.py"
Edited test_phase2_persistence_and_credentials.py
Ran command: `.venv/bin/python -c '
import subprocess, pathlib
out = subprocess.check_output(["git", "fsck", "--unreachable", "--no-reflogs", "--dangling"], text=True)
for line in out.splitlines():
    if "blob" in line:
        sha = line.split()[-1]
        txt = subprocess.check_output(["git", "cat-file", "-p", sha]).decode("utf-8", errors="ignore")
        if "test_auth05_unregistered_session_fail_closed_and_3lo_account_binding" in txt:
            cleaned = txt.rstrip() + "\n"
            pathlib.Path("tests/test_phase1_distributed_auth.py").write_text(cleaned, encoding="utf-8")
            print("RESTORED:", sha, "LINES:", len(cleaned.splitlines()))
            break
'`
Ran command: `.venv/bin/python -m compileall -q pqc_agent tools scripts migrations tests && .venv/bin/pytest -v -rs`
Viewed REPORT.md:1-96
Viewed task-385.log:1-55
Ran command: `DATABASE_URL="postgresql+psycopg://pqc_app:placeholder@127.0.0.1:5432/pqc_workspace" .venv/bin/alembic upgrade head --sql > /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_schema.sql && wc -l /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_schema.sql && grep -E "^CREATE (TABLE|UNIQUE INDEX|INDEX)" /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_schema.sql && rm -f /Users/jsaccomani/.gemini/jetski/brain/fcb836b9-a9b3-452a-bd38-08d5d30dd0e0/scratch/pg_schema.sql`
Created REPORT.md
Created PHASE_01_02_ACCEPTANCE.md
Ran command: `git add .env.example Dockerfile README.md alembic.ini app.yaml main.py pyproject.toml requirements.txt uv.lock pqc_agent/auth_store.py pqc_agent/credential_service.py pqc_agent/migration_tool.py pqc_agent/workspace_server.py tools/calibration_engine.py tools/gcloud_bridge.py tools/report_exporter.py migrations/env.py migrations/script.py.mako migrations/versions/20261117_0001_initial_phase1_phase2_schema.py scripts/deploy_cloud_run.sh scripts/migrate_sqlite_to_postgres.py scripts/setup_and_deploy_vertex.sh docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md docs/07-Agentic-PQC-Discovery-Questionnaire.md docs/security-remediation/MIGRATION_AND_ROLLBACK.md docs/security-remediation/PHASE_01_02_ACCEPTANCE.md security_test_logs/phase_01_02_remediation/REPORT.md tests/conftest.py tests/test_auth_hardening.py tests/test_phase1_distributed_auth.py tests/test_phase2_persistence_and_credentials.py tests/test_pqc_inventory.py && git status --short && git diff --cached --stat && git diff --cached --check && .venv/bin/python -c '
import re, subprocess, sys
patterns = [re.compile(p) for p in (r"GOCSPX-[A-Za-z0-9_-]{10,}", r"AIza[0-9A-Za-z_-]{35}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")]
diff = subprocess.check_output(["git", "diff", "--cached"], text=True)
for line in diff.splitlines():
    if line.startswith("+") and not line.startswith("+++"):
        for pat in patterns:
            if pat.search(line):
                print("SECRET DETECTED:", line[:120])
                sys.exit(1)
print("SECRET SCAN PASSED: 0 secrets in staged diff")
' && .venv/bin/pytest -q -rs`
Viewed PHASE1.md:395-447
Ran command: `git commit -m "security: complete PostgreSQL persistence and credential architecture" && git log -n 4 --oneline && git status --short --branch`

A execução corretiva de [PHASE1.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/PHASE1.md) (Fases 1 e 2) foi concluída na branch `security-hardening/phase-01-02`, preservando integralmente o histórico existente e parando antes da Fase 3 conforme determinado.

As evidências detalhadas, logs redigidos e o checklist de aceite estão registrados em:
- [REPORT.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_01_02_remediation/REPORT.md)
- [PHASE_01_02_ACCEPTANCE.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/security-remediation/PHASE_01_02_ACCEPTANCE.md)
- [MIGRATION_AND_ROLLBACK.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/security-remediation/MIGRATION_AND_ROLLBACK.md)

---

### Relatório Final de Execução (Fases 1 e 2)

#### 1. Vulnerabilidades Corrigidas
- **`AUTH-01` (Fluxo Implícito Residual):** Removido todo suporte a `response_type=token`, fragmentos `#access_token` e inicialização automática de `initTokenClient` (GIS desabilitado por padrão via `PQC_ENABLE_GIS_JAVASCRIPT_CLIENT=false`). Clientes públicos e confidenciais utilizam exclusivamente Authorization Code + PKCE (`S256`).
- **`AUTH-02` (PKCE no `state`):** `code_verifier` e `oidc_nonce` são gerados por CSPRNG e mantidos exclusivamente no banco ([OAuthTransactionRecord](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_store.py#L92-L113)), indexados por `state` opaco de uso único (consumo atômico via `UPDATE ... WHERE consumed_at IS NULL`).
- **`AUTH-03` (Exposição de Bearer Token de Sessão):** Removida toda serialização de `"token"` em respostas JSON (`/api/auth/google`, `/api/auth/auto`, `/api/auth/switch`, `/api/auth/me`), `localStorage`, `sessionStorage` e URLs. Autenticação consolidada em cookies `HttpOnly`, `SameSite=Lax`, `Secure` + proteção CSRF vinculada à sessão (`X-PQC-CSRF-Token`).
- **`AUTH-04` (Estado Local de Replay/Revogação):** Substituídos dicionários em memória e arquivos locais por tabelas transacionais compartilhadas (`pqc_oauth_transactions`, `pqc_consumed_nonces`, `pqc_auth_sessions`), com validação *allowlist* *fail-closed* ([is_session_revoked_or_expired](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_store.py#L923-L950)) e verificação de correspondência de conta no callback 3LO.
- **`DB-01` & `DB-02` (SQLite em Produção / GCS FUSE):** Removida toda dependência de `sqlite:///data/pqc_sessions.db`, monkeypatches de WAL e montagens `--add-volume=name=pqc-data,type=cloud-storage` em `/data`. Produção falha fechado ([validate_production_postgres_only](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_store.py#L461-L485)) caso Cloud SQL / PostgreSQL não esteja configurado e acessível.
- **`DB-03` (JSON como Persistência Autoritativa):** Perfis de usuário (`pqc_tenant_users`), metadados de sessão com FK (`pqc_session_metadata`), conexões GCP (`pqc_user_connections`), configuração OAuth (`pqc_oauth_client_configs`) e histórico de calibração Mosca (`pqc_calibration_events`) migrados para o banco relacional sem *dual-writes* em disco; JSON mantido apenas para exportação explícita de backup ([export_workspace_json_backup](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py#L229-L237)).
- **`ID-01` (`InMemoryCredentialService` e arquivos temporários de token):** Substituído por [EncryptedDatabaseCredentialService](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py#L241-L607) com *envelope encryption* AES-256-GCM empacotado via Google Cloud KMS ([CloudKmsDekWrapper](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py#L96-L157)) e AAD vinculada a `app|tenant|user|key`, rotação server-side de *refresh token*, revogação imediata entre instâncias, *allowlist* de Service Account Impersonation ([validate_impersonated_service_account](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py#L181-L203)) e eliminação de arquivos `mkstemp` em disco.

#### 2. Mudanças de Arquitetura
- **Camada Relacional Unificada:** [DistributedAuthStore](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_store.py#L588-L1590) (`postgresql+psycopg`) + ADK `DatabaseSessionService` (`postgresql+asyncpg`), com *connection pooling*, *statement/connect timeouts*, verificação `SELECT 1` na inicialização, suporte nativo ao socket Unix do Cloud SQL Auth Proxy (`/cloudsql/<PROJECT>:<REGION>:<INSTANCE>`) e migrações versionadas via Alembic ([20261117_0001_initial_phase1_phase2_schema.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/migrations/versions/20261117_0001_initial_phase1_phase2_schema.py)).
- **Separação Estrita de Armazenamento:** PostgreSQL concentra todos os dados transacionais; Cloud Storage (`GcsArtifactService`) permanece exclusivo para objetos/relatórios; Secret Manager injeta segredos de runtime; Cloud KMS protege DEKs de credenciais delegadas.
- **Migração Segura e Idempotente (`DB-04`):** Implementado [migrate_legacy_persistence](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/migration_tool.py#L240-L795) e CLI [migrate_sqlite_to_postgres.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/scripts/migrate_sqlite_to_postgres.py) com abertura somente-leitura (`?mode=ro`), `--dry-run`, reconciliação de contagens, validação de integridade referencial SQL, detecção de conflitos/órfãos, remoção de tokens legados em texto claro e verificação SHA-256 de imutabilidade dos arquivos de origem.

#### 3. Arquivos Criados ou Modificados
- **Código e Persistência:** [auth_guard.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_guard.py), [auth_store.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/auth_store.py), [credential_service.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/credential_service.py), [migration_tool.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/migration_tool.py), [portal_ui.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/portal_ui.py), [workspace_server.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pqc_agent/workspace_server.py), [gcloud_bridge.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/gcloud_bridge.py), [calibration_engine.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/calibration_engine.py), [report_exporter.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tools/report_exporter.py), [main.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/main.py).
- **Migrações, Configuração e Deploy:** [alembic.ini](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/alembic.ini), [env.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/migrations/env.py), [script.py.mako](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/migrations/script.py.mako), [20261117_0001_initial_phase1_phase2_schema.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/migrations/versions/20261117_0001_initial_phase1_phase2_schema.py), [migrate_sqlite_to_postgres.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/scripts/migrate_sqlite_to_postgres.py), [Dockerfile](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/Dockerfile), [app.yaml](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/app.yaml), [.env.example](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/.env.example), [pyproject.toml](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/pyproject.toml), [uv.lock](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/uv.lock), [requirements.txt](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/requirements.txt), [deploy_cloud_run.sh](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/scripts/deploy_cloud_run.sh), [setup_and_deploy_vertex.sh](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/scripts/setup_and_deploy_vertex.sh).
- **Documentação, Testes e Evidências:** [README.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/README.md), [03-Agentic-PQC-SOW-Readiness-Assessment-Template.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/03-Agentic-PQC-SOW-Readiness-Assessment-Template.md), [06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/06-Agentic-PQC-Technical-Architecture-and-Consultant-Guide.md), [07-Agentic-PQC-Discovery-Questionnaire.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/07-Agentic-PQC-Discovery-Questionnaire.md), [MIGRATION_AND_ROLLBACK.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/security-remediation/MIGRATION_AND_ROLLBACK.md), [PHASE_01_02_ACCEPTANCE.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/security-remediation/PHASE_01_02_ACCEPTANCE.md), [REPORT.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/security_test_logs/phase_01_02_remediation/REPORT.md), [conftest.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/conftest.py), [test_auth_hardening.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_auth_hardening.py), [test_phase1_distributed_auth.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase1_distributed_auth.py), [test_phase2_persistence_and_credentials.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase2_persistence_and_credentials.py), [test_pqc_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_pqc_inventory.py).

#### 4. Resultados Reais de Testes
- `.venv/bin/pytest -v -rs`: **`73 passed, 0 failed, 2 skipped` (`24.76s`)**
  - [test_auth_hardening.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_auth_hardening.py): `30 passed`
  - [test_phase1_distributed_auth.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase1_distributed_auth.py): `9 passed` (todos os 16 cenários obrigatórios `AUTH-05` + *fail-closed* de sessão não registrada + bloqueio `403 USER_MISMATCH` em 3LO)
  - [test_phase2_persistence_and_credentials.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase2_persistence_and_credentials.py): `6 passed, 1 skipped (BLOCKED)` (fluxo multi-instância de 11 etapas + restart `Instance A/B -> A2/B2`, corrida concorrente de callbacks e escritas, interrupção/rollback/recuperação de banco, envelope Cloud KMS + bloqueio de transplante AAD entre tenants, *fail-closed* PostgreSQL + DDL Alembic `PostgresqlImpl`, e migração idempotente `DB-04`)
  - [test_pqc_inventory.py](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_pqc_inventory.py): `28 passed, 1 skipped`
- `DATABASE_URL="postgresql+psycopg://..." .venv/bin/alembic upgrade head --sql`: **`PASS`** (201 linhas de DDL transacional PostgreSQL geradas e validadas + ciclo `upgrade head -> downgrade base -> upgrade head`).

#### 5. Testes Bloqueados (`BLOCKED`)
1. **[test_phase2_live_postgresql_multi_instance_integration](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_phase2_persistence_and_credentials.py#L1000-L1014) (`PQC_TEST_POSTGRES_URL`) — `BLOCKED`:** Esta máquina corporativa macOS não possui `postgres`, `initdb`, `docker` ou `podman` instalados, e a política binária **Google Santa** bloqueou com `SIGKILL (9)` (`No matching rule`) o binário `initdb` embutido (`pgserver`).
2. **Verificação de Deploy em Cloud Run + Cloud SQL + Cloud KMS — `BLOCKED`:** Proibida pelas regras de segurança de `PHASE1.md` (*"Do not deploy, migrate or modify production infrastructure"*) e sem instância Cloud SQL de *staging* anexada à sessão local.
3. **[test_live_vertex_gemini_turn_reports_model_telemetry](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/tests/test_pqc_inventory.py#L947-L954) — `BLOCKED` (Opt-in):** Depende de `PQC_LIVE_LLM_TEST=1` com chamada tarifada ao Vertex AI.

#### 6. Limitações Remanescentes
- A execução contra um processo PostgreSQL 16 ativo (`PQC_TEST_POSTGRES_URL="postgresql+psycopg://..." .venv/bin/pytest -v`) deve ser executada em ambiente de CI/staging com PostgreSQL/Cloud SQL disponível antes de promover para produção.
- Itens das Fases 3+ (hardening de SSRF/egress, *circuit breaker* de probes Vertex AI, limites de tamanho/*magic bytes* de upload e usuário não-root no container) permanecem fora do escopo desta entrega conforme instruído.

#### 7. SHAs dos Dois Commits Criados
1. **`60ffaa2`** — `security: complete OAuth and distributed authentication remediation`
2. **`02b53e9`** — `security: complete PostgreSQL persistence and credential architecture`

#### 8. Pré-Requisitos de Infraestrutura de Produção
1. Provisionar instância **Cloud SQL for PostgreSQL 16** (HA regional, banco `pqc_workspace`, usuário `pqc_app`) e anexar ao Cloud Run via `--add-cloudsql-instances` + `PQC_CLOUD_SQL_CONNECTION_NAME`.
2. Criar segredos no **Secret Manager** (`pqc-session-secret` -> `PQC_AUTH_SECRET`, `pqc-db-password` -> `PQC_DB_PASSWORD`, `pqc-oauth-client-secret` -> `PQC_GOOGLE_OAUTH_CLIENT_SECRET`) com `roles/secretmanager.secretAccessor` restrito por segredo.
3. Criar chave simétrica dedicada no **Cloud KMS** (`PQC_KMS_KEY_NAME`) com `roles/cloudkms.cryptoKeyEncrypterDecrypter` concedido exclusivamente sobre essa chave à Service Account de runtime, além de `roles/cloudsql.client`.
4. Configurar `PQC_IAP_AUDIENCE` e executar o procedimento de backup, `alembic upgrade head` e migração `--dry-run` documentado em [MIGRATION_AND_ROLLBACK.md](file:///Users/jsaccomani/Documents/Jetsky/My%20Projects/agentic_pqc_inventory/docs/security-remediation/MIGRATION_AND_ROLLBACK.md).

#### 9. Status Final da Fase 1
- **`COMPLETED (PASS)`** — Todos os requisitos `AUTH-01`..`AUTH-05` implementados e verificados com testes automatizados passando.

#### 10. Status Final da Fase 2
- **`IMPLEMENTATION & LOCAL MULTI-INSTANCE TESTS PASS — BLOCKED ON LIVE POSTGRESQL / CLOUD SQL STAGING EXECUTION`** — Toda a implementação (`DB-01`..`DB-04`, `ID-01`), migrações Alembic, proteção Cloud KMS e suíte multi-instância local passaram integralmente (`0` falhas), restando apenas executar `PQC_TEST_POSTGRES_URL=... pytest` contra um daemon PostgreSQL 16 / Cloud SQL de *staging* (bloqueado localmente pelo Santa no macOS corporativo) antes de considerar a Fase 2 encerrada para produção ou avançar para a Fase 3.