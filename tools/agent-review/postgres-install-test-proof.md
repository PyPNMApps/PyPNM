# Postgres Install + Test Execution Proof (Minimal Excerpts)

## 1) Install Flow Proof (required)
A) install.sh
- Option parsing + interactive prompt default behavior

FILE: install.sh
RANGE: 42-52
EXCERPT:
  --db-install-sqlite
                 Select SQLite as the DB backend (default when no DB flag is provided).
  --db-install-postgres
                 Select Postgres as the DB backend and prompt for a DSN or connection fields.
                 If no DB flag is provided, the installer prompts in interactive mode
                 (defaulting to sqlite) and defaults to sqlite in non-interactive or CI runs.

FILE: install.sh
RANGE: 136-152
EXCERPT:
    --db-install-sqlite)
      DB_INSTALL_SQLITE="1"
      ;;
    --db-install-postgres)
      DB_INSTALL_POSTGRES="1"
      ;;

FILE: install.sh
RANGE: 408-438
EXCERPT:
  if [[ "$DB_INSTALL_SQLITE" == "1" ]]; then
    echo "sqlite"
    return
  fi
  if [[ "$DB_INSTALL_POSTGRES" == "1" ]]; then
    echo "postgres"
    return
  fi
  if [[ ! -t 0 || -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "sqlite"
    return
  fi
  ...
  read -r -p "Choose database backend [sqlite]: " selection
  ...
  if [[ "$selection" == "" ]]; then
    selection="sqlite"
  fi

- Config write (Database.backend, Database.sqlite.path, Database.postgres.dsn)

FILE: install.sh
RANGE: 512-538
EXCERPT:
  db = data.get("Database")
  if not isinstance(db, dict):
      db = {}
      data["Database"] = db
  ...
  if "path" not in sqlite_cfg or sqlite_cfg["path"] is None:
      sqlite_cfg["path"] = ".data/db/pypnm.sqlite3"
  ...
  postgres_cfg["dsn"] = r"${dsn}"
  db["backend"] = r"${backend}"

- Env-var guidance for DSN

FILE: install.sh
RANGE: 450-463
EXCERPT:
  echo "Postgres configuration:"
  echo "  Use ${POSTGRES_DSN_ENV_VAR} to supply secrets at runtime (recommended)."
  read -r -p "Enter Postgres DSN (leave blank to enter fields or rely on env var): " dsn
  ...
  if [[ "$redacted" != "$dsn" ]]; then
      echo "⚠️  Passwords are not persisted to system.json; use ${POSTGRES_DSN_ENV_VAR}."
      dsn="$redacted"
  fi

FILE: install.sh
RANGE: 731-743
EXCERPT:
  db_backend="$(choose_db_backend)"
  ...
  db_postgres_dsn=""
  if [[ "$db_backend" == "postgres" ]]; then
    db_postgres_dsn="$(prompt_postgres_dsn)"
    if [[ "$db_postgres_dsn" == "" && -z "${!POSTGRES_DSN_ENV_VAR:-}" ]]; then
      echo "⚠️  Postgres selected but no DSN provided."
      echo "    Set ${POSTGRES_DSN_ENV_VAR} to inject the DSN at runtime."
    fi
  fi

- Postgres dependency install (MISSING)

MISSING: install.sh does not install Postgres dependencies or extras.
Current behavior: installs only dev+docs extras.

FILE: install.sh
RANGE: 706-710
EXCERPT:
  echo "📥 Installing PyPNM extras: dev + docs…"
  pip install -e "${PROJECT_ROOT}[dev,docs]"
  
  echo "📦 Installing required tooling: pytest, mkdocs, mkdocs-material, cryptography…"
  pip install "pytest>=7" "mkdocs>=1.6" "mkdocs-material>=9.5" "cryptography>=41"

B) Settings template / config writer (if install.sh delegates)
- install.sh writes settings directly (no separate template/script used for DB keys)

FILE: install.sh
RANGE: 512-540
EXCERPT:
  config_path = Path(r"${config_path}")
  data = json.loads(config_path.read_text())
  ...
  if "path" not in sqlite_cfg or sqlite_cfg["path"] is None:
      sqlite_cfg["path"] = ".data/db/pypnm.sqlite3"
  ...
  postgres_cfg["dsn"] = r"${dsn}"
  db["backend"] = r"${backend}"
  
  config_path.write_text(json.dumps(data, indent=4) + "\n")

## 2) Dependency Metadata Proof (required)
A) pyproject.toml optional dependencies

FILE: pyproject.toml
RANGE: 53-68
EXCERPT:
[project.optional-dependencies]
...
postgres = [
  "psycopg[binary]==3.2.3",
]

## 3) Test Gating + Execution Proof (required)
A) Postgres gating helper

FILE: tests/postgres_test_utils.py
RANGE: 14-23
EXCERPT:
def require_postgres() -> tuple[DatabaseDsn, ModuleType]:
    if os.environ.get("PYPNM_TEST_POSTGRES", "").strip() != "1":
        pytest.skip("PYPNM_TEST_POSTGRES not set")
    dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "").strip()
    if dsn == "":
        pytest.skip("PYPNM_DB_POSTGRES_DSN not set")
    try:
        import psycopg
    except ImportError:
        pytest.skip("psycopg not installed")
    return DatabaseDsn(dsn), psycopg

B) Example Postgres-gated tests (header/skip conditions)

FILE: tests/test_db_schema_manager.py
RANGE: 273-281
EXCERPT:
def test_postgres_schema_init_optional() -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = cast(DatabasePath, ".data/db/pypnm.sqlite3")
    manager = DatabaseSchemaManager.from_overrides(
        DatabaseBackend.POSTGRES, sqlite_path, postgres_dsn
    )
    manager.initialize_schema()
    health = manager.health_check()
    assert health.ok is True

FILE: tests/test_artifact_repository.py
RANGE: 134-139
EXCERPT:
def test_postgres_transaction_artifact_resolution_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    postgres_dsn, _ = require_postgres()
    sqlite_path = DatabasePath(str(tmp_path / "unused.sqlite3"))

## 4) CI Proof (preferred; provide if present)
A) GitHub Actions Postgres job

FILE: .github/workflows/daily-build.yml
RANGE: 39-96
EXCERPT:
  postgres-test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: pypnm
          POSTGRES_PASSWORD: ***
          POSTGRES_DB: pypnm
        ports:
          - 5432:5432
        options: >-
          --health-cmd="pg_isready -U pypnm -d pypnm"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=5

    env:
      PYPNM_DB_BACKEND: postgres
      PYPNM_DB_POSTGRES_DSN: postgresql://pypnm:***@localhost:5432/pypnm
      PGPASSWORD: ***

    steps:
      ...
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
          pip install "psycopg[binary]"
      ...
      - name: Run checks
        run: |
          pypnm-software-qa-checker

## 5) One Run Output Proof (required; choose one)
A) Local run output excerpt (shows Postgres tests skipped)

FILE: (command output) pytest -q | tail -n 20
RANGE: N/A
EXCERPT:
=========================== short test summary info ============================
SKIPPED [7] tests/postgres_test_utils.py:16: PYPNM_TEST_POSTGRES not set
SKIPPED [1] tests/test_database_manager.py:241: PYPNM_TEST_POSTGRES not set
================== 623 passed, 11 skipped in 64.22s (0:01:04) ==================

NOTE: This excerpt proves Postgres tests were NOT executed in this run.
If you need proof of execution, provide a CI log excerpt or a local run where
PYPNM_TEST_POSTGRES=1 and psycopg is installed.

---

# Proof Matrix
- Claim: Postgres selectable at install
  - Proof: install.sh RANGE 42-52, 136-152, 408-438
- Claim: Config keys written (Database.backend, Database.sqlite.path, Database.postgres.dsn)
  - Proof: install.sh RANGE 512-538
- Claim: Postgres deps installed via extras
  - Proof: MISSING (install.sh RANGE 706-710 shows only [dev,docs])
- Claim: Postgres tests enabled by env var
  - Proof: tests/postgres_test_utils.py RANGE 14-23
- Claim: Postgres-gated tests exist
  - Proof: tests/test_db_schema_manager.py RANGE 273-281; tests/test_artifact_repository.py RANGE 134-139
- Claim: CI runs Postgres tests
  - Proof: .github/workflows/daily-build.yml RANGE 39-96 (Postgres service + DSN env; note PYPNM_TEST_POSTGRES not set)
