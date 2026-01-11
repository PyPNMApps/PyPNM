### Summary
Aligned DB backend change set with policy and config hygiene: demo paths now use a single demo root, legacy plaintext passwords are logged as deprecated, JSON type aliases were consolidated, and documentation/install help were updated for consistency.

### Modified Files
- /home/dev01/Projects/PyPNM/install.sh
- /home/dev01/Projects/PyPNM/deploy/docker/config/system.json
- /home/dev01/Projects/PyPNM/demo/settings/system.json
- /home/dev01/Projects/PyPNM/src/pypnm/config/system_config_settings.py
- /home/dev01/Projects/PyPNM/src/pypnm/lib/types.py
- /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/analysis/report/multi_analysis_rpt.py
- /home/dev01/Projects/PyPNM/tests/test_system_config_settings.py
- /home/dev01/Projects/PyPNM/docs/system/system-config.md

### Commands Executed And Results
- `ruff check .` → failed (existing repo lint violations).
- `pytest` → passed (512 passed, 3 skipped).

### Tests
- `pytest` → pass (512 passed, 3 skipped).
- `ruff` → fail (existing repo violations).

### Notes / Warnings
- Ruff reports pre-existing import ordering and typing violations unrelated to this change set.

### Remaining TODOs / Follow-Ups
- None.

# FILE: /home/dev01/Projects/PyPNM/install.sh
#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# install.sh — Unified OS prerequisite installer and PyPNM bootstrapper
# Usage: ./install.sh [--demo-mode | --production] [--db-install-sqlite | --db-install-postgres] [--pnm-file-retrieval-setup] [venv_dir]
# ────────────────────────────────────────────────────────────────────────────────

VENV_DIR=".env"
DEMO_MODE="0"
PRODUCTION_MODE="0"
PNM_FILE_RETRIEVAL_SETUP="0"
DEVELOPMENT_MODE="0"
CLEAN_MODE="0"
PURGE_CACHE="0"
UNINSTALL_MODE="0"
DB_INSTALL_SQLITE="0"
DB_INSTALL_POSTGRES="0"
GITLEAKS_VERSION="8.18.1"
POSTGRES_DSN_ENV_VAR="PYPNM_DB_POSTGRES_DSN"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BANNER_PATH="${PROJECT_ROOT}/tools/banner.txt"

if [[ -f "${BANNER_PATH}" ]]; then
  cat "${BANNER_PATH}"
  echo
fi

usage() {
  cat <<EOF
PyPNM Installer And Bootstrap Script

Usage:
  ./install.sh [--demo-mode | --production] [--db-install-sqlite | --db-install-postgres] [--pnm-file-retrieval-setup] [venv_dir]
  ./install.sh --development
  ./install.sh --clean [--purge-cache]
  ./install.sh --uninstall [venv_dir]
  ./install.sh --help

Options:
  --development  Install Docker Engine + kind/kubectl + gitleaks for local dev and release workflows.
  --clean        Remove prior install artifacts (venv/build/dist/cache) before installing.
  --purge-cache  Clear pip cache after activating the venv (use with --clean when needed).
  --uninstall    Remove local install artifacts and the secrets key at ~/.ssh/pypnm_secrets.key.
  --db-install-sqlite
                 Select SQLite as the DB backend (default when no DB flag is provided).
  --db-install-postgres
                 Select Postgres as the DB backend and prompt for a DSN or connection fields.
                 If no DB flag is provided, the installer prompts in interactive mode
                 (defaulting to sqlite) and defaults to sqlite in non-interactive or CI runs.

  --demo-mode     Enable demo mode by backing up the default
                  src/pypnm/settings/system.json into backup/src/pypnm/settings/system.json
                  and replacing it with demo/settings/system.json. The demo system.json
                  should point all relevant directories to the demo/ tree.

  --production    Revert to production settings by restoring the backed-up
                  backup/src/pypnm/settings/system.json back to
                  src/pypnm/settings/system.json. This assumes a prior backup exists
                  (created by running with --demo-mode or a normal install).

  --pnm-file-retrieval-setup
                  After installation completes, attempt to run the interactive
                  PNM File Retrieval setup helper:

                      tools/pnm/pnm_file_retrieval_setup.py

                  This lets you choose how PyPNM retrieves PNM files:
                  local / tftp / ftp / scp / sftp / http / https.

                  For CI safety, this step is only executed when:
                    • stdin is a TTY (real terminal), and
                    • CI/GITHUB_ACTIONS are not set.
                  In CI environments, the option is acknowledged but skipped.

  venv_dir        Optional virtual environment directory name. Defaults to ".env".

  --help, -h      Show this help message and exit.

Examples:
  ./install.sh
      Create a venv in ".env" and install PyPNM with dev/docs extras.

  ./install.sh .pyenv
      Create a venv in ".pyenv" instead of ".env".

  ./install.sh --demo-mode
      Install and then switch system.json to the demo configuration
      (backing up the current system.json first).

  ./install.sh --development
      Install Docker Engine + kind/kubectl + gitleaks so release smoke tests can run.
      Tested on Ubuntu 22.04/24.04.

  ./install.sh --clean
      Remove previous install artifacts and rebuild the venv (preserves .data/ and
      src/pypnm/settings/system.json).

  ./install.sh --clean --purge-cache
      Remove previous install artifacts and clear pip cache before reinstalling.

  ./install.sh --uninstall
      Remove local install artifacts and the secrets key at ~/.ssh/pypnm_secrets.key.

  ./install.sh --demo-mode .env-demo
      Create a venv in ".env-demo" and enable demo-mode system.json.

  ./install.sh --production
      Install and then restore system.json from the backup tree, returning
      the configuration to production mode.

  ./install.sh --pnm-file-retrieval-setup
      Install and then invoke the PNM File Retrieval setup helper at the end,
      when running in an interactive, non-CI environment.

After installation, you can also configure how PyPNM retrieves PNM files
(local/TFTP/FTP/SCP/SFTP/HTTP/HTTPS) manually by running:

  ./tools/pnm/pnm_file_retrieval_setup.py
EOF
}

for arg in "$@"; do
  case "$arg" in
    --demo-mode)
      DEMO_MODE="1"
      ;;
    --production)
      PRODUCTION_MODE="1"
      ;;
    --pnm-file-retrieval-setup)
      PNM_FILE_RETRIEVAL_SETUP="1"
      ;;
    --development)
      DEVELOPMENT_MODE="1"
      ;;
    --clean)
      CLEAN_MODE="1"
      ;;
    --purge-cache)
      PURGE_CACHE="1"
      ;;
    --uninstall)
      UNINSTALL_MODE="1"
      ;;
    --db-install-sqlite)
      DB_INSTALL_SQLITE="1"
      ;;
    --db-install-postgres)
      DB_INSTALL_POSTGRES="1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      VENV_DIR="$arg"
      ;;
  esac
done

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  if [[ "$DEMO_MODE" == "1" || "$PRODUCTION_MODE" == "1" || "$PNM_FILE_RETRIEVAL_SETUP" == "1" || "$DEVELOPMENT_MODE" == "1" || "$CLEAN_MODE" == "1" || "$PURGE_CACHE" == "1" || "$DB_INSTALL_SQLITE" == "1" || "$DB_INSTALL_POSTGRES" == "1" ]]; then
    echo "❌ --uninstall cannot be combined with other flags."
    usage
    exit 1
  fi
fi

if [[ "$DEMO_MODE" == "1" && "$PRODUCTION_MODE" == "1" ]]; then
  echo "❌ Cannot use --demo-mode and --production together."
  usage
  exit 1
fi

if [[ "$DB_INSTALL_SQLITE" == "1" && "$DB_INSTALL_POSTGRES" == "1" ]]; then
  echo "❌ Cannot use --db-install-sqlite and --db-install-postgres together."
  usage
  exit 1
fi

clean_previous_install() {
  echo "🧹 Cleaning previous install artifacts..."

  local remove_paths=(
    "${PROJECT_ROOT}/${VENV_DIR}"
    "${PROJECT_ROOT}/build"
    "${PROJECT_ROOT}/dist"
    "${PROJECT_ROOT}/.pytest_cache"
    "${PROJECT_ROOT}/.ruff_cache"
    "${PROJECT_ROOT}/.mypy_cache"
    "${PROJECT_ROOT}/.pyright"
    "${PROJECT_ROOT}/.coverage"
    "${PROJECT_ROOT}/htmlcov"
    "${PROJECT_ROOT}/test_reports"
  )

  for path in "${remove_paths[@]}"; do
    if [[ -e "${path}" ]]; then
      echo "🗑️  Removing ${path}"
      rm -rf "${path}"
    fi
  done

  find "${PROJECT_ROOT}" -maxdepth 2 -name "*.egg-info" -type d -print0 | while IFS= read -r -d '' item; do
    echo "🗑️  Removing ${item}"
    rm -rf "${item}"
  done

  echo "ℹ️  Preserving ${PROJECT_ROOT}/.data and ${PROJECT_ROOT}/src/pypnm/settings/system.json"
}

install_gitleaks() {
  if command -v gitleaks >/dev/null 2>&1; then
    echo "✅ gitleaks already installed."
    return
  fi

  if [[ "$PM" == "none" ]]; then
    echo "⚠️  gitleaks not found and no package manager available."
    echo "    Install manually: https://github.com/gitleaks/gitleaks"
    return
  fi

  echo "🔧 Installing gitleaks..."
  case "$PM" in
    apt-get) $PM_INSTALL gitleaks || true ;;
    dnf|yum) $PM_INSTALL gitleaks || true ;;
    zypper)  $PM_INSTALL gitleaks || true ;;
    apk)     $PM_INSTALL gitleaks || true ;;
    brew)    $PM_INSTALL gitleaks || true ;;
    *)
      echo "⚠️  Unknown package manager; install gitleaks manually."
      echo "    https://github.com/gitleaks/gitleaks"
      return
      ;;
  esac

  if ! command -v gitleaks >/dev/null 2>&1; then
    if ! command -v curl >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete (curl missing)."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi
    if ! command -v tar >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete (tar missing)."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi

    local os arch filename url tmp_dir target_dir bin_path
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
      linux|darwin) ;;
      *)
        echo "⚠️  Unsupported OS for gitleaks auto-install: ${os}"
        echo "    Install manually: https://github.com/gitleaks/gitleaks"
        return
        ;;
    esac

    arch="$(uname -m)"
    case "$arch" in
      x86_64|amd64) arch="x64" ;;
      aarch64|arm64) arch="arm64" ;;
      *)
        echo "⚠️  Unsupported architecture for gitleaks auto-install: ${arch}"
        echo "    Install manually: https://github.com/gitleaks/gitleaks"
        return
        ;;
    esac

    filename="gitleaks_${GITLEAKS_VERSION}_${os}_${arch}.tar.gz"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${filename}"
    tmp_dir="$(mktemp -d)"
    echo "⬇️  Downloading gitleaks ${GITLEAKS_VERSION}..."
    if ! curl -fsSL "${url}" -o "${tmp_dir}/${filename}"; then
      echo "⚠️  Failed to download gitleaks from ${url}"
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    if ! tar -xzf "${tmp_dir}/${filename}" -C "${tmp_dir}"; then
      echo "⚠️  Failed to extract gitleaks archive."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    bin_path="${tmp_dir}/gitleaks"
    if [[ ! -f "${bin_path}" ]]; then
      echo "⚠️  gitleaks binary not found after extraction."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      rm -rf "${tmp_dir}"
      return
    fi

    target_dir="/usr/local/bin"
    if [[ -w "${target_dir}" ]]; then
      install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
    elif command -v sudo >/dev/null 2>&1; then
      sudo install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
    else
      target_dir="${HOME}/.local/bin"
      mkdir -p "${target_dir}"
      install -m 0755 "${bin_path}" "${target_dir}/gitleaks"
      echo "ℹ️  Added gitleaks to ${target_dir}; ensure it's on PATH."
    fi

    rm -rf "${tmp_dir}"
    if ! command -v gitleaks >/dev/null 2>&1; then
      echo "⚠️  gitleaks install did not complete."
      echo "    Install manually: https://github.com/gitleaks/gitleaks"
      return
    fi
  fi
}

remove_secrets_key() {
  local secrets_key_path
  secrets_key_path="${HOME}/.ssh/pypnm_secrets.key"

  if [[ -f "${secrets_key_path}" ]]; then
    echo "🗑️  Removing ${secrets_key_path}"
    rm -f "${secrets_key_path}"
  else
    echo "ℹ️  Secret key not found at ${secrets_key_path}"
  fi
}

uninstall_pypnm() {
  echo "🧹 Uninstalling PyPNM artifacts..."
  clean_previous_install
  remove_secrets_key
  echo "✅ Uninstall complete."
}

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  uninstall_pypnm
  exit 0
fi

backup_system_settings() {
  echo "🗂  Creating backup of system settings…"
  local backup_root
  backup_root="${PROJECT_ROOT}/backup"
  local src_path
  src_path="${PROJECT_ROOT}/src/pypnm/settings/system.json"
  local dst_path
  dst_path="${backup_root}/src/pypnm/settings/system.json"

  if [[ ! -f "$src_path" ]]; then
    echo "⚠️  System settings file not found at '$src_path'; skipping backup."
    return
  fi

  mkdir -p "$(dirname "$dst_path")"
  cp "$src_path" "$dst_path"
  echo "✅ Backup created at '$dst_path'."
}

restore_system_settings() {
  echo "🗂  Restoring system settings from backup…"
  local backup_root
  backup_root="${PROJECT_ROOT}/backup"
  local backup_path
  backup_path="${backup_root}/src/pypnm/settings/system.json"
  local target
  target="${PROJECT_ROOT}/src/pypnm/settings/system.json"

  if [[ ! -f "$backup_path" ]]; then
    echo "⚠️  Backup system settings not found at '$backup_path'; cannot restore."
    return
  fi

  mkdir -p "$(dirname "$target")"
  cp "$backup_path" "$target"
  echo "✅ System settings restored from backup to '$target'."
}

enable_demo_mode() {
  echo "🎛  Enabling demo mode configuration…"
  local demo_src
  demo_src="${PROJECT_ROOT}/demo/settings/system.json"
  local target
  target="${PROJECT_ROOT}/src/pypnm/settings/system.json"

  if [[ ! -f "$demo_src" ]]; then
    echo "⚠️  Demo settings file not found at '$demo_src'; skipping demo mode."
    return
  fi

  if [[ -f "$target" ]]; then
    echo "ℹ️  Overwriting existing system settings at '$target' with demo template."
  else
    echo "ℹ️  Creating system settings at '$target' from demo template."
  fi

  mkdir -p "$(dirname "$target")"
  cp "$demo_src" "$target"
  echo "✅ Demo mode system settings applied (directories now point to demo/)."
}

choose_db_backend() {
  local selection

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

  echo
  echo "Database backend selection:"
  echo "  - SQLite is recommended for standalone/single-writer deployments."
  echo "  - Postgres is recommended for multi-worker/multi-process deployments."
  read -r -p "Choose database backend [sqlite]: " selection

  selection="$(echo "$selection" | tr '[:upper:]' '[:lower:]' | xargs)"
  if [[ "$selection" == "" ]]; then
    selection="sqlite"
  fi
  if [[ "$selection" != "sqlite" && "$selection" != "postgres" ]]; then
    echo "⚠️  Invalid selection '${selection}'; defaulting to sqlite."
    selection="sqlite"
  fi

  echo "$selection"
}

prompt_postgres_dsn() {
  local dsn confirm
  local host port dbname user password sslmode

  if [[ ! -t 0 || -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo ""
    return
  fi

  echo
  echo "Postgres configuration:"
  echo "  Use ${POSTGRES_DSN_ENV_VAR} to supply secrets at runtime (recommended)."
  read -r -p "Enter Postgres DSN (leave blank to enter fields or rely on env var): " dsn

  dsn="$(echo "$dsn" | xargs)"
  if [[ "$dsn" != "" ]]; then
    echo "$dsn"
    return
  fi

  read -r -p "Enter Postgres connection fields now? [y/N]: " confirm
  confirm="$(echo "$confirm" | tr '[:upper:]' '[:lower:]' | xargs)"
  if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo ""
    return
  fi

  read -r -p "Host [localhost]: " host
  read -r -p "Port [5432]: " port
  read -r -p "Database [pypnm]: " dbname
  read -r -p "User [pypnm]: " user
  read -r -p "Password (leave blank to avoid storing): " password
  read -r -p "SSL mode (disable/allow/prefer/require) [disable]: " sslmode

  host="${host:-localhost}"
  port="${port:-5432}"
  dbname="${dbname:-pypnm}"
  user="${user:-pypnm}"
  sslmode="${sslmode:-disable}"

  if [[ "$password" == "" ]]; then
    dsn="postgresql://${user}@${host}:${port}/${dbname}"
  else
    dsn="postgresql://${user}:${password}@${host}:${port}/${dbname}"
  fi
  if [[ "$sslmode" != "" ]]; then
    dsn="${dsn}?sslmode=${sslmode}"
  fi

  echo "$dsn"
}

update_database_settings() {
  local backend
  local dsn
  local config_path

  backend="$1"
  dsn="$2"
  config_path="${PROJECT_ROOT}/src/pypnm/settings/system.json"

  if [[ ! -f "$config_path" ]]; then
    echo "⚠️  system.json not found at '${config_path}'; skipping DB configuration."
    return
  fi

  "$PYTHON_CMD" - <<PY
import json
from pathlib import Path

config_path = Path(r"${config_path}")
data = json.loads(config_path.read_text())

db = data.get("Database")
if not isinstance(db, dict):
    db = {}
    data["Database"] = db

sqlite_cfg = db.get("sqlite")
if not isinstance(sqlite_cfg, dict):
    sqlite_cfg = {}
    db["sqlite"] = sqlite_cfg

if "path" not in sqlite_cfg or sqlite_cfg["path"] is None:
    sqlite_cfg["path"] = ".data/db/pypnm.sqlite3"

postgres_cfg = db.get("postgres")
if not isinstance(postgres_cfg, dict):
    postgres_cfg = {}
    db["postgres"] = postgres_cfg

postgres_cfg["dsn"] = r"${dsn}"
db["backend"] = r"${backend}"

config_path.write_text(json.dumps(data, indent=4) + "\\n")
PY
}

echo "🔍 Detecting package manager..."
PM="none"; PM_UPDATE=""; PM_INSTALL=""
if command -v apt-get >/dev/null 2>&1; then
  PM="apt-get"; PM_UPDATE="sudo apt-get update"; PM_INSTALL="sudo apt-get install -y"
  echo "ℹ️  Debian/Ubuntu (apt-get)"
elif command -v dnf >/dev/null 2>&1; then
  PM="dnf"; PM_UPDATE="sudo dnf makecache"; PM_INSTALL="sudo dnf install -y"
  echo "ℹ️  Fedora/RHEL (dnf)"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"; PM_UPDATE="sudo yum makecache"; PM_INSTALL="sudo yum install -y"
  echo "ℹ️  RHEL/CentOS (yum)"
elif command -v zypper >/dev/null 2>&1; then
  PM="zypper"; PM_UPDATE="sudo zypper refresh"; PM_INSTALL="sudo zypper install -y"
  echo "ℹ️  SUSE/openSUSE (zypper)"
elif command -v apk >/dev/null 2>&1; then
  PM="apk"; PM_UPDATE=""; PM_INSTALL="sudo apk add --no-cache"
  echo "ℹ️  Alpine (apk)"
elif command -v brew >/dev/null 2>&1; then
  PM="brew"; PM_UPDATE="brew update"; PM_INSTALL="brew install"
  echo "ℹ️  macOS (brew)"
else
  echo "⚠️  Unsupported OS: please manually install 'ssh', 'sshpass', and Python venv support."
fi

if [[ "$PM" != "none" && -n "${PM_UPDATE:-}" ]]; then
  echo "🔄 Updating package cache..."
  $PM_UPDATE || true
fi

echo "✅ Installing OS prerequisites..."
if ! command -v ssh >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'ssh'."
  else
    echo "🔧 Installing ssh..."
    case "$PM" in
      apt-get) $PM_INSTALL openssh-client ;;
      dnf|yum) $PM_INSTALL openssh-clients ;;
      zypper)  $PM_INSTALL openssh ;;
      apk)     $PM_INSTALL openssh ;;
      brew)    $PM_INSTALL openssh ;;
    esac
  fi
fi

if ! command -v sshpass >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'sshpass'."
  else
    echo "🔧 Installing sshpass..."
    $PM_INSTALL sshpass || true
  fi
fi

echo "🧮 Ensuring SciPy/NumPy build prerequisites (where applicable)..."
case "$PM" in
  apt-get)
    $PM_INSTALL build-essential gfortran libopenblas-dev liblapack-dev || true
    ;;
  dnf|yum)
    $PM_INSTALL gcc gcc-c++ make blas-devel lapack-devel || true
    ;;
  zypper)
    $PM_INSTALL gcc gcc-c++ make libopenblas-devel lapack-devel || true
    ;;
  apk)
    $PM_INSTALL build-base gfortran openblas-dev lapack-dev || true
    ;;
  brew)
    # Homebrew wheels usually bundle BLAS/LAPACK; nothing extra required in most cases.
    :
    ;;
  *)
    echo "⚠️  Skipping SciPy/NumPy build prerequisites for unknown or manual PM."
    ;;
esac

if [[ "$DEVELOPMENT_MODE" == "1" ]]; then
  echo "🧰 Development setup: Docker + kind/kubectl + gitleaks..."
  if ! command -v curl >/dev/null 2>&1; then
    if [[ "$PM" == "none" ]]; then
      echo "❌ curl not found and no package manager available."
      exit 1
    fi
    echo "🔧 Installing curl..."
    case "$PM" in
      apt-get) $PM_INSTALL curl ;;
      dnf|yum) $PM_INSTALL curl ;;
      zypper)  $PM_INSTALL curl ;;
      apk)     $PM_INSTALL curl ;;
      brew)    $PM_INSTALL curl ;;
    esac
  fi

  if [[ "$PM" == "apt-get" ]]; then
    bash "${PROJECT_ROOT}/tools/docker/install-docker-ubuntu.sh"
  else
    echo "⚠️  --development is tested on Ubuntu 22.04/24.04; continuing with kind/kubectl install."
    echo "    Install Docker manually for your OS, then re-run if needed."
  fi

  bash "${PROJECT_ROOT}/tools/k8s/pypnm_kind_vm_bootstrap.sh"
  install_gitleaks
  echo "ℹ️  Docker may require: sudo systemctl start docker"
  echo "ℹ️  For non-sudo Docker: sudo usermod -aG docker \"${USER}\" (then log out/in)"
fi

if ! command -v python3 >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "❌ Python 3.x not found in PATH."
    exit 1
  fi
  echo "🔧 Installing Python 3..."
  case "$PM" in
    apt-get) $PM_INSTALL python3 ;;
    dnf|yum) $PM_INSTALL python3 ;;
    zypper)  $PM_INSTALL python3 ;;
    apk)     $PM_INSTALL python3 ;;
    brew)    $PM_INSTALL python ;;
  esac
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3")"
PYTHON_CMD="python${PYTHON_VERSION}"
if ! command -v "$PYTHON_CMD" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
  else
    echo "❌ Python 3.x not found in PATH."
    exit 1
  fi
fi

echo "🔧 Ensuring venv support is available..."
case "$PM" in
  apt-get) $PM_INSTALL "python${PYTHON_VERSION}-venv" || true ;;
  dnf|yum) $PM_INSTALL python3-virtualenv || true ;;
  zypper)  $PM_INSTALL python3-virtualenv || true ;;
  apk)     $PM_INSTALL python3 || true ;;
  brew)    $PM_INSTALL python || true ;;
  *)       echo "⚠️  Skipping venv package install for unknown PM." ;;
esac

if [[ "$CLEAN_MODE" == "1" ]]; then
  clean_previous_install
fi

echo "🛠  Creating virtual environment in '$VENV_DIR'…"
"$PYTHON_CMD" -m venv "$VENV_DIR"

echo "🚀 Activating '$VENV_DIR'…"
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

echo "⬆️  Upgrading pip, setuptools, wheel…"
pip install --upgrade pip setuptools wheel

if [[ "$PURGE_CACHE" == "1" ]]; then
  echo "🧽 Purging pip cache..."
  pip cache purge || true
fi

echo "📥 Installing PyPNM extras: dev + docs…"
pip install -e "${PROJECT_ROOT}[dev,docs]"

echo "📦 Installing required tooling: pytest, mkdocs, mkdocs-material, cryptography…"
pip install "pytest>=7" "mkdocs>=1.6" "mkdocs-material>=9.5" "cryptography>=41"

echo "🔎 Verifying MkDocs install…"
mkdocs --version

echo "🔧 Configuring PYTHONPATH…"
"$PROJECT_ROOT/scripts/install_py_path.sh" "$PROJECT_ROOT" || true

echo "🔐 Ensuring PyPNM secret key exists (~/.ssh/pypnm_secrets.key)…"
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "ℹ️  Skipping secret key creation (CI environment)."
  echo "    Create it locally with:"
  echo "      ./scripts/init_secrets_key.sh"
else
  if [[ -x "${PROJECT_ROOT}/scripts/init_secrets_key.sh" ]]; then
    "${PROJECT_ROOT}/scripts/init_secrets_key.sh" --quiet || true
  else
    echo "ℹ️  scripts/init_secrets_key.sh is missing or not executable; skipping."
  fi
fi

echo "🧪 Running unit tests…"
cd "$PROJECT_ROOT"
pytest -v

if [[ "$PRODUCTION_MODE" == "1" ]]; then
  restore_system_settings
elif [[ "$DEMO_MODE" == "1" ]]; then
  backup_system_settings
  enable_demo_mode
else
  backup_system_settings
fi

db_backend="$(choose_db_backend)"
db_postgres_dsn=""
if [[ "$db_backend" == "postgres" ]]; then
  db_postgres_dsn="$(prompt_postgres_dsn)"
  if [[ "$db_postgres_dsn" == "" && -z "${PYPNM_DB_POSTGRES_DSN:-}" ]]; then
    echo "⚠️  Postgres selected but no DSN provided."
    echo "    Set ${POSTGRES_DSN_ENV_VAR} to inject the DSN at runtime."
  fi
fi

update_database_settings "$db_backend" "$db_postgres_dsn"

###############################################################################
# Optional: PNM File Retrieval Setup (CI-Safe)
#
# Behavior:
#   - If --pnm-file-retrieval-setup was passed:
#       • Attempt to run tools/pnm/pnm_file_retrieval_setup.py automatically
#         when in an interactive, non-CI environment.
#       • If in CI or non-TTY, print a message and skip.
#
#   - If the flag was NOT passed:
#       • Do NOT prompt interactively.
#       • Just print a short message about the manual helper.
###############################################################################
run_pnm_setup_if_possible() {
  if [[ ! -t 0 || -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "ℹ️  Skipping PNM file retrieval setup (non-interactive or CI environment)."
    echo "    You can run it later with:"
    echo "      ./tools/pnm/pnm_file_retrieval_setup.py"
    return
  fi

  if [[ -x "./tools/pnm/pnm_file_retrieval_setup.py" ]]; then
    echo
    echo "Launching PNM file retrieval setup..."
    ./tools/pnm/pnm_file_retrieval_setup.py
  else
    echo "tools/pnm/pnm_file_retrieval_setup.py is missing or not executable."
    echo "You can run it manually later once it is available:"
    echo "  ./tools/pnm/pnm_file_retrieval_setup.py"
  fi
}

run_pnm_alias_installer_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/install_aliases.sh" ]]; then
    echo "🔗 Installing PyPNM shell aliases (e.g., config-menu)…"
    "${PROJECT_ROOT}/scripts/install_aliases.sh" || true
  fi
}

if [[ "$PNM_FILE_RETRIEVAL_SETUP" == "1" ]]; then
  echo
  echo "PNM File Retrieval Configuration (requested via --pnm-file-retrieval-setup)"
  run_pnm_setup_if_possible
else
  echo
  echo "ℹ️  PNM file retrieval setup was not requested."
  echo "    You can configure it later with:"
  echo "      ./tools/pnm/pnm_file_retrieval_setup.py"
fi

run_pnm_alias_installer_if_available

echo "✅ Bootstrap complete."
if [[ "$DEMO_MODE" == "1" ]]; then
  echo "👉 Demo mode is enabled: system settings now reference the demo/ directories."
fi
if [[ "$PRODUCTION_MODE" == "1" ]]; then
  echo "👉 Production mode is restored: system settings have been reverted from backup."
fi
echo "👉 Next steps:"
echo "   1) source '$VENV_DIR/bin/activate'"
echo "   2) (optional) ./tools/pnm/pnm_file_retrieval_setup.py"
echo "   3) mkdocs serve"

# FILE: /home/dev01/Projects/PyPNM/deploy/docker/config/system.json
{
    "CmtsOrchestrator": {
        "adapter": {
            "community": "cmtspublic",
            "hostname": "172.19.122.228",
            "write_community": "cmtspublic"
        }
    },
    "FastApiRequestDefault": {
        "ip_address": "192.168.0.1",
        "mac_address": "aa:bb:cc:dd:ee:ff"
    },
    "PnmBulkDataTransfer": {
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        },
        "method": "tftp",
        "tftp": {
            "ip_v4": "172.19.8.28",
            "ip_v6": "::1",
            "remote_dir": ""
        }
    },
    "PnmFileRetrieval": {
        "archive_dir": ".data/archive",
        "capture_group_db": ".data/db/capture_group.json",
        "csv_dir": ".data/csv",
        "json_dir": ".data/json",
        "json_transaction_db": ".data/db/json_transactions.json",
        "msg_rsp_dir": ".data/msg_rsp",
        "operation_db": ".data/db/operation_capture.json",
        "png_dir": ".data/png",
        "pnm_dir": ".data/pnm",
        "retries": 5,
        "retrieval_method": {
            "method": "sftp",
            "methods": {
                "ftp": {
                    "host": "localhost",
                    "password_enc": "",
                    "port": 21,
                    "remote_dir": "/srv/tftp",
                    "timeout": 5,
                    "tls": false,
                    "user": "user"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "password_enc": "",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "password_enc": "",
                    "port": 443
                },
                "local": {
                    "password_enc": "",
                    "src_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "172.19.8.28",
                    "password_enc": "",
                    "port": 22,
                    "private_key_path": "~/.ssh/id_rsa_pypnm",
                    "remote_dir": "/srv/tftp",
                    "user": "dev01"
                },
                "tftp": {
                    "host": "localhost",
                    "password_enc": "",
                    "port": 69,
                    "remote_dir": "",
                    "timeout": 5
                }
            }
        },
        "session_group_db": ".data/db/session_group.json",
        "transaction_db": ".data/db/transactions.json",
        "xlsx_dir": ".data/xlsx"
    },
    "Database": {
        "backend": "sqlite",
        "sqlite": {
            "path": ".data/db/pypnm.sqlite3"
        },
        "postgres": {
            "dsn": ""
        }
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "read_community": "public",
                "retries": 3,
                "write_community": "public"
            },
            "3": {
                "authPassword": "",
                "authProtocol": "SHA",
                "enable": false,
                "privPassword": "",
                "privProtocol": "AES",
                "retries": 3,
                "securityLevel": "authPriv",
                "username": "user"
            }
        }
    },
    "TestMode": {
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        },
        "global": {
            "mode": {
                "enable": true
            }
        }
    },
    "logging": {
        "log_dir": "logs",
        "log_filename": "pypnm.log",
        "log_level": "INFO"
    },
    "pypnm-cmts": {
        "cmts": [
            {
                "SNMP": {
                    "timeouts": {
                        "request_seconds": 5,
                        "retries": 1
                    },
                    "version": {
                        "2c": {
                            "enable": true,
                            "port": 161,
                            "read_community": "cmtspublic",
                            "retries": 3,
                            "write_community": "cmtspublic"
                        },
                        "3": {
                            "authPassword": "",
                            "authProtocol": "SHA",
                            "enable": false,
                            "port": 161,
                            "privPassword": "",
                            "privProtocol": "AES",
                            "retries": 3,
                            "securityLevel": "authPriv",
                            "username": "user"
                        }
                    }
                },
                "device": {
                    "hostname": "172.19.122.228",
                    "model": "",
                    "vendor": ""
                }
            }
        ]
    }
}

# FILE: /home/dev01/Projects/PyPNM/demo/settings/system.json
{
    "FastApiRequestDefault": {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.168.0.1"
    },
    "SNMP": {
        "timeout": 2,
        "version": {
            "2c": {
                "enable": true,
                "retries": 3,
                "read_community": "public",
                "write_community": "private"
            },
            "3": {
                "enable": false,
                "retries": 3,
                "username": "user",
                "securityLevel": "authPriv",
                "authProtocol": "SHA",
                "authPassword": "pass",
                "privProtocol": "AES",
                "privPassword": "privpass"
            }
        }
    },
    "PnmBulkDataTransfer": {
        "method": "tftp",
        "tftp": {
            "ip_v4": "192.168.0.10",
            "ip_v6": "::1",
            "remote_dir": ""
        },
        "http": {
            "base_url": "http://files.example.com/",
            "port": 80
        },
        "https": {
            "base_url": "https://files.example.com/",
            "port": 443
        }
    },
    "PnmFileRetrieval": {
        "pnm_dir": "demo/.data/pnm",
        "csv_dir": "demo/.data/csv",
        "json_dir": "demo/.data/json",
        "xlsx_dir": "demo/.data/xlsx",
        "png_dir": "demo/.data/png",
        "archive_dir": "demo/.data/archive",
        "msg_rsp_dir": "demo/.data/msg_rsp",
        "transaction_db": "demo/.data/db/transactions.json",
        "capture_group_db": "demo/.data/db/capture_group.json",
        "session_group_db": "demo/.data/db/session_group.json",
        "operation_db": "demo/.data/db/operation_capture.json",
        "json_transaction_db": "demo/.data/db/json_transactions.json",
        "retries": 5,
        "retrieval_method": {
            "method": "local",
            "methods": {
                "local": {
                    "src_dir": "/srv/tftp"
                },
                "tftp": {
                    "host": "localhost",
                    "port": 69,
                    "timeout": 5,
                    "remote_dir": ""
                },
                "ftp": {
                    "host": "localhost",
                    "port": 21,
                    "tls": false,
                    "timeout": 5,
                    "user": "test",
                    "password_enc": "",
                    "remote_dir": "/srv/tftp"
                },
                "sftp": {
                    "host": "localhost",
                    "port": 22,
                    "user": "test",
                    "password_enc": "",
                    "remote_dir": "/srv/tftp"
                },
                "http": {
                    "base_url": "http://STUB/",
                    "port": 80
                },
                "https": {
                    "base_url": "https://STUB/",
                    "port": 443
                }
            }
        }
    },
    "Database": {
        "backend": "sqlite",
        "sqlite": {
            "path": "demo/.data/db/pypnm.sqlite3"
        },
        "postgres": {
            "dsn": ""
        }
    },
    "logging": {
        "log_level": "INFO",
        "log_dir": "logs",
        "log_filename": "pypnm.log"
    },
    "TestMode": {
        "global": {
            "mode": {
                "enable": true
            }
        },
        "class_name": {
            "DsScQamChannelSpectrumAnalyzer": {
                "mode": {
                    "enable": true
                }
            }
        }
    }
}

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/config/system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from pypnm.config.database_settings import (
    DatabaseSettings,
    DEFAULT_POSTGRES_DSN,
    DEFAULT_SQLITE_DB_PATH,
    POSTGRES_DSN_ENV_VAR,
)
from pypnm.config.config_manager import ConfigManager
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.secret.crypto_manager import SecretCryptoError, SecretCryptoManager
from pypnm.lib.types import (
    DatabaseBackend,
    DatabaseDsn,
    DatabasePath,
    FileNameStr,
    InetAddressStr,
    IPv4Str,
    IPv6Str,
    MacAddressStr,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)


class SystemConfigSettings:
    """Provides dynamically reloaded system configuration via class properties."""
    _cfg        = ConfigManager()
    _logger     = logging.getLogger("SystemConfigSettings")

    _DEFAULT_IP_ADDRESS: InetAddressStr      = cast(InetAddressStr, "192.168.0.100")
    _DEFAULT_SNMP_RETRIES: int              = 5
    _DEFAULT_SNMP_TIMEOUT: int              = 2
    _DEFAULT_FILE_RETRIEVAL_RETRIES: int    = 5
    _DEFAULT_HTTP_PORT: int                 = 80
    _DEFAULT_HTTPS_PORT: int                = 443
    _DEFAULT_TFTP_PORT: int                 = 69
    _DEFAULT_FTP_PORT: int                  = 21
    _DEFAULT_SFTP_PORT: int                 = 22
    _DEFAULT_SCP_PORT: int                  = 22
    _DEFAULT_LOG_LEVEL: str                 = "INFO"
    _DEFAULT_LOG_DIR: str                   = "logs"
    _DEFAULT_LOG_FILENAME: str              = "pypnm.log"
    _DEFAULT_SNMP_READ_COMMUNITY: str       = "public"
    _DEFAULT_SNMP_WRITE_COMMUNITY: str      = ""
    _DEFAULT_PNM_DIR: str                   = ".data/pnm"
    _DEFAULT_CSV_DIR: str                   = ".data/csv"
    _DEFAULT_JSON_DIR: str                  = ".data/json"
    _DEFAULT_XLSX_DIR: str                  = ".data/xlsx"
    _DEFAULT_PNG_DIR: str                   = ".data/png"
    _DEFAULT_ARCHIVE_DIR: str               = ".data/archive"
    _DEFAULT_MSG_RSP_DIR: str               = ".data/msg_rsp"
    _DEFAULT_DB_BACKEND: DatabaseBackend    = DatabaseBackend.SQLITE
    _DEFAULT_SQLITE_DB_PATH: DatabasePath   = DEFAULT_SQLITE_DB_PATH
    _DEFAULT_POSTGRES_DSN: DatabaseDsn      = DEFAULT_POSTGRES_DSN
    _POSTGRES_DSN_ENV_VAR: str              = POSTGRES_DSN_ENV_VAR

    _ENCRYPTED_TOKEN_PREFIX: str            = "ENC["

    _PRIMARY_RETRIEVAL_METHOD_KEY: str      = "retrieval_method"
    _LEGACY_RETRIEVAL_METHOD_KEY: str       = "retrival_method"

    @classmethod
    def _config_path(cls, *path: str) -> str:
        """Return dotted path for logging."""
        return ".".join(path)

    @classmethod
    def _postgres_dsn_env_override(cls) -> str:
        value = os.getenv(cls._POSTGRES_DSN_ENV_VAR, "")
        return value.strip()

    @classmethod
    def _peek_str(cls, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @classmethod
    def _peek_str_fallback(cls, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            return str(value)
        return cls._peek_str(*legacy)

    @classmethod
    def _maybe_decrypt(cls, value: str, *path: str) -> str:
        text = value.strip()
        if text == "":
            return ""
        if not text.startswith(cls._ENCRYPTED_TOKEN_PREFIX):
            return text
        try:
            return SecretCryptoManager.decrypt_password(text)
        except SecretCryptoError as exc:
            cls._logger.error(
                "Failed to decrypt configuration value for '%s': %s",
                cls._config_path(*path),
                exc,
            )
            return ""

    @classmethod
    def _get_password_value(cls, require: bool, *method_path: str) -> str:
        password_enc = cls._peek_str(*method_path, "password_enc")
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *method_path, "password_enc")
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str(*method_path, "password")
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*method_path, "password"),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*method_path, "password"),
        )
        return cls._maybe_decrypt(password, *method_path, "password")

    @classmethod
    def _get_password_value_fallback(cls, require: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        password_enc = cls._peek_str_fallback(primary + ("password_enc",), legacy + ("password_enc",))
        if password_enc.strip() != "":
            decrypted = cls._maybe_decrypt(password_enc, *(primary + ("password_enc",)))
            if decrypted != "":
                return decrypted
            if require:
                return ""

        password = cls._peek_str_fallback(primary + ("password",), legacy + ("password",))
        if password.strip() == "":
            if require:
                cls._logger.error(
                    "Missing configuration value for '%s'; expected password or password_enc",
                    cls._config_path(*(primary + ("password",))),
                )
            return ""

        cls._logger.warning(
            "Using legacy plaintext password for '%s'; prefer password_enc",
            cls._config_path(*(primary + ("password",))),
        )
        return cls._maybe_decrypt(password, *(primary + ("password",)))

    @classmethod
    def _get_str(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        if value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*path),
                default,
            )
            return default
        return value

    @classmethod
    def _get_str_fallback(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str) and value != "":
                return value
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path(*primary),
                    value,
                    coerced,
                )
                return coerced
            if value == "":
                legacy_value = cls._cfg.get(*legacy)
                if legacy_value is not None:
                    if not isinstance(legacy_value, str):
                        coerced = str(legacy_value)
                        cls._logger.error(
                            "Non-string configuration value for '%s': %r; using coerced '%s'",
                            cls._config_path(*primary),
                            legacy_value,
                            coerced,
                        )
                        return coerced
                    if legacy_value != "":
                        return legacy_value
                cls._logger.error(
                    "Empty configuration value for '%s'; using default '%s'",
                    cls._config_path(*primary),
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        if legacy_value == "":
            cls._logger.error(
                "Empty configuration value for '%s'; using default '%s'",
                cls._config_path(*primary),
                default,
            )
            return default
        return legacy_value

    @classmethod
    def _get_str_allow_empty(cls, default: str, *path: str) -> str:
        value = cls._cfg.get(*path)
        if value is None:
            return default
        if not isinstance(value, str):
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*path),
                value,
                coerced,
            )
            return coerced
        return value

    @classmethod
    def _get_str_fallback_allow_empty(cls, default: str, primary: tuple[str, ...], legacy: tuple[str, ...]) -> str:
        value = cls._cfg.get(*primary)
        if value is not None:
            if isinstance(value, str):
                return value
            coerced = str(value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                value,
                coerced,
            )
            return coerced

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            return default
        if not isinstance(legacy_value, str):
            coerced = str(legacy_value)
            cls._logger.error(
                "Non-string configuration value for '%s': %r; using coerced '%s'",
                cls._config_path(*primary),
                legacy_value,
                coerced,
            )
            return coerced
        return legacy_value

    @classmethod
    def _get_int(cls, default: int, *path: str) -> int:
        value = cls._cfg.get(*path)
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*path),
                default,
            )
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*path),
                value,
                default,
            )
            return default

    @classmethod
    def _get_int_fallback(cls, default: int, primary: tuple[str, ...], legacy: tuple[str, ...]) -> int:
        value = cls._cfg.get(*primary)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                cls._logger.error(
                    "Invalid integer configuration value for '%s': %r; using default %d",
                    cls._config_path(*primary),
                    value,
                    default,
                )
                return default

        legacy_value = cls._cfg.get(*legacy)
        if legacy_value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %d",
                cls._config_path(*primary),
                default,
            )
            return default
        try:
            return int(legacy_value)
        except (TypeError, ValueError):
            cls._logger.error(
                "Invalid integer configuration value for '%s': %r; using default %d",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

    @classmethod
    def _get_bool(cls, default: bool, *path: str) -> bool:
        value = cls._cfg.get(*path)
        if isinstance(value, bool):
            return value
        if value is None:
            cls._logger.error(
                "Missing configuration value for '%s'; using default %s",
                cls._config_path(*path),
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*path),
            value,
            default,
        )
        return default

    @classmethod
    def _get_bool_fallback(cls, default: bool, primary: tuple[str, ...], legacy: tuple[str, ...]) -> bool:
        value = cls._cfg.get(*primary)
        if isinstance(value, bool):
            return value
        if value is None:
            legacy_value = cls._cfg.get(*legacy)
            if isinstance(legacy_value, bool):
                return legacy_value
            if legacy_value is None:
                cls._logger.error(
                    "Missing configuration value for '%s'; using default %s",
                    cls._config_path(*primary),
                    default,
                )
                return default
            text = str(legacy_value).strip().lower()
            if text in ("1", "true", "yes", "on"):
                return True
            if text in ("0", "false", "no", "off"):
                return False
            cls._logger.error(
                "Invalid boolean configuration value for '%s': %r; using default %s",
                cls._config_path(*primary),
                legacy_value,
                default,
            )
            return default

        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False

        cls._logger.error(
            "Invalid boolean configuration value for '%s': %r; using default %s",
            cls._config_path(*primary),
            value,
            default,
        )
        return default

    @classmethod
    def database_settings(cls) -> DatabaseSettings:
        data: dict[str, object] = {}

        backend_value = cls._cfg.get("Database", "backend")
        if backend_value is not None:
            data["backend"] = str(backend_value).strip()

        sqlite_value = cls._cfg.get("Database", "sqlite", "path")
        if sqlite_value is None:
            sqlite_path = str(cls._DEFAULT_SQLITE_DB_PATH)
        else:
            sqlite_path = str(sqlite_value)
        data["sqlite"] = {"path": sqlite_path}

        postgres_value = cls._cfg.get("Database", "postgres", "dsn")
        if postgres_value is None:
            postgres_dsn = str(cls._DEFAULT_POSTGRES_DSN)
        else:
            postgres_dsn = str(postgres_value)

        env_override = cls._postgres_dsn_env_override()
        if env_override != "":
            postgres_dsn = env_override
        data["postgres"] = {"dsn": postgres_dsn}

        return DatabaseSettings.model_validate(data)

    @classmethod
    def database_backend(cls) -> DatabaseBackend:
        try:
            return cls.database_settings().backend
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_DB_BACKEND

    @classmethod
    def database_sqlite_path(cls) -> DatabasePath:
        try:
            return cls.database_settings().sqlite.path
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_SQLITE_DB_PATH

    @classmethod
    def database_postgres_dsn(cls) -> DatabaseDsn:
        try:
            return cls.database_settings().postgres.dsn
        except ValidationError as exc:
            cls._logger.error("Invalid Database configuration: %s", exc)
            return cls._DEFAULT_POSTGRES_DSN

    @classmethod
    def get_config_path(cls) -> str:
        return cls._cfg.get_config_path()

    @classmethod
    def default_mac_address(cls) -> MacAddressStr:
        mac = cls._cfg.get("FastApiRequestDefault", "mac_address")
        if not mac:
            cls._logger.error(
                "Missing configuration value for '%s'; using MacAddress.null()",
                cls._config_path("FastApiRequestDefault", "mac_address"),
            )
            return cast(MacAddressStr, MacAddress.null())
        return cast(MacAddressStr, mac)

    @classmethod
    def default_ip_address(cls) -> InetAddressStr:
        return cast(
            InetAddressStr,
            cls._get_str(cls._DEFAULT_IP_ADDRESS, "FastApiRequestDefault", "ip_address"),
        )

    # SNMP v2 settings
    @classmethod
    def snmp_enable(cls) -> bool:
        return cls._get_bool(True, "SNMP", "version", "2c", "enable")

    @classmethod
    def snmp_retries(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_RETRIES, "SNMP", "version", "2c", "retries")



    @classmethod
    def snmp_read_community(cls) -> SnmpReadCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "read_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpReadCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "read_community"),
                    value,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        legacy = cls._cfg.get("SNMP", "version", "2c", "community")
        if legacy is not None:
            if isinstance(legacy, str) and legacy.strip() != "":
                return cast(SnmpReadCommunity, legacy)
            if not isinstance(legacy, str):
                coerced = str(legacy)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "community"),
                    legacy,
                    coerced,
                )
                return cast(SnmpReadCommunity, coerced)
        return cast(
            SnmpReadCommunity,
            cls._get_str(cls._DEFAULT_SNMP_READ_COMMUNITY, "SNMP", "version", "2c", "read_community"),
        )

    @classmethod
    def snmp_write_community(cls) -> SnmpWriteCommunity:
        value = cls._cfg.get("SNMP", "version", "2c", "write_community")
        if value is not None:
            if isinstance(value, str) and value.strip() != "":
                return cast(SnmpWriteCommunity, value)
            if not isinstance(value, str):
                coerced = str(value)
                cls._logger.error(
                    "Non-string configuration value for '%s': %r; using coerced '%s'",
                    cls._config_path("SNMP", "version", "2c", "write_community"),
                    value,
                    coerced,
                )
                return cast(SnmpWriteCommunity, coerced)
        return cast(
            SnmpWriteCommunity,
            cls._get_str(cls._DEFAULT_SNMP_WRITE_COMMUNITY, "SNMP", "version", "2c", "write_community"),
        )

    # SNMP v3 settings

    @classmethod
    def snmp_v3_enable(cls) -> bool:
        return cls._get_bool(False, "SNMP", "version", "3", "enable")

    @classmethod
    def snmp_v3_username(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "username")

    @classmethod
    def snmp_v3_security_level(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "securityLevel")

    @classmethod
    def snmp_v3_auth_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "authProtocol")

    @classmethod
    def snmp_v3_auth_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "authPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "authPassword")

    @classmethod
    def snmp_v3_priv_protocol(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        return cls._get_str("", "SNMP", "version", "3", "privProtocol")

    @classmethod
    def snmp_v3_priv_password(cls) -> str:
        if not cls.snmp_v3_enable():
            return ""
        value = cls._get_str("", "SNMP", "version", "3", "privPassword")
        return cls._maybe_decrypt(value, "SNMP", "version", "3", "privPassword")

    # SNMP general settings
    @classmethod
    def snmp_timeout(cls) -> int:
        return cls._get_int(cls._DEFAULT_SNMP_TIMEOUT, "SNMP", "timeout")

    # Bulk data transfer settings
    @classmethod
    def bulk_transfer_method(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "method")

    @classmethod
    def bulk_tftp_ip_v4(cls) -> IPv4Str:
        return cast(
            IPv4Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v4"),
        )

    @classmethod
    def bulk_tftp_ip_v6(cls) -> IPv6Str:
        return cast(
            IPv6Str,
            cls._get_str("", "PnmBulkDataTransfer", "tftp", "ip_v6"),
        )

    @classmethod
    def bulk_tftp_remote_dir(cls) -> str:
        return cls._get_str_allow_empty("", "PnmBulkDataTransfer", "tftp", "remote_dir")

    @classmethod
    def bulk_http_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "http", "base_url")

    @classmethod
    def bulk_http_port(cls) -> int:
        return cls._get_int(cls._DEFAULT_HTTP_PORT, "PnmBulkDataTransfer", "http", "port")

    @classmethod
    def bulk_https_base_url(cls) -> str:
        return cls._get_str("", "PnmBulkDataTransfer", "https", "base_url")

    @classmethod
    def bulk_https_port(cls) -> int:
        return cls._get_int(cls._DEFAULT_HTTPS_PORT, "PnmBulkDataTransfer", "https", "port")

    # PNM file retrieval/storage settings
    @classmethod
    def save_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def pnm_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNM_DIR, "PnmFileRetrieval", "pnm_dir")

    @classmethod
    def csv_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_CSV_DIR, "PnmFileRetrieval", "csv_dir")

    @classmethod
    def json_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_JSON_DIR, "PnmFileRetrieval", "json_dir")

    @classmethod
    def xlsx_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_XLSX_DIR, "PnmFileRetrieval", "xlsx_dir")

    @classmethod
    def png_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_PNG_DIR, "PnmFileRetrieval", "png_dir")

    @classmethod
    def archive_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_ARCHIVE_DIR, "PnmFileRetrieval", "archive_dir")

    @classmethod
    def message_response_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_MSG_RSP_DIR, "PnmFileRetrieval", "msg_rsp_dir")

    @classmethod
    def transaction_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "transaction_db")

    @classmethod
    def capture_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "capture_group_db")

    @classmethod
    def session_group_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "session_group_db")

    @classmethod
    def operation_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "operation_db")

    @classmethod
    def json_db(cls) -> str:
        return cls._get_str("", "PnmFileRetrieval", "json_transaction_db")

    @classmethod
    def file_retrieval_retries(cls) -> int:
        return cls._get_int(cls._DEFAULT_FILE_RETRIEVAL_RETRIES, "PnmFileRetrieval", "retries")

    @classmethod
    def retrieval_method(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "method")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "method")

        return cls._get_str_fallback("", primary, legacy)

    # Local method
    @classmethod
    def local_src_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "local", "src_dir")
        return cls._get_str_fallback("", primary, legacy)

    # TFTP method
    @classmethod
    def tftp_host(cls) -> InetAddressStr:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "host")
        return InetAddressStr(cls._get_str_fallback("", primary, legacy))

    @classmethod
    def tftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_TFTP_PORT, primary, legacy)

    @classmethod
    def tftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def tftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "tftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # FTP method
    @classmethod
    def ftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_FTP_PORT, primary, legacy)

    @classmethod
    def ftp_use_tls(cls) -> bool:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "tls")
        return cls._get_bool_fallback(False, primary, legacy)

    @classmethod
    def ftp_timeout(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "timeout")
        return cls._get_int_fallback(cls._DEFAULT_SNMP_TIMEOUT, primary, legacy)

    @classmethod
    def ftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def ftp_password(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp")
        return cls._get_password_value_fallback(
            True,
            primary,
            legacy,
        )

    @classmethod
    def ftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "ftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SCP method
    @classmethod
    def scp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SCP_PORT, primary, legacy)

    @classmethod
    def scp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def scp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def scp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "scp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # SFTP method
    @classmethod
    def sftp_host(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "host")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "port")
        return cls._get_int_fallback(cls._DEFAULT_SFTP_PORT, primary, legacy)

    @classmethod
    def sftp_user(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "user")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_password(cls) -> str:
        private_key_path_primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path_legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        private_key_path         = cls._peek_str_fallback(private_key_path_primary, private_key_path_legacy).strip()
        require                  = private_key_path == ""

        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp")

        return cls._get_password_value_fallback(
            require,
            primary,
            legacy,
        )

    @classmethod
    def sftp_private_key_path(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "private_key_path")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def sftp_remote_dir(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "sftp", "remote_dir")
        return cls._get_str_fallback_allow_empty("", primary, legacy)

    # HTTP method
    @classmethod
    def http_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def http_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "http", "port")
        return cls._get_int_fallback(cls._DEFAULT_HTTP_PORT, primary, legacy)

    # HTTPS method
    @classmethod
    def https_base_url(cls) -> str:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "base_url")
        return cls._get_str_fallback("", primary, legacy)

    @classmethod
    def https_port(cls) -> int:
        primary = ("PnmFileRetrieval", cls._PRIMARY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
        legacy  = ("PnmFileRetrieval", cls._LEGACY_RETRIEVAL_METHOD_KEY, "methods", "https", "port")
        return cls._get_int_fallback(cls._DEFAULT_HTTPS_PORT, primary, legacy)

    # Logging
    @classmethod
    def log_level(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_LEVEL, "logging", "log_level")

    @classmethod
    def log_dir(cls) -> str:
        return cls._get_str(cls._DEFAULT_LOG_DIR, "logging", "log_dir")

    @classmethod
    def log_filename(cls) -> FileNameStr:
        return cls._get_str(cls._DEFAULT_LOG_FILENAME, "logging", "log_filename")

    @classmethod
    def initialize_directories(cls) -> None:
        """
        Create necessary directories if they do not exist.
        """
        directories = [
            cls.pnm_dir(),
            cls.csv_dir(),
            cls.json_dir(),
            cls.xlsx_dir(),
            cls.png_dir(),
            cls.archive_dir(),
            cls.message_response_dir(),
            cls.log_dir(),
        ]
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    @classmethod
    def reload(cls) -> None:
        """
        Reload the configuration settings.
        """
        cls._cfg.reload()
        cls.initialize_directories()

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/lib/types.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import NewType, TypeAlias

import numpy as np
from numpy.typing import NDArray

# TODO: New home for these
GroupId         = NewType("GroupId", str)
TransactionId   = NewType("TransactionId", str)
OperationId     = NewType("OperationId", str)

HashStr = NewType("HashStr", str)
ExitCode = NewType("ExitCode", int)

# Enum String Type
class StringEnum(str, Enum):
    """Py3.10-compatible StrEnum shim."""
    pass

class DatabaseBackend(StringEnum):
    """Supported Database Backend Identifiers."""
    SQLITE   = "sqlite"
    POSTGRES = "postgres"

class FloatEnum(float, Enum):
    """Float-like Enum base: members behave like floats."""
    pass

# Basic strings
String: TypeAlias       = str
StringArray: TypeAlias  = list[String]
JsonScalar: TypeAlias   = str | int | float | bool | None
JsonValue: TypeAlias    = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias   = dict[str, JsonValue]

# ────────────────────────────────────────────────────────────────────────────────
# Core numerics
# ────────────────────────────────────────────────────────────────────────────────
Number       = int | float | np.number
Float64      = np.float64
ByteArray    = list[np.uint8]

# Generic array-likes (inputs)
# TODO: Review to remove -> _ArrayLike = Union[Sequence[Number], NDArray[object]]
_ArrayLike   = Sequence[Number] | NDArray[np.generic]

ArrayLike    = list[Number]
ArrayLikeF64 = Sequence[float] | NDArray[np.float64]

# Canonical ndarray outputs (internal processing should normalize to these)
NDArrayF64: TypeAlias   = NDArray[np.float64]
NDArrayI64: TypeAlias   = NDArray[np.int64]
NDArrayC128: TypeAlias  = NDArray[np.complex128]

# ────────────────────────────────────────────────────────────────────────────────
# Simple series / containers  — use TypeAlias (recommended)
# ────────────────────────────────────────────────────────────────────────────────
IntSeries: TypeAlias        = list[int]
FloatSeries: TypeAlias      = list[float]
TwoDFloatSeries: TypeAlias  = list[FloatSeries]
FloatSequence: TypeAlias    = Sequence[float]

# Complex number encodings (JSON-safe)
Complex                  = tuple[float, float]  # (re, im)
ComplexArray: TypeAlias  = list[Complex]        # K × (re, im)
ComplexSeries: TypeAlias = list[complex]        # Python complex list (internal use)
ComplexMatrix: TypeAlias = list[ComplexArray]

# ────────────────────────────────────────────────────────────────────────────────
# Modulation profile identifiers
# ────────────────────────────────────────────────────────────────────────────────
ProfileId = NewType("ProfileId", int)

# ────────────────────────────────────────────────────────────────────────────────
# Paths / filesystem
# ────────────────────────────────────────────────────────────────────────────────
PathLike    = str | Path
PathArray   = list[PathLike]
FileNameStr = NewType("FileNameStr", str)
DatabasePath = NewType("DatabasePath", str)
DatabaseDsn  = NewType("DatabaseDsn", str)

# ────────────────────────────────────────────────────────────────────────────────
# ────────────────────────────────────────────────────────────────────────────────
# Unit-tagged NewTypes (scalars only; runtime = underlying type)
# ────────────────────────────────────────────────────────────────────────────────
# Time / index
CaptureTime   = NewType("CaptureTime", int)
TimeStamp     = NewType("TimeStamp", int)
TimestampSec  = NewType("TimestampSec", int)
TimestampMs   = NewType("TimestampMs", int)
TimeStampUs   = NewType("TimeStampUs", int)
TimeStampNs   = NewType("TimeStampNs", int)
SampleIndex   = NewType("SampleIndex", int)

# RF / PHY units (keep as scalars with units)
FrequencyHz   = NewType("FrequencyHz", int)
BandwidthHz   = NewType("BandwidthHz", int)

PowerdBmV     = NewType("PowerdBmV", float)
PowerdB       = NewType("PowerdB", float)
MERdB         = NewType("MERdB", float)
SNRdB         = NewType("SNRdB", float)
SNRln         = NewType("SNRln", float)

# DOCSIS identifiers
ChannelId     = NewType("ChannelId", int)
SubcarrierId  = NewType("SubcarrierId", int)
SubcarrierIdx = NewType("SubcarrierIdx", int)

# SNMP identifiers
OidStr          = NewType("OidStr", str)              # symbolic or dotted-decimal
OidNumTuple     = NewType("OidNumTuple", tuple[int, ...])
SnmpIndex       = NewType("SnmpIndex", int)
InterfaceIndex  = NewType("InterfaceIndex", int)
EntryIndex      = NewType("EntryIndex", int)

# Network addressing (store as plain strings; validate elsewhere)
HostNameStr     = NewType("HostNameStr", str)
SnmpReadCommunity  = NewType("SnmpReadCommunity", str)
SnmpWriteCommunity = NewType("SnmpWriteCommunity", str)
SnmpCommunity      = SnmpReadCommunity
MacAddressStr   = NewType("MacAddressStr", str)         # aa:bb:cc:dd:ee:ff | aa-bb-cc-dd-ee-ff | aabb.ccdd.eeff | aabbccddeeff | aabbcc:ddeeff |
InetAddressStr  = NewType("InetAddressStr", str)        # 192.168.0.1 | 2001:db8::1
IPv4Str         = NewType("IPv4Str", InetAddressStr)    # 192.168.0.1
IPv6Str         = NewType("IPv6Str", InetAddressStr)    # 2001:db8::1

# File tokens
FileStem      = NewType("FileStem", str)            # name without extension
FileExt       = NewType("FileExt", str)             # ".csv", ".png", …
FileName      = NewType("FileName", str)

# ────────────────────────────────────────────────────────────────────────────────
# Analysis-specific tuples / series
# ────────────────────────────────────────────────────────────────────────────────
RegressionCoeffs = tuple[float, float]              # (slope, intercept)
RegressionStats  = tuple[float, float, float]       # (slope, intercept, r2)

# RxMER / spectrum containers
FrequencySeriesHz: TypeAlias = list[FrequencyHz]
MerSeriesdB: TypeAlias       = FloatSeries
ShannonSeriesdB: TypeAlias   = FloatSeries
MagnitudeSeries: TypeAlias   = FloatSeries

BitsPerSymbol       = NewType("BitsPerSymbol", int)
BitsPerSymbolSeries: TypeAlias = list[BitsPerSymbol]

Microseconds = NewType("Microseconds", float)

# IFFT time response
IfftTimeResponse: TypeAlias = tuple[NDArrayF64, NDArrayC128]

# ────────────────────────────────────────────────────────────────────────────────
# HTTP return code type
# ────────────────────────────────────────────────────────────────────────────────
HttpRtnCode = NewType("HttpRtnCode", int)

ScalarValue: TypeAlias = float | int | str

# ────────────────────────────────────────────────────────────────────────────────
# SSH return code type
# ────────────────────────────────────────────────────────────────────────────────
UserNameStr         = NewType("UserNameStr", str)

SshOk: TypeAlias    = bool
SshStdout           = NewType("SshStdout", str)
SshStderr           = NewType("SshStderr", str)
SshExitCode         = NewType("SshExitCode", int)
SshCommandResult: TypeAlias = tuple[SshStdout, SshStderr, SshExitCode]

RemoteDirEntry             = NewType("RemoteDirEntry", str)
RemoteDirEntries: TypeAlias = list[RemoteDirEntry]

# ────────────────────────────────────────────────────────────────────────────────
# Explicit public surface
# ────────────────────────────────────────────────────────────────────────────────
__all__ = [
    "SshOk", "SshStdout", "SshStderr", "SshExitCode", "SshCommandResult",
    "RemoteDirEntry", "RemoteDirEntries", "UserNameStr",
    "ScalarValue",
    "HashStr",
    "TransactionId", "GroupId", "OperationId",
    # enums
    "StringEnum", "FloatEnum", "DatabaseBackend",
    # strings
    "String", "StringArray", "JsonScalar", "JsonValue", "JsonObject",
    "ByteArray",
    # numerics
    "Number", "Float64", "ArrayLike", "ArrayLikeF64", "NDArrayF64", "NDArrayI64",
    "FloatSeries", "TwoDFloatSeries", "FloatSequence", "IntSeries",
    # complex
    "Complex", "ComplexArray", "ComplexSeries",
    # paths
    "PathLike", "PathArray", "FileNameStr", "DatabasePath", "DatabaseDsn",
    # unit-tagged scalars
    "CaptureTime", "TimeStamp", "TimestampSec", "TimestampMs", "TimeStampUs", "TimeStampNs",
    "SampleIndex",
    "FrequencyHz", "BandwidthHz", "PowerdBmV", "PowerdB", "MERdB", "SNRdB", "SNRln",
    "ChannelId", "SubcarrierId",
    "OidStr", "OidNumTuple",
    "SnmpReadCommunity", "SnmpWriteCommunity", "SnmpCommunity",
    "MacAddressStr", "IPv4Str", "IPv6Str",
    "FileStem", "FileExt", "FileName",
    # analysis tuples / series
    "RegressionCoeffs", "RegressionStats",
    "FrequencySeriesHz", "MerSeriesdB", "ShannonSeriesdB", "MagnitudeSeries",
    # modulation/profile & misc
    "ProfileId", "BitsPerSymbol", "BitsPerSymbolSeries", "Microseconds",
    "HttpRtnCode", "InterfaceIndex", "EntryIndex"
]

# FILE: /home/dev01/Projects/PyPNM/src/pypnm/api/routes/advance/analysis/report/multi_analysis_rpt.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel

from pypnm.api.routes.advance.common.capture_data_aggregator import (
    CaptureDataAggregator,
    TransactionCollection,
)
from pypnm.api.routes.advance.common.transactionsCollection import (
    TransactionCollectionModel,
)
from pypnm.api.routes.basic.abstract.analysis_report import AnalysisOutputModel
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.data_type.sysDescr import SystemDescriptor, SystemDescriptorModel
from pypnm.lib.archive.manager import ArchiveManager
from pypnm.lib.csv.manager import CSVManager
from pypnm.lib.db.json_transaction import JsonTransactionDb
from pypnm.lib.mac_address import MacAddress, cast
from pypnm.lib.matplot.manager import MatplotManager
from pypnm.lib.types import ChannelId, JsonScalar, PathArray, PathLike, TimeStamp
from pypnm.lib.utils import Generate, TimeUnit


class MultiAnalysisRpt(ABC):
    """
    Abstact Class to manage multiple captures:
     + This class will be inherited and can support single or multiple cable modems
    """
    def __init__(self, capt_data_agg: CaptureDataAggregator) -> None:
        self.logger = logging.getLogger("MultiAnalysisRpt")

        self._capt_data_agg = capt_data_agg
        self._trans_collect:TransactionCollection = capt_data_agg.collect()
        tcm:TransactionCollectionModel = self._trans_collect.getTransactionCollectionModel()[0]

        self._png_dir: PathLike       = cast(PathLike, SystemConfigSettings.png_dir())
        self._csv_dir: PathLike       = cast(PathLike, SystemConfigSettings.csv_dir())
        self._json_dir: PathLike      = cast(PathLike, SystemConfigSettings.json_dir())
        self._archive_dir: PathLike   = cast(PathLike, SystemConfigSettings.archive_dir())

        self._group_time:TimeStamp    = Generate.time_stamp()
        self._base_filename: PathLike = ""
        self._common_analysis_model: dict[ChannelId, BaseModel] = {}

        self._mac_addresses: set[MacAddress]  = set()
        self._cmts_mac_address: MacAddress = MacAddress(MacAddress.null())
        self._sys_descr_model: SystemDescriptorModel  = tcm.device_details.system_description

        self.csv_files: list[PathLike]  = []
        self.plot_files: list[PathLike] = []
        self.json_files: list[PathLike] = []

        self.logger.info(f"MultiAnalysisRpt: MAC: {self._mac_addresses}, "
                         f"Model: {self._sys_descr_model.model_dump()}, "
                         f"GroupTime: {self._group_time}")

    def getMacAddresses(self) -> list[MacAddress]:
        """Return the cable-modem MAC address associated with this report session."""
        return self._trans_collect.getMacAddresses()

    def get_system_description(self) -> SystemDescriptor:
        """Return the device SystemDescriptor used for filenames and labeling."""
        return SystemDescriptor.load_from_dict(self._sys_descr_model.model_dump())

    def get_group_time(self) -> int:
        """Return the session/group timestamp used to namespace output filenames."""
        return self._group_time

    def to_output_model(self) -> AnalysisOutputModel:
        """
        Produce a serializable model of the generated artifacts (time, CSVs, plots, archive).

        Call this after `build_report()` to pass paths and metadata to API callers.
        """
        return AnalysisOutputModel(
            time         =   self._group_time,
            csv_files    =   self.csv_files,
            plot_files   =   self.plot_files,
            json_files   =   self.json_files,
            archive_file =   self.archive_file,)

    def create_csv_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a CSV filename of the form:
            <csv_dir>/<mac>_<model>_<timestamp>[_TAGS].csv

        Example:
            fname = self.create_csv_fname(tags=["ch1", "rpt"])
        '''
        if tags is None:
            tags = []
        return f"{self._csv_dir}/{self.create_generic_fname(tags=tags, ext='csv')}"

    def create_png_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a PNG filename of the form:
            <png_dir>/<mac>_<model>_<timestamp>[_TAGS].png

        Example:
            fname = self.create_png_fname(tags=["spectrum"])
        '''
        if tags is None:
            tags = []
        return f"{self._png_dir}/{self.create_generic_fname(tags=tags, ext='png')}"

    def create_json_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a PNG filename of the form:
            <json_dir>/<mac>_<model>_<timestamp>[_TAGS].json

        Example:
            fname = self.create_json_fname(tags=["spectrum"])
        '''
        if tags is None:
            tags = []
        return f"{self._json_dir}/{self.create_generic_fname(tags=tags, ext='json')}"

    def create_archive_fname(self, tags: list[str] = None) -> PathLike:
        '''
        Build a ZIP archive filename of the form:
            <archive_dir>/<mac>_<model>_<timestamp>[_TAGS].zip

        Example:
            fname = self.create_archive_fname(tags=["bundle"])
        '''
        if tags is None:
            tags = []
        return f"{self._archive_dir}/{self.create_generic_fname(tags=tags, ext='zip')}"

    def create_generic_fname(self, tags: list[str], ext: str = "") -> str:
        """
        Generate a generic filename using the current session metadata plus tags.

        Args:
            tags: Optional descriptors to append (e.g., ["ch1", "rpt"]).
            ext:  Optional file extension (e.g., "csv", ".png").

        Returns:
            The constructed filename (no directories).

        Example:
            name = self.create_generic_fname(tags=["debug"], ext="json")
        """
        return self._generate_fname(tags=tags, ext=ext)

    def csv_manager_factory(self) -> CSVManager:
        """Return a `CSVManager` instance. Subclasses may override to customize behavior."""
        return CSVManager()

    def get_base_filename(self) -> str:
        """
        Return the base filename (no extension) derived from MAC/model/time.

        Useful when emitting multiple related files for the same report run.
        """
        return self._generate_fname()

    def build_report(self) -> Path:
        """
        Run the full report pipeline: `_process()` → CSV generation → plot rendering → ZIP.

        Returns:
            The path to the created ZIP archive.

        Typical use:
            archive = report.build_report()
            return report.to_model()
        """
        self._process()

        f:PathArray = [Path('')]

        for csv_mgr in self.create_csv():

            if not csv_mgr.write():
                self.logger.error(f"Failed to write CSV: {csv_mgr.get_path_fname()}")
                continue

            self.logger.debug(f'Wrote CSV File: {csv_mgr.get_path_fname()}')
            self.csv_files.append(csv_mgr.get_path_fname())
            f.append(csv_mgr.get_path_fname())

        for matplot_mgr in self.create_matplot():
            for fn in matplot_mgr.get_png_files():
                self.logger.debug(f'Wrote Matplotlib Figure: {fn}')
                self.plot_files.append(fn)
                f.append(fn)

        if not self.json_files:
            self.logger.warning("No JSON files were registered for the report archive.")
        else:
            f.extend(self.json_files)

        try:
            self.archive_file = ArchiveManager().zip_files(files=f, archive_path=self.create_archive_fname())

        except Exception as e:
            self.logger.error(f"Failed to create archive: {e}")

        return self.archive_file

    def _generate_fname(self, tags: list[str] = None, ext: str = "") -> str:
        """
        Construct a sanitized filename from:
          - MAC address (colon-free, lowercase)
          - device model (`system_description.model`, spaces → underscores, lowercase)
          - group timestamp
          - optional tag suffix (underscored)
          - optional extension

        Args:
            tags: Descriptive tokens to append (e.g., ["ch1", "rpt"]).
            ext:  Extension with or without leading dot.

        Returns:
            The finalized filename string (no directory).

        Example:
            self._generate_fname(tags=["ch1", "rpt"], ext="csv")
        """
        if tags is None:
            tags = []
        mac = self.getMacAddresses()[0].to_mac_format()
        model = self.get_system_description().model.replace(" ", "_").lower()
        ts = str(self.get_group_time())

        clean_tags = []
        for t in tags:
            t_clean = str(t).strip().replace(" ", "_").lower()
            if t_clean:
                clean_tags.append(t_clean)

        tag_part = f"_{'_'.join(clean_tags)}" if clean_tags else ""
        ext = ext.lstrip(".")
        ext_part = f".{ext}" if ext else ""

        return f"{mac}_{model}_{ts}{tag_part}{ext_part}"

    def getTransactionCollection(self) -> TransactionCollection:
        """Return the `TransactionCollection` instance used to collect capture files."""
        return self._trans_collect

    def register_models_for_json_archive_files(self, model:BaseModel, filename_tags: list[str], append_timestamp: bool = True) -> None:
        """Register a Pydantic model to be serialized as JSON and included in the report archive."""

        # model is a Pydantic BaseModel instance, but it can be any subclass
        # We need to make sure its initial derive is from BaseModel
        if not isinstance(model, BaseModel):
            raise TypeError("model must be a Pydantic BaseModel instance")

        if append_timestamp:
            filename_tags.append(str(Generate.time_stamp(TimeUnit.NANOSECONDS)))

        full_path_fname = self.create_json_fname(tags=filename_tags)

        JsonTransactionDb().write_json(data  = model.model_dump(),
                                       fname = Path(full_path_fname).parts[-1])

        self.json_files.append(full_path_fname)

    @abstractmethod
    def _process(self) -> None:
        """
        Populate per-channel report models from analysis results.

        Implement in subclasses:
            - Parse `self.get_analysis_model()` and/or `self.get_analysis_data()`.
            - Build models and register with:
                `self.register_common_analysis_model(channel_id, model)`.
        """
        pass

    @abstractmethod
    def create_csv(self, **kwargs: JsonScalar) -> list[CSVManager]:
        """
        Build one or more `CSVManager` instances ready to `write()`.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[CSVManager]
            List of configured `CSVManager` instances ready to write.
        """
        return []

    @abstractmethod
    def create_matplot(self, **kwargs: JsonScalar) -> list[MatplotManager]:
        """
        Build one or more `MatplotManager` instances to render PNG figures.

        Parameters
        ----------
        **kwargs : JsonScalar
            Optional configuration flags or scalar parameters (ints, floats,
            strings, booleans, or None) used by concrete implementations.

        Returns
        -------
        list[MatplotManager]
            List of configured `MatplotManager` instances used to generate plots.
        """
        return []

# FILE: /home/dev01/Projects/PyPNM/tests/test_system_config_settings.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import DatabaseBackend


class FakeConfigManager:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}
        self.reload_called: bool = False

    def get(self, *path: str) -> object | None:
        key = ".".join(path)
        return self._data.get(key)

    def set(self, value: object, *path: str) -> None:
        key = ".".join(path)
        self._data[key] = value

    def reload(self) -> None:
        self.reload_called = True


@pytest.fixture(autouse=True)
def _reset_cfg(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Ensure each test starts with a fresh FakeConfigManager.
    """
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)


def test_default_mac_address_from_config(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {"FastApiRequestDefault.mac_address": "aa:bb:cc:dd:ee:ff"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    mac = SystemConfigSettings.default_mac_address()
    assert mac == "aa:bb:cc:dd:ee:ff"


def test_default_mac_address_missing_uses_null_and_logs_error(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        mac = SystemConfigSettings.default_mac_address()

    assert mac == MacAddress.null()
    assert (
        "Missing configuration value for 'FastApiRequestDefault.mac_address'"
        in caplog.text
    )


def test_default_ip_address_uses_config_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"FastApiRequestDefault.ip_address": "10.0.0.5"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    ip = SystemConfigSettings.default_ip_address()
    assert ip == "10.0.0.5"


def test_default_ip_address_missing_falls_back_to_default_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        ip = SystemConfigSettings.default_ip_address()

    assert ip == "192.168.0.100"
    assert (
        "Missing configuration value for 'FastApiRequestDefault.ip_address'"
        in caplog.text
    )


def test_snmp_enable_boolean_and_string_handling(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Direct boolean True
    fake = FakeConfigManager(
        {"SNMP.version.2c.enable": True}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    assert SystemConfigSettings.snmp_enable() is True

    # String false
    fake2 = FakeConfigManager(
        {"SNMP.version.2c.enable": "false"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)
    assert SystemConfigSettings.snmp_enable() is False

    # Invalid value falls back to default True and logs
    fake3 = FakeConfigManager(
        {"SNMP.version.2c.enable": "not-a-bool"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        value = SystemConfigSettings.snmp_enable()

    assert value is True
    assert "Invalid boolean configuration value for 'SNMP.version.2c.enable'" in caplog.text


def test_snmp_retries_int_conversion_and_defaults(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Valid integer string
    fake = FakeConfigManager(
        {"SNMP.version.2c.retries": "7"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    assert SystemConfigSettings.snmp_retries() == 7

    # Missing => default 5 with log
    fake2 = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        retries_missing = SystemConfigSettings.snmp_retries()

    assert retries_missing == 5
    assert "Missing configuration value for 'SNMP.version.2c.retries'" in caplog.text

    # Invalid => default 5 with log
    fake3 = FakeConfigManager(
        {"SNMP.version.2c.retries": "not-an-int"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake3)

    with caplog.at_level(logging.ERROR, logger=logger_name):
        retries_invalid = SystemConfigSettings.snmp_retries()

    assert retries_invalid == 5
    assert "Invalid integer configuration value for 'SNMP.version.2c.retries'" in caplog.text


def test_database_backend_defaults_to_sqlite_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    backend = SystemConfigSettings.database_backend()
    assert backend == DatabaseBackend.SQLITE


def test_database_settings_rejects_invalid_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"Database.backend": "oracle"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_database_settings_rejects_blank_sqlite_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"Database.sqlite.path": ""}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_database_settings_env_override_for_postgres_dsn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.setenv("PYPNM_DB_POSTGRES_DSN", "postgresql://pypnm@localhost:5432/pypnm")

    settings = SystemConfigSettings.database_settings()
    assert settings.postgres.dsn == "postgresql://pypnm@localhost:5432/pypnm"


def test_database_settings_blank_postgres_dsn_without_env_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "Database.backend": "postgres",
            "Database.postgres.dsn": "",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    with pytest.raises(ValidationError):
        SystemConfigSettings.database_settings()


def test_log_settings_with_defaults_and_overrides(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Override all three logging keys
    fake = FakeConfigManager(
        {
            "logging.log_level": "DEBUG",
            "logging.log_dir": "/var/log/pypnm",
            "logging.log_filename": "custom.log",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.log_level() == "DEBUG"
    assert SystemConfigSettings.log_dir() == "/var/log/pypnm"
    assert SystemConfigSettings.log_filename() == "custom.log"

    # Missing keys => defaults with error logs
    fake2 = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake2)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        level = SystemConfigSettings.log_level()
        log_dir = SystemConfigSettings.log_dir()
        fname = SystemConfigSettings.log_filename()

    assert level == "INFO"
    assert log_dir == "logs"
    assert fname == "pypnm.log"

    text = caplog.text
    assert "Missing configuration value for 'logging.log_level'" in text
    assert "Missing configuration value for 'logging.log_dir'" in text
    assert "Missing configuration value for 'logging.log_filename'" in text


def test_initialize_directories_creates_expected_default_dirs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """
    Use defaults and change CWD so .data/* and logs/ are created under tmp_path.
    """
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    monkeypatch.chdir(tmp_path)

    SystemConfigSettings.initialize_directories()

    # Defaults from SystemConfigSettings
    base = tmp_path
    expected_dirs = [
        base / ".data" / "pnm",
        base / ".data" / "csv",
        base / ".data" / "json",
        base / ".data" / "xlsx",
        base / ".data" / "png",
        base / ".data" / "archive",
        base / ".data" / "msg_rsp",
        base / "logs",
    ]

    for d in expected_dirs:
        assert d.is_dir(), f"Expected directory to exist: {d}"


def test_reload_calls_config_reload_and_initializes_directories(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)
    monkeypatch.chdir(tmp_path)

    SystemConfigSettings.reload()

    # reload() must have been called on the underlying ConfigManager
    assert fake.reload_called is True

    # And directories should be initialized as in the previous test
    base = tmp_path
    assert (base / ".data" / "pnm").is_dir()
    assert (base / "logs").is_dir()


def test_scp_settings_use_config_values(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.scp.host": "scp-host",
            "PnmFileRetrieval.retrieval_method.methods.scp.port": "2222",
            "PnmFileRetrieval.retrieval_method.methods.scp.user": "scpuser",
            "PnmFileRetrieval.retrieval_method.methods.scp.password": "scppass",
            "PnmFileRetrieval.retrieval_method.methods.scp.private_key_path": "/home/test/.ssh/id_rsa_scp",
            "PnmFileRetrieval.retrieval_method.methods.scp.remote_dir": "/srv/tftp",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.scp_host() == "scp-host"
    assert SystemConfigSettings.scp_port() == 2222
    assert SystemConfigSettings.scp_user() == "scpuser"
    assert SystemConfigSettings.scp_password() == "scppass"
    assert SystemConfigSettings.scp_private_key_path() == "/home/test/.ssh/id_rsa_scp"
    assert SystemConfigSettings.scp_remote_dir() == "/srv/tftp"


def test_scp_port_and_private_key_defaults_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.scp.host": "localhost",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        port = SystemConfigSettings.scp_port()
        key_path = SystemConfigSettings.scp_private_key_path()

    assert port == 22
    assert key_path == ""

    text = caplog.text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.port'" in text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.scp.private_key_path'" in text


def test_sftp_settings_use_config_values(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.sftp.host": "sftp-host",
            "PnmFileRetrieval.retrieval_method.methods.sftp.port": "2223",
            "PnmFileRetrieval.retrieval_method.methods.sftp.user": "sftpuser",
            "PnmFileRetrieval.retrieval_method.methods.sftp.password": "sftppass",
            "PnmFileRetrieval.retrieval_method.methods.sftp.private_key_path": "/home/test/.ssh/id_rsa_sftp",
            "PnmFileRetrieval.retrieval_method.methods.sftp.remote_dir": "/srv/tftp-sftp",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.sftp_host() == "sftp-host"
    assert SystemConfigSettings.sftp_port() == 2223
    assert SystemConfigSettings.sftp_user() == "sftpuser"
    assert SystemConfigSettings.sftp_password() == "sftppass"
    assert SystemConfigSettings.sftp_private_key_path() == "/home/test/.ssh/id_rsa_sftp"
    assert SystemConfigSettings.sftp_remote_dir() == "/srv/tftp-sftp"


def test_sftp_port_and_private_key_defaults_and_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = FakeConfigManager(
        {
            "PnmFileRetrieval.retrieval_method.methods.sftp.host": "localhost",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    logger_name = "SystemConfigSettings"
    with caplog.at_level(logging.ERROR, logger=logger_name):
        port = SystemConfigSettings.sftp_port()
        key_path = SystemConfigSettings.sftp_private_key_path()

    assert port == 22
    assert key_path == ""

    text = caplog.text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.port'" in text
    assert "Missing configuration value for 'PnmFileRetrieval.retrieval_method.methods.sftp.private_key_path'" in text


def test_snmp_read_community_defaults_to_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "public"


def test_snmp_write_community_defaults_to_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager()
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == ""


def test_snmp_read_community_falls_back_to_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"SNMP.version.2c.community": "legacy"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "legacy"


def test_snmp_read_community_prefers_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {
            "SNMP.version.2c.read_community": "read",
            "SNMP.version.2c.community": "legacy",
        }
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_read_community() == "read"


def test_snmp_write_community_does_not_use_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"SNMP.version.2c.community": "legacy"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == ""


def test_snmp_write_community_uses_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeConfigManager(
        {"SNMP.version.2c.write_community": "private"}
    )
    monkeypatch.setattr(SystemConfigSettings, "_cfg", fake)

    assert SystemConfigSettings.snmp_write_community() == "private"

# FILE: /home/dev01/Projects/PyPNM/docs/system/system-config.md
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# System Configuration Reference

Canonical Structure And Field Semantics For `system.json`.

* **Config file**: [`src/pypnm/settings/system.json`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/settings/system.json)
* **ConfigManager class**: [`src/pypnm/config/config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/config_manager.py)
* **PnmConfigManager class**: [`src/pypnm/config/pnm_config_manager.py`](https://github.com/PyPNMApps/PyPNM/blob/main/src/pypnm/config/pnm_config_manager.py)

## Table Of Contents

* [1. FastApiRequestDefault](#1-fastapirequestdefault)
* [2. SNMP](#2-snmp)
* [3. PnmBulkDataTransfer](#3-pnmbulkdatatransfer)
* [4. PnmFileRetrieval](#4-pnmfileretrieval)
* [5. Database](#5-database)
* [6. Logging](#6-logging)
* [7. TestMode](#7-testmode)
* [Loading Configuration](#loading-configuration)

## 1. FastApiRequestDefault

Default Parameters For REST Requests To The FastAPI Service.

```json
"FastApiRequestDefault": {
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "ip_address": "192.168.0.100"
}
```

| Field       | Type   | Description                       |
| ----------- | ------ | --------------------------------- |
| mac_address | string | Default device MAC address.       |
| ip_address  | string | Default device IP (IPv4 or IPv6). |

## 2. SNMP

Global SNMP Settings, Including Version-Specific Options.

```json
"SNMP": {
  "timeout": 2,
  "version": {
    "2c": {
      "enable": true,
      "retries": 3,
      "read_community": "public",
      "write_community": "private"
    },
    "3": {
      "enable": false,
      "retries": 3,
      "username": "user",
      "securityLevel": "authPriv",
      "authProtocol": "SHA",
      "authPassword": "pass",
      "privProtocol": "AES",
      "privPassword": "privpass"
    }
  }
}
```

**Top-Level**

| Field   | Type   | Description                                  |
| ------- | ------ | -------------------------------------------- |
| timeout | number | Per-request timeout (seconds).               |
| version | object | Container for v2c/v3 configuration versions. |

**SNMP v2c**

| Field           | Type    | Description                     |
| --------------- | ------- | ------------------------------- |
| enable          | boolean | Enable v2c operations.          |
| retries         | number  | Retry count on timeout/failure. |
| read_community  | string  | Community for GET/WALK.         |
| write_community | string  | Community for SET.              |

**SNMP v3**

| Field         | Type    | Description                                  |
| ------------- | ------- | -------------------------------------------- |
| enable        | boolean | Enable v3 operations.                        |
| retries       | number  | Retry count on timeout/failure.              |
| username      | string  | Security name.                               |
| securityLevel | string  | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| authProtocol  | string  | For example `MD5`, `SHA`.                    |
| authPassword  | string  | Required when `auth*` is used.               |
| privProtocol  | string  | For example `DES`, `AES`.                    |
| privPassword  | string  | Required when `*Priv` is used.               |

## 3. PnmBulkDataTransfer

Transport Parameters For CM-Generated Files (for example, RxMER, FEC Summary) Sent To A Server.

```json
"PnmBulkDataTransfer": {
  "method": "tftp",
  "tftp": {
    "ip_v4": "192.168.0.10",
    "ip_v6": "::1",
    "remote_dir": ""
  },
  "http": {
    "base_url": "http://files.example.com/",
    "port": 80
  },
  "https": {
    "base_url": "https://files.example.com/",
    "port": 443
  }
}
```

| Field   | Type   | Description                                                |
| ------- | ------ | ---------------------------------------------------------- |
| method  | string | Preferred bulk method: `tftp`, `http`, or `https`.         |
| tftp.*  | object | TFTP targets for IPv4/IPv6 plus optional remote directory. |
| http.*  | object | HTTP base URL and port for file delivery.                  |
| https.* | object | HTTPS base URL and port for file delivery.                 |

## 4. PnmFileRetrieval {#pnmfileretrieval}

Local Storage Layout And Remote Retrieval Methods.

Related Guide: [File Transfer Methods](pnm-file-retrieval/index.md)

Runtime DB location policy: SQLite DB files live under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file.

```json
"PnmFileRetrieval": {
  "pnm_dir": ".data/pnm",
  "csv_dir": ".data/csv",
  "json_dir": ".data/json",
  "xlsx_dir": ".data/xlsx",
  "png_dir": ".data/png",
  "archive_dir": ".data/archive",
  "msg_rsp_dir": ".data/msg_rsp",
  "transaction_db": ".data/db/transactions.json",
  "capture_group_db": ".data/db/capture_group.json",
  "session_group_db": ".data/db/session_group.json",
  "operation_db": ".data/db/operation_capture.json",
  "json_transaction_db": ".data/db/json_transactions.json",
  "retries": 5,
  "retrieval_method": {
    "method": "local",
    "methods": {
      "local": {
        "src_dir": "/srv/tftp"
      },
      "tftp": {
        "host": "localhost",
        "port": 69,
        "timeout": 5,
        "remote_dir": ""
      },
      "ftp": {
        "host": "localhost",
        "port": 21,
        "tls": false,
        "timeout": 5,
        "user": "user",
        "password_enc": "",
        "remote_dir": "/srv/tftp"
      },
      "sftp": {
        "host": "localhost",
        "port": 22,
        "user": "user",
        "password_enc": "",
        "private_key_path": "",
        "remote_dir": "/srv/tftp"
      },
      "http": {
        "base_url": "http://STUB/",
        "port": 80
      },
      "https": {
        "base_url": "https://STUB/",
        "port": 443
      }
    }
  }
}
```

`password_enc` is the preferred password field for file retrieval methods. Plaintext `password` is supported only as a legacy fallback and is deprecated.

**Directories And Databases**

| Field               | Type   | Description                                  |
| ------------------- | ------ | -------------------------------------------- |
| pnm_dir             | string | Local storage for raw PNM binaries.          |
| csv_dir             | string | Local storage for derived CSVs.              |
| json_dir            | string | Local storage for derived JSON.              |
| xlsx_dir            | string | Local storage for Excel reports.             |
| png_dir             | string | Local storage for generated PNGs.            |
| archive_dir         | string | Local storage for analysis ZIP archives.     |
| msg_rsp_dir         | string | Local storage for message/response metadata. |
| transaction_db      | string | JSON ledger of file transactions.            |
| capture_group_db    | string | JSON map of grouped transactions.            |
| session_group_db    | string | JSON map of session groups.                  |
| operation_db        | string | JSON map of operation to capture group.      |
| json_transaction_db | string | JSON map of JSON transaction metadata.       |

**Retrieval Settings**

| Field                                  | Type   | Description                                                           |
| -------------------------------------- | ------ | --------------------------------------------------------------------- |
| retrieval_method.method                 | string | Active retrieval method: `local`, `tftp`, `ftp`, `sftp`, `http`, `https`. |
| retrieval_method.methods.local.src_dir  | string | Source directory to watch/copy from when using `local`.               |
| retrieval_method.methods.tftp.*         | object | TFTP host/port/timeout and remote directory.                          |
| retrieval_method.methods.ftp.*          | object | FTP connection, credentials, and remote directory.                    |
| retrieval_method.methods.sftp.*         | object | SFTP connection and remote directory.                                 |
| retrieval_method.methods.http.*         | object | HTTP base URL and port.                                               |
| retrieval_method.methods.https.*        | object | HTTPS base URL and port.                                              |
| retries                                | number | Max attempts per retrieval operation.                                 |

> The legacy key name `retrival_method` is accepted for backward compatibility.

## 5. Database

Database Backend Selection And Connection Settings.

```json
"Database": {
  "backend": "sqlite",
  "sqlite": {
    "path": ".data/db/pypnm.sqlite3"
  },
  "postgres": {
    "dsn": ""
  }
}
```

Backend selection is set at install time (SQLite default; Postgres recommended for multi-worker deployments). SQLite stores its DB file under `.data/db/` (demo uses `demo/.data/db/`), while Postgres is external and does not create a local DB file. For Postgres, supply the DSN via `PYPNM_DB_POSTGRES_DSN` to avoid storing plaintext credentials in tracked JSON files. Blank strings for required values are invalid when the backend is active.

DB backend migration is in progress; legacy ledger keys remain until Phase M6.

## 6. Logging

Application Logging Options.

```json
"logging": {
  "log_level": "INFO",
  "log_dir": "logs",
  "log_filename": "pypnm.log"
}
```

| Field        | Type   | Description                                 |
| ------------ | ------ | ------------------------------------------- |
| log_level    | string | `DEBUG`, `INFO`, `WARN`, or `ERROR`.        |
| log_dir      | string | Directory for log files.                    |
| log_filename | string | Log filename (created under `log_dir`).     |

## 7. TestMode

Global And Class-Specific Test-Mode Controls.

```json
"TestMode": {
  "global": {
    "mode": {
      "enable": true
    }
  },
  "class_name": {
    "DsScQamChannelSpectrumAnalyzer": {
      "mode": {
        "enable": true
      }
    }
  }
}
```

| Field                          | Type    | Description                                            |
| ------------------------------ | ------- | ------------------------------------------------------ |
| global.mode.enable             | boolean | Enable or disable global test mode.                    |
| class_name.<Class>.mode.enable | boolean | Per-class override for test mode, keyed by class name. |

## Loading Configuration

Typical Access Pattern Using The Manager Abstractions.

```python
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_config_manager import PnmConfigManager

cfg = ConfigManager()

mac = cfg.get("FastApiRequestDefault", "mac_address")
ip  = cfg.get("FastApiRequestDefault", "ip_address")

pnm_cfg = PnmConfigManager()
tftp_v4 = pnm_cfg.get("PnmBulkDataTransfer", "tftp")["ip_v4"]
```
