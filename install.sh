#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────────────────────────
# install.sh — Unified OS prerequisite installer and PyPNM bootstrapper
# Usage: ./install.sh [--demo-mode | --production] [--pnm-file-retrieval-setup] [venv_dir]
# ────────────────────────────────────────────────────────────────────────────────

VENV_DIR=".env"
DEMO_MODE="0"
PRODUCTION_MODE="0"
PNM_FILE_RETRIEVAL_SETUP="0"
DEVELOPMENT_MODE="0"
CLEAN_MODE="0"
PURGE_CACHE="0"
UNINSTALL_MODE="0"
UPDATE_MODE="0"
UPDATE_TAG=""
GITLEAKS_VERSION="8.18.1"
PYPNM_SHARED_GROUP="pypnm"
GROUP_MEMBERSHIP_CHANGED="0"

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
  ./install.sh [--demo-mode | --production] [--pnm-file-retrieval-setup] [venv_dir]
  ./install.sh --development
  ./install.sh --clean [--purge-cache]
  ./install.sh --update [tag]
  ./install.sh --uninstall [venv_dir]
  ./install.sh --help

Options:
  --development  Install Docker Engine + kind/kubectl + gitleaks for local dev and release workflows.
  --clean        Remove prior install artifacts (venv/build/dist/cache) before installing.
  --purge-cache  Clear pip cache after activating the venv (use with --clean when needed).
  --update       Delegate to the Docker update helper. Stops the current PyPNM
                 Docker deployment, removes old PyPNM containers/images, and
                 reinstalls the requested tag. If no tag is provided, the latest
                 release is used.
  --uninstall    Remove local install artifacts and the secrets key at ~/.ssh/pypnm_secrets.key.

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

  During interactive local installs, install.sh also offers to inspect and
  remediate a local tftpd-hpa server for upload-capable TFTP service by
  running:

      ./scripts/setup_tftp_server.sh

                  On Debian/Ubuntu, this helper updates
                  /etc/default/tftpd-hpa directly. On other Linux distros,
                  it performs detection and exits cleanly when the distro uses
                  a different tftpd-hpa layout.

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

  ./install.sh --update
      Update an existing PyPNM Docker deployment to the latest release.

  ./install.sh --update v1.5.3.0
      Update an existing PyPNM Docker deployment to a specific release.

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

And you can inspect or remediate a local tftpd-hpa server manually with:

  ./scripts/setup_tftp_server.sh

To update an existing Docker deployment manually, you can also run:

  ./scripts/update-pypnm-docker-container.sh [tag]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo-mode)
      DEMO_MODE="1"
      shift
      ;;
    --production)
      PRODUCTION_MODE="1"
      shift
      ;;
    --pnm-file-retrieval-setup)
      PNM_FILE_RETRIEVAL_SETUP="1"
      shift
      ;;
    --development)
      DEVELOPMENT_MODE="1"
      shift
      ;;
    --clean)
      CLEAN_MODE="1"
      shift
      ;;
    --purge-cache)
      PURGE_CACHE="1"
      shift
      ;;
    --update)
      UPDATE_MODE="1"
      if [[ $# -gt 1 && "${2:-}" != "" && ! "${2:-}" =~ ^- ]]; then
        UPDATE_TAG="$2"
        shift 2
        continue
      fi
      shift
      ;;
    --uninstall)
      UNINSTALL_MODE="1"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      VENV_DIR="$1"
      shift
      ;;
  esac
done

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  if [[ "$DEMO_MODE" == "1" || "$PRODUCTION_MODE" == "1" || "$PNM_FILE_RETRIEVAL_SETUP" == "1" || "$DEVELOPMENT_MODE" == "1" || "$CLEAN_MODE" == "1" || "$PURGE_CACHE" == "1" || "$UPDATE_MODE" == "1" ]]; then
    echo "❌ --uninstall cannot be combined with other flags."
    usage
    exit 1
  fi
fi

if [[ "$UPDATE_MODE" == "1" ]]; then
  if [[ "$DEMO_MODE" == "1" || "$PRODUCTION_MODE" == "1" || "$PNM_FILE_RETRIEVAL_SETUP" == "1" || "$DEVELOPMENT_MODE" == "1" || "$CLEAN_MODE" == "1" || "$PURGE_CACHE" == "1" || "$UNINSTALL_MODE" == "1" || "$VENV_DIR" != ".env" ]]; then
    echo "❌ --update cannot be combined with install/uninstall or venv options."
    usage
    exit 1
  fi
fi

if [[ "$DEMO_MODE" == "1" && "$PRODUCTION_MODE" == "1" ]]; then
  echo "❌ Cannot use --demo-mode and --production together."
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

run_docker_update() {
  local update_script="${PROJECT_ROOT}/scripts/update-pypnm-docker-container.sh"

  if [[ ! -x "${update_script}" ]]; then
    echo "❌ Missing update helper: ${update_script}"
    exit 1
  fi

  echo "🔄 Updating PyPNM Docker deployment..."
  if [[ -n "${UPDATE_TAG}" ]]; then
    "${update_script}" "${UPDATE_TAG}"
  else
    "${update_script}"
  fi
}

if [[ "$UNINSTALL_MODE" == "1" ]]; then
  uninstall_pypnm
  exit 0
fi

if [[ "$UPDATE_MODE" == "1" ]]; then
  run_docker_update
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

if ! command -v zstd >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'zstd'."
  else
    echo "🔧 Installing zstd..."
    case "$PM" in
      apt-get) $PM_INSTALL zstd ;;
      dnf|yum) $PM_INSTALL zstd ;;
      zypper)  $PM_INSTALL zstd ;;
      apk)     $PM_INSTALL zstd ;;
      brew)    $PM_INSTALL zstd ;;
    esac
  fi
fi

if ! command -v gzip >/dev/null 2>&1; then
  if [[ "$PM" == "none" ]]; then
    echo "⚠️  No package manager; cannot auto-install 'gzip'."
  else
    echo "🔧 Installing gzip..."
    case "$PM" in
      apt-get) $PM_INSTALL gzip ;;
      dnf|yum) $PM_INSTALL gzip ;;
      zypper)  $PM_INSTALL gzip ;;
      apk)     $PM_INSTALL gzip ;;
      brew)    $PM_INSTALL gzip ;;
    esac
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
  if [[ "$PM" == "brew" ]]; then
    echo "⚠️  macOS does not support the Docker/kind bootstrap in this script."
    echo "    Skipping Docker/kind install; running gitleaks setup only."
    install_gitleaks
  else
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

run_tftp_server_setup_offer_if_possible() {
  if [[ ! -t 0 || -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "ℹ️  Skipping local TFTP server setup offer (non-interactive or CI environment)."
    echo "    You can run it later with:"
    echo "      ./scripts/setup_tftp_server.sh"
    return
  fi

  if [[ ! -x "${PROJECT_ROOT}/scripts/setup_tftp_server.sh" ]]; then
    echo "ℹ️  scripts/setup_tftp_server.sh is missing or not executable."
    echo "    Run it later once available:"
    echo "      ./scripts/setup_tftp_server.sh"
    return
  fi

  echo
  read -r -p "Offer local tftpd-hpa upload setup now? [y/N]: " setup_tftp_answer || true
  case "${setup_tftp_answer:-N}" in
    y|Y|yes|YES)
      "${PROJECT_ROOT}/scripts/setup_tftp_server.sh"
      ;;
    *)
      echo "ℹ️  Skipping local TFTP server setup."
      echo "    You can run it later with:"
      echo "      ./scripts/setup_tftp_server.sh"
      ;;
  esac
}

run_pnm_alias_installer_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/install_aliases.sh" ]]; then
    echo "🔗 Installing PyPNM shell aliases (e.g., config-menu)…"
    "${PROJECT_ROOT}/scripts/install_aliases.sh" || true
  fi
}

run_with_privilege_if_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return $?
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@"
    return $?
  fi
  return 1
}

ensure_pypnm_shared_group() {
  local target_user
  target_user="${SUDO_USER:-${USER:-$(id -un)}}"

  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ℹ️  Skipping '${PYPNM_SHARED_GROUP}' group setup on non-Linux host."
    return
  fi

  if getent group "${PYPNM_SHARED_GROUP}" >/dev/null 2>&1; then
    echo "👥 Group '${PYPNM_SHARED_GROUP}' already exists."
  else
    if run_with_privilege_if_needed groupadd "${PYPNM_SHARED_GROUP}"; then
      echo "👥 Created group '${PYPNM_SHARED_GROUP}'."
    else
      echo "⚠️  Unable to create group '${PYPNM_SHARED_GROUP}'."
      return
    fi
  fi

  if id -nG "${target_user}" 2>/dev/null | tr ' ' '\n' | grep -qx "${PYPNM_SHARED_GROUP}"; then
    echo "👤 User '${target_user}' is already in group '${PYPNM_SHARED_GROUP}'."
    return
  fi

  if run_with_privilege_if_needed usermod -aG "${PYPNM_SHARED_GROUP}" "${target_user}"; then
    echo "👤 Added user '${target_user}' to group '${PYPNM_SHARED_GROUP}'."
    GROUP_MEMBERSHIP_CHANGED="1"
  else
    echo "⚠️  Unable to add user '${target_user}' to group '${PYPNM_SHARED_GROUP}'."
  fi
}

ensure_tmp_pypnm_permissions() {
  local tmp_root="/tmp/pypnm"

  mkdir -p "${tmp_root}" || {
    echo "⚠️  Unable to create ${tmp_root}."
    return
  }

  if chgrp "${PYPNM_SHARED_GROUP}" "${tmp_root}" >/dev/null 2>&1 || run_with_privilege_if_needed chgrp "${PYPNM_SHARED_GROUP}" "${tmp_root}" >/dev/null 2>&1; then
    :
  else
    echo "⚠️  Unable to set group '${PYPNM_SHARED_GROUP}' on ${tmp_root}."
  fi

  if chmod 2775 "${tmp_root}" >/dev/null 2>&1 || run_with_privilege_if_needed chmod 2775 "${tmp_root}" >/dev/null 2>&1; then
    echo "📁 Ensured ${tmp_root} exists with group '${PYPNM_SHARED_GROUP}' and permissions 2775."
  else
    echo "⚠️  Unable to set permissions 2775 on ${tmp_root}."
  fi
}

run_tmp_cleanup_cron_installer_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/install-tmp-cleanup-cron.sh" ]]; then
    echo "🧹 Installing tmp cache cleanup cron job..."
    "${PROJECT_ROOT}/scripts/install-tmp-cleanup-cron.sh" || true
  fi
}

seed_fastapi_worker_profile_if_available() {
  if [[ -x "${PROJECT_ROOT}/scripts/seed-fastapi-worker-profile.py" ]]; then
    echo "⚙️  Seeding FastAPI worker profile from host CPU and RAM..."
    "${PROJECT_ROOT}/scripts/seed-fastapi-worker-profile.py" || true
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

run_tftp_server_setup_offer_if_possible

ensure_pypnm_shared_group
ensure_tmp_pypnm_permissions
run_pnm_alias_installer_if_available
run_tmp_cleanup_cron_installer_if_available
seed_fastapi_worker_profile_if_available

echo "✅ Bootstrap complete."
if [[ "$DEMO_MODE" == "1" ]]; then
  echo "👉 Demo mode is enabled: system settings now reference the demo/ directories."
fi
if [[ "$PRODUCTION_MODE" == "1" ]]; then
  echo "👉 Production mode is restored: system settings have been reverted from backup."
fi
if [[ "${GROUP_MEMBERSHIP_CHANGED}" == "1" ]]; then
  echo "👉 Group membership changed for '${SUDO_USER:-${USER:-$(id -un)}}'. Start a new login session for group changes to take effect."
fi
echo "👉 Next steps:"
echo "   1) source '$VENV_DIR/bin/activate'"
echo "   2) (optional) ./tools/pnm/pnm_file_retrieval_setup.py"
echo "   3) ./scripts/start-fastapi-service.sh"
echo "   4) mkdocs serve"
