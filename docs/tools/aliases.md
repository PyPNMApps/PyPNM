# Aliases

PyPNM provides optional shell aliases to speed up common workflows. These are
installed via the repo script and should be kept in sync with
`scripts/install_aliases.sh`.

## Install aliases

From the repo root:

```bash
./scripts/install_aliases.sh
```

Reload your shell config (for example `source ~/.bashrc`) to activate them.

## Alias list

| Alias | Command | Notes |
| --- | --- | --- |
| `config-menu` | `python tools/system_config/menu.py` | Launches the system config menu. |
| `pypnm-release` | `python tools/release/release.py` | Release flow; see `docs/release/release-strategy.md` for options. |
| `pypnm-release-hot-fix` | `python tools/release/release.py --branch hot-fix --next build` | Hot-fix release flow with build bump. |
| `pypnm-clean` | `./tools/maintenance/clean.sh` | Cleanup helper; see `docs/tools/pypnm-clean.md` for options. |
| `pypnm-support-bundle` | `python tools/build/support_bundle_builder.py` | Support bundle; see `docs/issues/support-bundle.md`. |
| `pypnm-mac-update` | `python tools/pnm/pnm-mac-updater.py` | MAC updater; see `docs/tools/pnm-file-macaddress-updater.md`. |
| `pypnm-version-check` | `python tools/release/check_version.py` | Verifies `version.py` and `pyproject.toml` versions match. |

## Update policy

When adding or moving tools, update this page and `scripts/install_aliases.sh`
to keep aliases and options consistent.
