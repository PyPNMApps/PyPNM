# Tools List

| Guide | Description |
|-------|-------------|
| [PyPNM MIB Compiler](pypnm-mib-compiler.md)                   | A utility to compile MIB files for use with PyPNM.    |
| [PNM File MacAddress Updater](pnm-file-macaddress-updater.md) | A utility to update MAC addresses in PNM files.       |
| [Clean](pypnm-clean.md)                                       | Clean utility                                         |
| [Release](../release/release-strategy.md)                     | A tool to manage and automate software versioning.    |
| [Git Save](git-save.md)                                       | Local save helper with pre-commit build bump rules.   |
| [Local Container Build](local-container-build.md)             | Local Docker build + optional health check preflight. |
| [System Config Apply](system-config-apply.md)                 | Apply JSON config updates without prompts.            |
| [Local Kubernetes Smoke](local-kubernetes-smoke.md)           | Build/load kind and validate the /health endpoint.    |
| [Version Check](version-check.md)                             | Verifies version consistency between version files.   |
| [Aliases](aliases.md)                                         | Optional shell aliases for common tools.              |

## Tools layout

New tools should live in a category subdirectory under `tools/` (for example, `tools/pnm/`, `tools/snmp/`, `tools/build/`, `tools/local/`, `tools/maintenance/`, `tools/release/`, `tools/security/`). Avoid placing new scripts at the tools root.

## Maintenance

### tools/maintenance/kill-pypnm.py

Lists active `pypnm` processes in a numbered table and supports terminating by table line number.
This includes detached `pypnm serve --run-background` processes discovered from the runtime pidfile.

```bash
./tools/maintenance/kill-pypnm.py
```

```bash
./tools/maintenance/kill-pypnm.py --line 1 3
```

```bash
./tools/maintenance/kill-pypnm.py --all
```

Key options:
- `--line <n ...>` kill specific rows from the displayed table
- `--all` kill all active `pypnm` processes
- `--signal <TERM|KILL|INT|...>` choose signal (default `TERM`)

Display notes:
- If `tabulate` is installed, the script uses markdown-style table rendering
- If `tabulate` is not installed, the script falls back to plain fixed-width formatting
- The `SOURCE` column shows whether a row came from a live process scan or the detached serve pidfile
