# Tools List

| Guide | Description |
|-------|-------------|
| [PyPNM MIB Compiler](pypnm-mib-compiler.md)                   | A utility to compile MIB files for use with PyPNM.    |
| [PNM File MacAddress Updater](pnm-file-macaddress-updater.md) | A utility to update MAC addresses in PNM files.       |
| [Clean](pypnm-clean.md)                                       | Clean utility                                         |
| [Release](../release/release-strategy.md)                     | A tool to manage and automate software versioning.    |
| [Git Save](git-save.md)                                       | Local save helper with post-commit build bump rules.  |
| [Local Container Build](local-container-build.md)             | Local Docker build + optional health check preflight. |
| [System Config Apply](system-config-apply.md)                 | Apply JSON config updates without prompts.            |
| [Local Kubernetes Smoke](local-kubernetes-smoke.md)           | Build/load kind and validate the /health endpoint.    |
| [Version Check](version-check.md)                             | Verifies version consistency between version files.   |
| [Aliases](aliases.md)                                         | Optional shell aliases for common tools.              |

## Tools layout

New tools should live in a category subdirectory under `tools/` (for example, `tools/pnm/`, `tools/snmp/`, `tools/build/`, `tools/local/`, `tools/maintenance/`, `tools/release/`, `tools/security/`). Avoid placing new scripts at the tools root.
