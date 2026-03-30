# PyPNM CLI

The `pypnm` command is the primary CLI entrypoint for PyPNM.

Current command structure:

- `pypnm serve` for starting the FastAPI service
- `pypnm config-menu` for launching the interactive system configuration menu

## Usage

```bash
pypnm --help
```

Expected top-level shape:

```text
usage: pypnm [-h] [-v] {serve,config-menu} ...
```

## Commands

### `pypnm serve`

Starts the FastAPI service (`pypnm.api.main:app`) through Uvicorn.

Common options:

- `--host` (default `127.0.0.1`)
- `--port` (default `8000`)
- `--ssl`, `--cert`, `--key`
- `--log-level {critical,error,warning,info,debug,trace}`
- `--workers`
- `--limit-max-requests`
- `--no-access-log`
- `--reload`
- `--reload-dir` (repeatable)
- `--reload-include` (repeatable)
- `--reload-exclude` (repeatable)
- `--mute-tags`
- `--mute-tags-hard`

Examples:

```bash
pypnm serve
pypnm serve --host 0.0.0.0 --port 8080
pypnm serve --reload
pypnm serve --workers 4 --limit-max-requests 2000
pypnm serve --ssl --cert ./certs/cert.pem --key ./certs/key.pem
pypnm serve --mute-tags "PNM Operations - Multi-Downstream OFDM RxMER"
pypnm serve --mute-tags "Orchestrator,Operational" --mute-tags-hard
```

Notes:

- When `--reload` is enabled, `--workers` is forced to `1`.
- `--limit-max-requests` passes Uvicorn's worker recycle threshold through to the serve runtime.
- For production memory safety, prefer multiple workers with a non-zero `--limit-max-requests` instead of `--reload`.
- `--mute-tags` hides matching-tag routes from OpenAPI/docs.
- `--mute-tags-hard` additionally enforces `403` for matching routes.

### `pypnm config-menu`

Launches the interactive system configuration menu (same behavior as the legacy helper script).

Example:

```bash
pypnm config-menu
```

## Version

```bash
pypnm --version
```

## Migration from old syntax

Old:

```bash
pypnm --reload
pypnm --host 0.0.0.0 --port 8000
```

New:

```bash
pypnm serve --reload
pypnm serve --host 0.0.0.0 --port 8000
```
