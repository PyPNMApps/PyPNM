# Health

Returns lightweight service health and runtime sizing details for the running
PyPNM API instance.

**GET** `/health`

## Purpose

Use this endpoint for:

- readiness and liveness checks
- verifying the running package version
- checking process uptime
- checking current resident memory usage
- monitoring `.data` growth by first-level directory

## Response Example

```json
{
  "status": "ok",
  "service": {
    "name": "pypnm-docsis",
    "version": "1.4.3.0"
  },
  "uptime": {
    "starttime": 1773640097,
    "uptime": 65
  },
  "memory": {
    "rss_bytes": 12582912,
    "total_bytes": 17179869184,
    "free_bytes": 8216707072,
    "available_bytes": 10379091968,
    "usage_percent": 0.07
  },
  "data": {
    "path": ".data",
    "size_bytes": 1761579619,
    "directories": {
      "json": 1728244816,
      "xlsx": 0,
      "pnm": 17349665,
      "csv": 2819493,
      "png": 2805111,
      "db": 3388387,
      "archive": 6968882,
      "msg_rsp": 3265
    }
  }
}
```

## Response Fields

| Field | Type | Description |
| --- | --- | --- |
| `status` | string | Top-level health status. Expected value is `ok` when the API is ready. |
| `service.name` | string | Package/service name loaded from `pyproject.toml`. |
| `service.version` | string | Running PyPNM version. |
| `uptime.starttime` | integer | Service start time as Unix epoch seconds. |
| `uptime.uptime` | integer | Elapsed uptime in whole seconds since `starttime`. |
| `memory.rss_bytes` | integer | Current resident memory used by the running PyPNM process, in bytes. |
| `memory.total_bytes` | integer | Total system memory on the current host, in bytes. |
| `memory.free_bytes` | integer | Free system memory on the current host, in bytes. |
| `memory.available_bytes` | integer | Available system memory on the current host, in bytes. |
| `memory.usage_percent` | number | Resident process memory as a percent of total system memory. |
| `data.path` | string | Runtime data root path. |
| `data.size_bytes` | integer | Recursive apparent size of the `.data` directory in bytes. |
| `data.directories` | object | Recursive apparent sizes for each first-level directory under `.data`. |

## Notes

- `memory.rss_bytes` is based on Linux resident set size (`VmRSS`).
- `memory.total_bytes` is based on Linux total memory (`MemTotal`).
- `memory.free_bytes` is based on Linux free memory (`MemFree`).
- `memory.available_bytes` is based on Linux available memory (`MemAvailable`).
- `memory.usage_percent` is computed as `rss_bytes / total_bytes * 100`.
- `data.size_bytes` is logical file size, not filesystem block allocation.
- `data.directories` helps identify which artifact classes are consuming disk.
- This endpoint is intended to stay lightweight and local to the running service.
