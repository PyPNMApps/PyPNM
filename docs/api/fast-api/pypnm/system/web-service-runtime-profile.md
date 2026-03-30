# PyPNM Web Service Runtime Profile

The PyPNM Web Service Runtime Profile endpoint exposes the worker sizing metadata used by the running FastAPI service.

This includes:

- the generated worker-profile env file path
- whether the profile file exists
- CPU and memory values detected when the profile was seeded
- seeded worker and recycle settings
- the active runtime values currently in use by the service
- whether those active values came from an explicit CLI choice or the seeded profile

## Endpoint

`GET /pypnm/system/webService/runtimeProfile`

## Example

```bash
curl -X GET "http://127.0.0.1:8000/pypnm/system/webService/runtimeProfile"
```

## Example Response

```json
{
  "status": "success",
  "profile": {
    "profile_env_path": ".data/runtime/pypnm-serve.env",
    "profile_exists": true,
    "detected_cpu_count": 8,
    "detected_total_memory_gib": 16.0,
    "seeded_workers": 4,
    "seeded_limit_max_requests": 2000,
    "active_workers": 4,
    "active_limit_max_requests": 2000,
    "active_source": "seeded_profile"
  }
}
```

## Notes

- This endpoint is intended for operators and deployment debugging.
- It complements `/health` without expanding the minimal public health contract.
- `active_source` is typically `seeded_profile` when launched through `./scripts/start-fastapi-service.sh` without explicit worker flags.
- `active_source` is typically `explicit_cli` when launched with direct `pypnm serve --workers ... --limit-max-requests ...` arguments.
