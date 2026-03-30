# PyPNM Worker Sizing

PyPNM serves FastAPI through Uvicorn worker processes. For production, worker count should be based on both:

- available CPU cores
- available RAM

PyPNM analysis paths can be both CPU-heavy and memory-heavy, so choosing workers from CPU count alone can overcommit memory on smaller systems.

## Recommendation

For production installs, seed the initial `pypnm serve` defaults from the target host at install time using:

- logical CPU count
- total available memory

Then keep the values operator-overrideable at runtime.

PyPNM now ships a helper script for that purpose:

```bash
./scripts/seed-fastapi-worker-profile.py
```

By default, the helper writes `pypnm-serve.env` under the configured
`PnmFileRetrieval.runtime_dir` path from `system.json`.

The generated env file is consumed automatically by:

```bash
./scripts/start-fastapi-service.sh
```

This gives a good out-of-box default while still letting deployments adjust for:

- container CPU limits
- memory limits
- colocated services
- future hardware changes

## Sizing Rules

Recommended starting rules:

- `workers = min(4, cpu_count)`
- then reduce workers if memory is tight
- `limit-max-requests = 2000` as the default recycle safety valve
- use `limit-max-requests = 1000` on smaller systems or when investigating memory creep

## Hardware Scenarios

| Hardware Profile | CPU | RAM | Recommended Workers | Recommended `--limit-max-requests` | Notes |
|---|---:|---:|---:|---:|---|
| Small lab VM | 2 cores | 4 GB | 1 | 1000 | Safest low-memory baseline. |
| Small production node | 2 cores | 8 GB | 2 | 1000 | Good for light concurrent API usage. |
| Balanced node | 4 cores | 8 GB | 2 | 2000 | CPU allows 4, but memory is the limiter. |
| Standard production node | 4 cores | 16 GB | 4 | 2000 | Good default target for mixed API and analysis traffic. |
| Larger analysis node | 8 cores | 16 GB | 4 | 2000 | Keep workers capped to avoid per-worker memory pressure. |
| Larger production node | 8 cores | 32 GB | 4 | 2000 | Extra RAM helps absorb analysis spikes without needing more workers. |
| High-capacity node | 16+ cores | 64+ GB | 4-8 | 2000-4000 | Only raise above 4 when concurrency demand is proven. |

## Why Memory Matters

Each worker is a separate process with its own memory footprint.

That means:

- `4` workers can use roughly `4x` the memory of `1` worker under similar load
- heavy analysis requests can temporarily push a single worker much higher than idle baseline
- recycle limits help stop slow per-worker growth from becoming permanent

## Install-Time Defaulting

If the installer seeds defaults automatically, the logic should be conservative:

1. Detect CPU count.
2. Detect total memory.
3. Choose a worker count from the lower of:
   CPU-based target
   memory-based target
4. Write the suggested values into the install or service wrapper.
5. Keep CLI overrides available.

Suggested memory guardrails:

- under `6 GB` RAM: default to `1` worker
- `6-12 GB` RAM: default to at most `2` workers
- `12-24 GB` RAM: default to at most `4` workers
- above `24 GB` RAM: allow `4`, and only go higher when concurrency testing justifies it

## Example Commands

```bash
# Small node
pypnm serve --host 0.0.0.0 --port 8000 --workers 1 --limit-max-requests 1000

# Standard production node
pypnm serve --host 0.0.0.0 --port 8000 --workers 4 --limit-max-requests 2000

# Higher-capacity node with proven concurrency need
pypnm serve --host 0.0.0.0 --port 8000 --workers 6 --limit-max-requests 2000
```

## Practical Guidance

- Start conservatively.
- Watch RSS per worker under real analysis traffic.
- Increase workers only when you need more concurrency.
- Lower `limit-max-requests` if you see slow worker growth over time.
- Do not use `--reload` for production sizing decisions.
