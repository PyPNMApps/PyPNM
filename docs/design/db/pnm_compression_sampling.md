<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 Maurice Garcia -->

# PNM Compression Sampling

This note captures a 10-file random sample from `tests/files` and records size savings plus single-run compress/decompress time per algorithm.

## Per-File Results

| File | Orig (B) | gzip (B, %, c_ms, d_ms) | bzip2 (B, %, c_ms, d_ms) | xz (B, %, c_ms, d_ms) | zstd (B, %, c_ms, d_ms) |
|---|---:|---:|---:|---:|---:|
| rxmer.bin | 7508 | 4388, 41.6%, 1.06, 0.78 | 4171, 44.4%, 1.74, 1.14 | 4436, 40.9%, 3.64, 1.33 | 4098, 45.4%, 1.32, 0.97 |
| us_pre_equalizer_coef_last.bin | 7138 | 4960, 30.5%, 1.03, 0.86 | 4847, 32.1%, 2.01, 1.17 | 4244, 40.5%, 3.98, 1.53 | 5885, 17.6%, 1.31, 1.02 |
| histogram.bin | 1053 | 615, 41.6%, 0.93, 0.81 | 768, 27.1%, 1.07, 0.86 | 616, 41.5%, 2.42, 1.02 | 580, 44.9%, 1.39, 1.08 |
| channel_estimation.bin | 29948 | 28652, 4.3%, 1.49, 1.01 | 28213, 5.8%, 4.44, 2.41 | 28080, 6.2%, 7.90, 2.80 | 28626, 4.4%, 1.37, 1.09 |
| spectrum_analyzer_snmp.bin | 42020 | 25855, 38.5%, 1.83, 1.12 | 19334, 54.0%, 4.72, 2.46 | 22992, 45.3%, 7.51, 2.54 | 28824, 31.4%, 1.69, 1.34 |
| const_display.bin | 32798 | 26229, 20.0%, 1.99, 1.12 | 22953, 30.0%, 3.86, 2.48 | 26428, 19.4%, 7.28, 2.81 | 26117, 20.4%, 1.46, 1.17 |
| us_pre_equalizer_coef.bin | 7138 | 6748, 5.5%, 0.97, 0.95 | 7002, 1.9%, 2.21, 1.25 | 6564, 8.0%, 3.89, 1.51 | 6797, 4.8%, 1.30, 1.01 |
| spectrum_analyzer.bin | 41511 | 28142, 32.2%, 1.97, 1.18 | 20450, 50.7%, 4.18, 2.21 | 25244, 39.2%, 7.47, 2.88 | 31838, 23.3%, 1.41, 1.23 |
| modulation_profile.bin | 1881 | 259, 86.2%, 0.89, 0.73 | 243, 87.1%, 1.00, 0.83 | 244, 87.0%, 1.70, 1.05 | 210, 88.8%, 1.29, 0.99 |
| fec_summary.bin | 48030 | 7532, 84.3%, 1.32, 0.99 | 4150, 91.4%, 3.22, 1.46 | 2708, 94.4%, 3.74, 1.25 | 4401, 90.8%, 1.33, 1.17 |

## Averages

| Algo | Avg savings | Avg comp (ms) | Avg decomp (ms) |
|---|---:|---:|---:|
| gzip | 38.5% | 1.35 | 0.96 |
| bzip2 | 42.4% | 2.84 | 1.63 |
| xz | 42.3% | 4.95 | 1.87 |
| zstd | 37.2% | 1.39 | 1.11 |

## Script Used

```python
import json
import random
import shutil
import subprocess
import time
from pathlib import Path

def tool_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run_with_output(cmd: list[str], data: bytes) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return proc.returncode, proc.stdout, proc.stderr

def compress(algo: str, data: bytes) -> tuple[bytes, float]:
    start = time.perf_counter()
    if algo == "gzip":
        rc, out, _ = run_with_output(["gzip", "-c", "-1"], data)
    elif algo == "bzip2":
        rc, out, _ = run_with_output(["bzip2", "-c", "-1"], data)
    elif algo == "xz":
        rc, out, _ = run_with_output(["xz", "-c", "-1"], data)
    elif algo == "zstd":
        rc, out, _ = run_with_output(["zstd", "-c", "-1"], data)
    else:
        raise ValueError(f"unsupported algo: {algo}")
    if rc != 0:
        raise RuntimeError(f"{algo} failed")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return out, elapsed_ms

def decompress(algo: str, data: bytes) -> tuple[bytes, float]:
    start = time.perf_counter()
    if algo == "gzip":
        rc, out, _ = run_with_output(["gzip", "-dc"], data)
    elif algo == "bzip2":
        rc, out, _ = run_with_output(["bzip2", "-dc"], data)
    elif algo == "xz":
        rc, out, _ = run_with_output(["xz", "-dc"], data)
    elif algo == "zstd":
        rc, out, _ = run_with_output(["zstd", "-dc"], data)
    else:
        raise ValueError(f"unsupported algo: {algo}")
    if rc != 0:
        raise RuntimeError(f"{algo} decompress failed")
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return out, elapsed_ms

def main() -> None:
    base_dir = Path("/home/dev01/Projects/PyPNM/tests/files")
    files = [p for p in base_dir.iterdir() if p.is_file()]
    if len(files) < 10:
        raise RuntimeError("not enough files")

    random.seed(0xC0DEC0)
    sample = random.sample(files, 10)

    algos = ["gzip", "bzip2", "xz", "zstd"]
    algos = [a for a in algos if tool_exists(a)]

    rows = []
    for p in sample:
        data = p.read_bytes()
        row = {"file": p.name, "orig": len(data)}
        for algo in algos:
            comp, comp_ms = compress(algo, data)
            decomp, decomp_ms = decompress(algo, comp)
            if decomp != data:
                raise RuntimeError(f"roundtrip mismatch for {p.name} {algo}")
            row[algo] = len(comp)
            row[f"{algo}_c_ms"] = comp_ms
            row[f"{algo}_d_ms"] = decomp_ms
        rows.append(row)

    print(json.dumps({"algos": algos, "rows": rows}, indent=2))

if __name__ == "__main__":
    main()
```
