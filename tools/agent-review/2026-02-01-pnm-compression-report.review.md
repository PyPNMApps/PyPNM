## Agent Review Bundle Summary
- Goal: Add average compression savings (bytes) to PNM compression report.
- Changes: Updated report table to include average savings per codec in bytes.
- Files: tools/reports/pnm-compression-2026-02-01.md.
- Tests: mkdocs build -s.
- Notes: lz4 computed with Python lz4 module in .env.

# FILE: tools/reports/pnm-compression-2026-02-01.md
# PNM Compression Comparison

Source directory: `/home/dev01/Projects/PyPNM/.data/pnm`

Compression ratio = compressed size / original size.

Notes:
- zstd available: yes
- gzip available: yes
- lz4 available: yes

| PNM type | Files | Avg size (bytes) | Avg zstd ratio | Avg zstd savings (bytes) | Avg gzip ratio | Avg gzip savings (bytes) | Avg lz4 ratio | Avg lz4 savings (bytes) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ds_ofdm_chan_est_coef | 137 | 30428 | 0.953 | 1436 | 0.954 | 1406 | 1.001 | -23 |
| ds_ofdm_codeword_error_rate | 6 | 38427 | 0.112 | 34118 | 0.149 | 32694 | 0.273 | 27942 |
| ds_ofdm_modulation_profile | 2 | 1418 | 0.159 | 1193 | 0.179 | 1164 | 0.241 | 1076 |
| ds_ofdm_rxmer_per_subcar | 140 | 7628 | 0.550 | 3431 | 0.586 | 3159 | 0.960 | 304 |
| us_pre_equalizer_coef | 159 | 7138 | 0.774 | 1614 | 0.711 | 2065 | 0.927 | 518 |

Download: `tools/reports/pnm-compression-2026-02-01.md`
