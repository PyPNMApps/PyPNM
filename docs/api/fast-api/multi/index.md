# Multi-capture API index

Use these guides when you need periodic or scheduled captures (for example, hourly RxMER snapshots) along with downstream analysis.

> **Background**
> Read the [capture operation guide](capture-operation.md) first. It explains how capture operations, transactions, and storage hang together.

## Workflow at a glance

1. **Plan** - Decide whether you need multi-RxMER or multi-channel-estimation captures and confirm storage availability.
2. **Start** - Call the workflow-specific endpoint (for example, [multi-RxMER capture](multi-capture-rxmer.md)) with schedule, modem list, and retention options.
3. **Monitor** - Poll operation status and review logs via the [PyPNM system endpoints](../pypnm/index.md).
4. **Download** - Use the workflow guide or [file manager](../file-manager/file-manager-api.md) to grab ZIP archives once captures complete.
5. **Analyze** - Feed the captures into one of the advanced analysis modules listed below.

## Multi-capture workflows

| Workflow | Purpose |
|----------|---------|
| [Multi-RxMER capture](multi-capture-rxmer.md) | Periodic downstream OFDM RxMER sampling across multiple carriers. |
| [Multi-DS channel estimation](multi-capture-chan-est.md) | Scheduled OFDM channel estimation captures and reporting. |

## Advanced analysis modules

| Module | Purpose |
|--------|---------|
| [Multi-RxMER min/avg/max](analysis/multi-rxmer-min-avg-max.md) | Roll up RxMER across captures. |
| [Multi-ChanEst min/avg/max](analysis/multi-chanest-min-avg-max.md) | Summaries for channel estimation data. |
| [Group delay calculator](analysis/group-delay-calculator.md) | Compute group delay variations. |
| [OFDM performance 1:1](analysis/multi-rxmer-ofdm-performance-part-1.md) | Compare per-subcarrier capacity vs profile. |
| [OFDM echo detection](analysis/ofdm-echo-detection.md) | Detect reflections and echo artifacts. |
| [Phase slope LTE detection](analysis/phase-slope-lte-detection.md) | Spot LTE-related interference patterns. |
| [Signal statistics](analysis/signal-statistics.md) | Extract RMS/min/max variance from captures. |
- [Multi-Capture US OFDMA Pre-Equalization](multi-capture-us-ofdma-pre-eq.md)
