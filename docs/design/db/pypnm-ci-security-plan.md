# CI Security Scanning Plan (Deferred Until End Of DB Conversion)

This document captures a pragmatic, no-cost CI security scanning baseline for PyPNM that approximates “Black Duck–style” coverage using free tooling. The intent is to implement this after the DB conversion is complete.

## Goals

- Catch common security defects in source (SAST).
- Detect vulnerable dependencies early (SCA).
- Prevent credential/secret leakage.
- Improve supply-chain hygiene and repo hardening.
- Optionally scan container images (if/when images are published).

## Recommended Coverage Map

| Category | Primary Tooling | CI Trigger | Notes |
|---|---|---|---|
| SAST (static analysis) | GitHub CodeQL | main + schedule | Publishes alerts to GitHub Security tab. |
| Dependency vulnerabilities (Python) | pip-audit | PR + main | Fast, Python-focused SCA. |
| Dependency vulnerabilities (cross-ecosystem) | OSV-Scanner | PR + main | Optional “second signal” for OSV parity. |
| Secrets detection | GitHub Secret Scanning + Push Protection; Gitleaks | PR + main | GitHub provides platform-native coverage; Gitleaks adds repo parity and custom patterns. |
| Supply-chain posture | OpenSSF Scorecard | schedule | Repo hardening checks (permissions, pinning, etc.). |
| Container/image CVEs (optional) | Trivy | main + schedule | Only if images are built/published. |

## GitHub-Native Security (Free For Public Repositories)

Enable these in repo settings (or org-wide defaults where available):

- Code scanning (CodeQL)
- Secret scanning + push protection
- Dependency graph + Dependabot alerts + security updates
- Dependency review (PR gate)
- SBOM export (from dependency graph)

## CI Execution Plan

### Pull Request Gates (Fast)

Run on every PR and mark as required checks:

1) Dependency review (blocks newly introduced vulnerable dependency changes)
2) pip-audit (Python dependency CVEs)
3) Gitleaks (secrets in diff plus full-repo scanning)

Optional:
- OSV-Scanner (additional feed)

### Main Branch + Scheduled (Deeper)

Run on main and on a weekly schedule:

1) CodeQL (SAST; SARIF upload to Security tab)
2) OpenSSF Scorecard (supply-chain posture; SARIF upload)
3) Trivy (container/image scan) only if/when you build images

## Drop-In GitHub Actions Workflow (Starter)

Place this at `.github/workflows/security.yml`. Adjust Python version and schedule as needed.

```yaml
name: security

on:
  pull_request:
  push:
    branches: [ "main" ]
  schedule:
    - cron: "0 9 * * 1"   # Mondays 09:00 UTC

permissions:
  contents: read

jobs:
  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4

  pip-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: pip-audit
        uses: pypa/gh-action-pip-audit@v1

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  codeql:
    if: github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/analyze@v3

  scorecard:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Enforcement And Policy

- Add branch protection rules requiring the PR gate jobs (dependency review, pip-audit, gitleaks) to pass before merge.
- Consider failing builds on:
  - any HIGH/CRITICAL dependency finding, or
  - any secret detection finding.
- Keep the “deep scans” (CodeQL/Scorecard/Trivy) on main/schedule to avoid PR latency.

## PyPNM-Specific Considerations

- PyPNM interacts with SNMP/TFTP/DSNs and may eventually include remote retrieval credentials. Prioritize secret scanning/push protection and Gitleaks early.
- If adding Postgres CI service containers later, keep security workflows separate so they remain fast and deterministic.
- If/when container images are produced (DockerHub/GHCR), add Trivy image scanning as a follow-on step.

## Deferred Implementation Checklist (End Of DB Conversion)

- [ ] Enable GitHub security features: CodeQL, secret scanning + push protection, Dependabot alerts/updates, dependency review.
- [ ] Add `.github/workflows/security.yml` (starter above).
- [ ] Add branch protection: require PR gate checks.
- [ ] Optionally add OSV-Scanner for a second vulnerability feed.
- [ ] Decide whether container scanning (Trivy) is needed now or later.
