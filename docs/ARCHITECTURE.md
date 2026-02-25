# Architecture Overview

`docker-otty` is a Go-based Docker CLI plugin that orchestrates Trivy scans and emits user-friendly reports.

## High-Level Flow
1. Parse global and command-specific flags.
2. Load `config.yaml` (or custom path).
3. Ensure Trivy binary exists (download or local ZIP extraction).
4. Build the scan target list (CLI images, config images, optional container discovery).
5. Execute Trivy scan(s) with timeout and scanner options.
6. Parse JSON output and derive:
   - severity totals
   - risk explanations
   - CI gate status
7. Write timestamped report files.

## Main Components
- `main.go`
  - command routing (`run`, `multi`, `daemon`)
  - target selection and orchestration
  - report generation and CI gating
- `config/config.go`
  - YAML config model and loader
- `trivy/trivy.go`
  - Trivy binary preparation logic
- `main_test.go`
  - parsing and analysis unit tests

## Scan Target Sources
- Explicit CLI image names
- `scan_images` from config
- Installed container images (`docker ps -a`) via `--containers`
- Running container images (`docker ps`) via `--running-containers`

## Output Model
- Per-image report files (`txt`, `json`, or `md`)
- `multi` summary artifact: `summary-YYYYMMDD-HHMMSS.json`

## Operational Modes
- `run`: one image, one report
- `multi`: many images, optional parallel workers
- `daemon`: repeated cycles at configured interval
