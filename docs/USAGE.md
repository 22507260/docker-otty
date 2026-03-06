# Usage Guide

This guide covers day-to-day usage of `docker-otty`.

## Standalone GUI
`otty-gui` runs as a separate local application (not an extension).

```powershell
go build -o otty-gui.exe ./cmd/otty-gui
.\otty-gui.exe
```

Optional flags:

| Flag | Description |
|---|---|
| `--config <path>` | Config file path (default: `config.yaml`) |
| `--addr <host:port>` | HTTP listen address (default: `127.0.0.1:8787`) |
| `--no-open` | Do not auto-open the browser |

## Global Flags
| Flag | Description |
|---|---|
| `--yes`, `-y` | Auto-confirm prompts |
| `--no-input` | Disable interactive input |

## `run` Command
Scan one image.

```bash
docker otty run <image> [options]
```

### Options
| Option | Description |
|---|---|
| `--config <path>` | Config file path (default: `config.yaml`) |
| `--output <file>` | Output file path (timestamp appended) |
| `--format <txt|json|md>` | Report format |
| `--top <n>` | Number of top risk explanations |
| `--timeout <seconds>` | Trivy timeout per scan |
| `--scanners <csv>` | Trivy scanners (for example `vuln,misconfig`) |
| `--fail-on <high|critical|none>` | CI gate severity level |
| `--max-medium <n>` | CI gate medium threshold |
| `--baseline <report.json>` | Baseline report for new-finding comparison (`docker-otty json` or raw Trivy JSON) |
| `--fail-on-new <high|critical|none>` | New-finding CI gate severity level (requires `--baseline`) |
| `--max-new-medium <n>` | New-finding medium threshold (requires `--baseline`) |
| `--exit-code <n>` | Exit code when CI gate fails |

### Example
```bash
docker otty run nginx:latest --format md --top 10 --fail-on critical
docker otty run nginx:latest --format json --baseline ./scan-results/previous-run.json --fail-on-new high --max-new-medium 2
```

## `multi` Command
Scan multiple images in one execution.

```bash
docker otty multi [image1 image2 ...] [options]
```

### Options
| Option | Description |
|---|---|
| `--images <img1,img2>` | Comma-separated image list |
| `--containers`, `--container` | Include image names from `docker ps -a` |
| `--running-containers`, `--running-container` | Include image names from `docker ps` |
| `--workers <n>` | Parallel worker count |
| `--output-dir <dir>` | Output directory |
| `--config <path>` | Config file path |
| `--format <txt|json|md>` | Report format |
| `--top <n>` | Number of top risk explanations |
| `--timeout <seconds>` | Trivy timeout per image |
| `--scanners <csv>` | Trivy scanners |
| `--fail-on <high|critical|none>` | CI gate severity level |
| `--max-medium <n>` | CI gate medium threshold |
| `--baseline-dir <dir>` | Baseline report directory for per-image drift comparison |
| `--baseline-required` | Fail when an image baseline cannot be found or parsed |
| `--fail-on-new <high|critical|none>` | New-finding CI gate severity level (requires `--baseline-dir`) |
| `--max-new-medium <n>` | New-finding medium threshold (requires `--baseline-dir`) |
| `--exit-code <n>` | Exit code when CI gate fails |

### Examples
```bash
docker otty multi --images nginx:latest,alpine:3.18 --workers 4
docker otty multi --containers
docker otty multi --running-containers
docker otty multi --images nginx:latest,alpine:3.18 --baseline-dir ./scan-results --fail-on-new high --baseline-required --exit-code 9
```

## `daemon` Command
Run periodic scans.

```bash
docker otty daemon [options]
```

### Options
| Option | Description |
|---|---|
| `--interval <seconds>` | Scan cycle interval |
| `--config <path>` | Config file path |
| `--format <txt|json|md>` | Report format |
| `--top <n>` | Number of top risk explanations |
| `--timeout <seconds>` | Trivy timeout |
| `--scanners <csv>` | Trivy scanners |
| `--containers`, `--container` | Include image names from `docker ps -a` |
| `--running-containers`, `--running-container` | Include image names from `docker ps` |
| `--once` | Run one cycle and exit |

### Examples
```bash
docker otty daemon --interval 3600 --config config.yaml
docker otty daemon --running-containers --once
```

## `doctor` Command
Run environment and config diagnostics.

```bash
docker otty doctor [options]
```

### Options
| Option | Description |
|---|---|
| `--config <path>` | Config file path |
| `--format <txt|json>` | Doctor report output format |
| `--strict` | Treat warnings as failures (non-zero exit) |

### Examples
```bash
docker otty doctor
docker otty doctor --format json
docker otty doctor --strict
```

## Exit Codes
- `0`: success
- `1`: runtime error or CI gate violation default code
- `2`: argument/usage error
- custom value from `--exit-code` when CI gate fails

## Practical Tips
- Use `--no-input` in CI jobs.
- Use `--scanners vuln` when you need faster scans.
- Use `--running-containers` for quick operational checks.
- Use `--containers` for broader inventory checks including stopped containers.
