# Usage Guide

This guide covers day-to-day usage of `docker-otty`.

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
| `--exit-code <n>` | Exit code when CI gate fails |

### Example
```bash
docker otty run nginx:latest --format md --top 10 --fail-on critical
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
| `--exit-code <n>` | Exit code when CI gate fails |

### Examples
```bash
docker otty multi --images nginx:latest,alpine:3.18 --workers 4
docker otty multi --containers
docker otty multi --running-containers
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
