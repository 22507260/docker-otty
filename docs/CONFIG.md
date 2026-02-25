# Config Guide

`docker-otty` reads configuration from `config.yaml` by default.

## Reference
| Key | Type | Required | Default Behavior | Description |
|---|---|---|---|---|
| `trivy_url` | string | yes | none | Trivy source. Can be a local ZIP path or remote release URL. |
| `scan_images` | list[string] | no | empty list | Static image list used by `multi` and `daemon`. |
| `scan_installed_containers` | bool | no | `false` | Include image names discovered via `docker ps -a`. |
| `scan_running_containers` | bool | no | `false` | Include image names discovered via `docker ps`. |
| `interval` | int | no | `3600` | Daemon scan interval in seconds. |
| `output_dir` | string | no | current directory | Output directory for reports. |

## Example
```yaml
trivy_url: "./trivy_0.69.1_windows-64bit.zip"
scan_images:
  - "nginx:latest"
  - "alpine:3.18"
scan_installed_containers: false
scan_running_containers: true
interval: 1800
output_dir: "./scan-results"
```

## Selection Behavior
- `run`: scans only the image provided in CLI.
- `multi`: combines CLI images, `scan_images`, and optionally container-discovered images.
- `daemon`: uses `scan_images` and optionally container-discovered images every cycle.

## Validation Rules
- Image names are validated before scanning.
- Duplicate image names are automatically removed.
- Invalid image entries are skipped (daemon) or cause errors (run/multi normalization path).
