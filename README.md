
# docker-otty

<p align="center">
  <img src="assets/logo.png" alt="docker-otty logo" width="300" />
</p>

<p align="center">
  <b>Docker CLI plugin for Trivy-based container image security scanning</b>
</p>

<p align="center">
  <a href="https://github.com/22507260/docker-otty/actions/workflows/ci.yml"><img src="https://github.com/22507260/docker-otty/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://github.com/22507260/docker-otty/releases"><img src="https://img.shields.io/github/v/release/22507260/docker-otty?include_prereleases&label=release" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/22507260/docker-otty" alt="License"></a>
  <a href="https://github.com/22507260/docker-otty/stargazers"><img src="https://img.shields.io/github/stars/22507260/docker-otty?style=social" alt="GitHub stars"></a>
</p>

<p align="center">
  <a href="CHANGELOG.md">Changelog</a> |
  <a href="docs/USAGE.md">Usage Guide</a> |
  <a href="docs/CONFIG.md">Config Guide</a> |
  <a href="CONTRIBUTING.md">Contributing</a> |
  <a href="CODE_OF_CONDUCT.md">Code of Conduct</a>
</p>

## Why docker-otty?

- 🚀 Runs as a native Docker CLI plugin: `docker otty ...`
- 📄 Produces practical reports in `txt`, `json`, or `md`
- 🏃 Supports single, multi-image, and daemon scan modes
- ✅ Adds CI gate controls for fail-fast pipelines
- 🔍 Can scan explicit image lists, installed container images, and running container images
## Project Demo

<p align="center">
  <img src="assets/logo.png" alt="docker-otty demo" width="300" />
</p>

<!-- Ekran görüntüsü veya kısa bir terminal demosu ekleyebilirsiniz. -->
## Project Links & Community

- [Contribution Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Open Issues](https://github.com/22507260/docker-otty/issues)
- [Discussions](https://github.com/22507260/docker-otty/discussions)
## Social & Promotion

- Projeyi [Twitter](https://twitter.com/) ve [LinkedIn](https://www.linkedin.com/) gibi platformlarda paylaşın.
- Open source topluluklarına ve forumlara tanıtın.
- Awesome list ve trending repo başvurusu yapın.

> Daha fazla katkı ve yıldız için repoyu paylaşmayı unutmayın!

## Quick Start
### Prerequisites
- Docker CLI installed and working
- Go `1.20+` (only needed when building from source)

### Build
```powershell
go build -o docker-otty.exe .
```

### Install as Docker CLI plugin (Windows)
```powershell
New-Item -ItemType Directory -Force "$HOME\.docker\cli-plugins" | Out-Null
Copy-Item .\docker-otty.exe "$HOME\.docker\cli-plugins\docker-otty.exe" -Force
```

### Install as Docker CLI plugin (Linux/macOS)
```bash
go build -o docker-otty .
mkdir -p ~/.docker/cli-plugins
cp ./docker-otty ~/.docker/cli-plugins/docker-otty
chmod +x ~/.docker/cli-plugins/docker-otty
```

### Verify
```bash
docker otty help
docker otty version
```

## Command Overview
| Command | Purpose | Typical Usage |
|---|---|---|
| `run` | Scan one image once | `docker otty run nginx:latest` |
| `multi` | Scan many images in one execution (parallel capable) | `docker otty multi --images nginx:latest,alpine:3.18 --workers 4` |
| `daemon` | Repeated periodic scanning | `docker otty daemon --interval 3600` |
| `help` | Show all command help | `docker otty help` |
| `version` | Show plugin version | `docker otty version` |

## Core Examples
### Single image scan
```bash
docker otty run nginx:latest --format json --top 10
```

### Multi scan with CI gating
```bash
docker otty multi --images nginx:latest,alpine:3.18 --workers 4 --fail-on high --exit-code 9
```

### Scan installed container images (`docker ps -a`)
```bash
docker otty multi --containers
```

### Scan only running container images (`docker ps`)
```bash
docker otty multi --running-containers
```

### Daemon mode one cycle
```bash
docker otty daemon --running-containers --once
```

## Configuration
Sample [`config.yaml`](config.yaml):

```yaml
trivy_url: "./trivy_0.69.1_windows-64bit.zip"
scan_images:
  - "nginx:latest"
  - "alpine:3.18"
scan_installed_containers: false
scan_running_containers: false
interval: 3600
output_dir: "./scan-results"
```

Config field details are documented in [`docs/CONFIG.md`](docs/CONFIG.md).

## Reports
- `run`: one timestamped report file
- `multi`: one report per target image and one `summary-YYYYMMDD-HHMMSS.json`
- `daemon`: one timestamped report per scan target per cycle
- Format options: `txt`, `json`, `md`

## CI/CD Notes
CI gate flags:
- `--fail-on high|critical|none`
- `--max-medium <n>`
- `--exit-code <n>`
- Use `--no-input` for non-interactive environments

## Documentation
- Usage details: [`docs/USAGE.md`](docs/USAGE.md)
- Config details: [`docs/CONFIG.md`](docs/CONFIG.md)
- Architecture overview: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- GitHub setup checklist: [`docs/GITHUB_SETUP.md`](docs/GITHUB_SETUP.md)
- Release process: [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md)
- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Security policy: [`SECURITY.md`](SECURITY.md)

## GitHub Automation
- CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
- Release: [`.github/workflows/release.yml`](.github/workflows/release.yml)

## License
MIT - see [`LICENSE`](LICENSE).
