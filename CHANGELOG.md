# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- Installed container image discovery for `multi` and `daemon` via `--containers`.
- Config support for installed container discovery: `scan_installed_containers`.
- Running container image discovery for `multi` and `daemon` via `--running-containers`.
- Config support for running container discovery: `scan_running_containers`.
- GitHub issue forms for bug reports and feature requests.
- Pull request template, contribution guide, and security policy.
- Dedicated usage and configuration documentation under `docs/`.

### Changed
- README redesigned for GitHub presentation, onboarding, and command discovery.

## [1.0.0] - 2026-02-25

### Added
- `multi` command for scanning multiple images in one run.
- Parallel scanning for `multi` with `--workers`.
- Report format support for `txt`, `json`, `md` via `--format`.
- CI gate controls with `--fail-on`, `--max-medium`, `--exit-code`.
- Timestamped output names to avoid report overwrite.
- Human-readable Trivy risk explanations in terminal and reports.
- Multi-run summary report (`summary-YYYYMMDD-HHMMSS.json`).
- Release automation scripts and CI workflows.

### Changed
- Scan result summary terminology aligned to Trivy risk levels:
  - Critical/High Risk Finding Count
  - Medium/Low Risk Finding Count
  - Clean Target Count
- Plugin version bumped to `1.0.0`.

### Removed
- Non-Trivy malware scanner path; scanning is now Trivy-only.
