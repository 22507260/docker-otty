# Contributing

Thanks for contributing to `docker-otty`.

## Development Prerequisites
- Go `1.20+`
- Docker CLI
- PowerShell (for helper scripts on Windows)

## Local Setup
```powershell
git clone <your-fork-or-repo-url>
cd docker-otty
go test ./...
go build ./...
```

## Quality Check
Run the built-in verification script before opening a PR:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

## Change Scope Expectations
- Keep pull requests focused and small.
- Update docs when behavior or flags change.
- Add or update tests for functional changes.
- Update `CHANGELOG.md` under `Unreleased` for user-facing changes.

## Commit Message Style
Use clear, imperative commit titles, for example:
- `add running container discovery for daemon`
- `update README command reference`

## Pull Request Checklist
- [ ] Tests pass locally (`go test ./...`)
- [ ] Project builds (`go build ./...`)
- [ ] Docs and examples are updated
- [ ] Changelog entry added for user-facing changes
