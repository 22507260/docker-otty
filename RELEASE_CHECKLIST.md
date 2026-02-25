# Release Checklist

1. Update `VERSION`.
2. Update `CHANGELOG.md` with the release date and notes.
3. Verify locally:
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1`
4. Build release artifacts:
   - `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\release.ps1 -Version <version>`
5. Smoke test plugin:
   - `docker otty version`
   - `docker otty run alpine:latest --config config.yaml`
6. Tag and publish:
   - `git tag v<version>`
   - `git push origin v<version>`
7. Confirm GitHub release assets:
   - zipped binaries
   - `checksums.txt`
   - `README.md`, `CHANGELOG.md`, `LICENSE`, `VERSION`
