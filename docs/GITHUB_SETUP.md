# GitHub Repository Setup Checklist

Use this checklist when creating the public repository.

## 1. Repository Basics
- Repository name: `docker-otty`
- Description: `Docker CLI plugin for Trivy-based container image security scanning`
- Visibility: Public
- Default branch: `main`

## 2. Visual Presentation
- Upload social preview image (you can use `assets/logo.png`).
- Pin the repository in your GitHub profile.
- Add topics:
  - `docker`
  - `docker-plugin`
  - `trivy`
  - `security`
  - `container-security`
  - `golang`

## 3. Recommended Repo Settings
- Enable Issues
- Enable Discussions (optional but useful)
- Enable Projects (optional)
- Enable Wiki (optional)

## 4. Branch Protection
- Protect `main`:
  - Require pull request before merge
  - Require status checks (CI workflow)
  - Require linear history (optional)

## 5. Security Settings
- Enable Dependabot alerts
- Enable secret scanning (if available for your plan)
- Configure private vulnerability reporting

## 6. Initial Push Flow
```bash
git init
git add .
git commit -m "initial repository setup"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## 7. First Release Flow
```bash
git tag v1.0.0
git push origin v1.0.0
```

Release workflow will build artifacts and publish GitHub Release assets.
