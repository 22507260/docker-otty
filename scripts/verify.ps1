Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $repoRoot

Write-Host "Formatting Go files..."
gofmt -w main.go main_test.go config\config.go trivy\trivy.go

Write-Host "Running tests..."
go test ./...

Write-Host "Building project..."
go build ./...

Write-Host "Verification completed successfully."
