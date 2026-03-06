package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeReportFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default", input: "", want: "txt"},
		{name: "json", input: "json", want: "json"},
		{name: "uppercase", input: "MD", want: "md"},
		{name: "invalid", input: "xml", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeReportFormat(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "none", want: ""},
		{in: "high", want: "high"},
		{in: "critical", want: "critical"},
		{in: "LOW", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseFailOn(tc.in)
		if tc.wantErr && err == nil {
			t.Fatalf("parseFailOn(%q): expected error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("parseFailOn(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseFailOn(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseScanners(t *testing.T) {
	got, err := parseScanners("vuln, secret ,vuln,misconfig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "vuln,secret,misconfig" {
		t.Fatalf("got %q, want %q", got, "vuln,secret,misconfig")
	}

	if _, err := parseScanners(" , "); err == nil {
		t.Fatalf("expected error for empty scanner list")
	}
}

func TestRemediationCommandHint(t *testing.T) {
	cmd := remediationCommandHint(
		trivyResult{Type: "alpine", Target: "alpine:latest"},
		trivyFinding{PkgName: "openssl"},
	)
	if cmd == "" {
		t.Fatalf("expected non-empty command for alpine")
	}
}

func TestEvaluateCIGate(t *testing.T) {
	severity := severityCounts{Critical: 1, High: 2, Medium: 5}
	opts := ciGateOptions{FailOn: "high", MaxMedium: 4}
	violations := evaluateCIGate(severity, opts)
	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d: %v", len(violations), violations)
	}
}

func TestAnalyzeTrivyReport(t *testing.T) {
	report := trivyReport{
		Results: []trivyResult{
			{
				Vulnerabilities: []trivyFinding{
					{Severity: "HIGH"},
					{Severity: "MEDIUM"},
				},
			},
			{
				Vulnerabilities: nil,
				Secrets:         nil,
			},
		},
	}

	summary, severity := analyzeTrivyReport(report)

	if summary.DefiniteMalicious != 1 {
		t.Fatalf("DefiniteMalicious=%d, want 1", summary.DefiniteMalicious)
	}
	if summary.Suspicious != 1 {
		t.Fatalf("Suspicious=%d, want 1", summary.Suspicious)
	}
	if summary.Safe != 1 {
		t.Fatalf("Safe=%d, want 1", summary.Safe)
	}
	if severity.High != 1 || severity.Medium != 1 {
		t.Fatalf("unexpected severity breakdown: %+v", severity)
	}
}

func TestParseInstalledContainerImageOutput(t *testing.T) {
	raw := "nginx:latest\n<none>\n\nalpine:3.18\nnginx:latest\n<missing>\nredis@sha256:deadbeef\n"
	got := parseInstalledContainerImageOutput(raw)
	want := []string{"nginx:latest", "alpine:3.18", "redis@sha256:deadbeef"}

	if len(got) != len(want) {
		t.Fatalf("len(got)=%d, want %d. got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestIsValidImageNameDigest(t *testing.T) {
	if !isValidImageName("registry.local/app@sha256:deadbeef") {
		t.Fatalf("expected digest-form image name to be valid")
	}
	if isValidImageName("bad image") {
		t.Fatalf("expected image name with spaces to be invalid")
	}
}

func TestCompareNewFindings(t *testing.T) {
	baseline := trivyReport{
		Results: []trivyResult{
			{
				Target: "alpine:3.18",
				Vulnerabilities: []trivyFinding{
					{VulnerabilityID: "CVE-1111", PkgName: "openssl", Severity: "HIGH", InstalledVersion: "1.0.0"},
				},
			},
		},
	}
	current := trivyReport{
		Results: []trivyResult{
			{
				Target: "alpine:3.18",
				Vulnerabilities: []trivyFinding{
					{VulnerabilityID: "CVE-1111", PkgName: "openssl", Severity: "HIGH", InstalledVersion: "1.0.0"},
					{VulnerabilityID: "CVE-2222", PkgName: "musl", Severity: "CRITICAL", InstalledVersion: "2.0.0"},
				},
				Secrets: []trivyFinding{
					{ID: "SECRET-42", PkgName: "config", Severity: "MEDIUM"},
				},
			},
		},
	}

	severity, explanations, newCount := compareNewFindings(current, baseline, 5)
	if newCount != 2 {
		t.Fatalf("newCount=%d, want 2", newCount)
	}
	if severity.Critical != 1 || severity.Medium != 1 || severity.High != 0 {
		t.Fatalf("unexpected new-finding severity breakdown: %+v", severity)
	}
	if len(explanations) == 0 {
		t.Fatalf("expected at least one explanation")
	}
	if !strings.Contains(explanations[0], "CVE-2222") {
		t.Fatalf("expected critical finding to be listed first, got: %q", explanations[0])
	}
}

func TestLoadBaselineReportFromDockerOttyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	content := `{
  "image": "alpine:latest",
  "trivy_report": {
    "Results": [
      {
        "Target": "alpine:latest",
        "Vulnerabilities": [
          {"VulnerabilityID":"CVE-1234","PkgName":"apk-tools","Severity":"HIGH"}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write baseline file: %v", err)
	}

	report, err := loadBaselineReport(path)
	if err != nil {
		t.Fatalf("loadBaselineReport returned error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("len(report.Results)=%d, want 1", len(report.Results))
	}
}

func TestLoadBaselineReportFromRawTrivyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline-raw.json")
	content := `{
  "Results": [
    {
      "Target": "nginx:latest",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-9999","PkgName":"libssl","Severity":"CRITICAL"}
      ]
    }
  ]
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write baseline file: %v", err)
	}

	report, err := loadBaselineReport(path)
	if err != nil {
		t.Fatalf("loadBaselineReport returned error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("len(report.Results)=%d, want 1", len(report.Results))
	}
}

func TestFindLatestBaselineReportForImage(t *testing.T) {
	dir := t.TempDir()
	image := "nginx:latest"
	base := sanitizeScanFileName(image)

	oldPath := filepath.Join(dir, base+"-scan-20250101-010101.json")
	newPath := filepath.Join(dir, base+"-scan-20250101-020202.json")
	if err := os.WriteFile(oldPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write old baseline: %v", err)
	}
	if err := os.WriteFile(newPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write new baseline: %v", err)
	}

	oldTime := time.Now().Add(-2 * time.Hour)
	newTime := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("failed to set old baseline mod time: %v", err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatalf("failed to set new baseline mod time: %v", err)
	}

	got, err := findLatestBaselineReportForImage(dir, image)
	if err != nil {
		t.Fatalf("findLatestBaselineReportForImage returned error: %v", err)
	}
	if got != newPath {
		t.Fatalf("got %q, want %q", got, newPath)
	}

	missing, err := findLatestBaselineReportForImage(dir, "alpine:3.18")
	if err != nil {
		t.Fatalf("findLatestBaselineReportForImage (missing) returned error: %v", err)
	}
	if missing != "" {
		t.Fatalf("expected empty path for missing baseline, got %q", missing)
	}
}
