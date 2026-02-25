package main

import "testing"

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
