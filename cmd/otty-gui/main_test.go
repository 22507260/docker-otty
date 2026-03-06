package main

import "testing"

func TestNormalizeReportFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: "json"},
		{in: "json", want: "json"},
		{in: "TXT", want: "txt"},
		{in: "xml", wantErr: true},
	}

	for _, tc := range tests {
		got, err := normalizeReportFormat(tc.in)
		if tc.wantErr && err == nil {
			t.Fatalf("normalizeReportFormat(%q): expected error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("normalizeReportFormat(%q): unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeReportFormat(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseScanners(t *testing.T) {
	got, err := parseScanners("vuln, secret, vuln,misconfig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "vuln,secret,misconfig" {
		t.Fatalf("got %q, want %q", got, "vuln,secret,misconfig")
	}

	if _, err := parseScanners(" , "); err == nil {
		t.Fatalf("expected error for empty scanners")
	}
}

func TestIsValidImageName(t *testing.T) {
	if !isValidImageName("nginx:latest") {
		t.Fatalf("expected valid image")
	}
	if !isValidImageName("registry.local/app@sha256:deadbeef") {
		t.Fatalf("expected digest image to be valid")
	}
	if isValidImageName("bad image") {
		t.Fatalf("image containing spaces should be invalid")
	}
}
