package trivy

import "testing"

func TestInferReleaseDownloadURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "windows-archive-name",
			input:   "./trivy_0.69.1_windows-64bit.zip",
			wantURL: "https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_windows-64bit.zip",
			wantOK:  true,
		},
		{
			name:    "absolute-windows-path",
			input:   `C:\tools\trivy_0.70.0_windows-64bit.zip`,
			wantURL: "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_windows-64bit.zip",
			wantOK:  true,
		},
		{
			name:   "non-zip-input",
			input:  "trivy.exe",
			wantOK: false,
		},
		{
			name:   "invalid-archive-name",
			input:  "archive.zip",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotOK := inferReleaseDownloadURL(tc.input)
			if gotOK != tc.wantOK {
				t.Fatalf("gotOK=%v, want %v (url=%q)", gotOK, tc.wantOK, gotURL)
			}
			if gotURL != tc.wantURL {
				t.Fatalf("gotURL=%q, want %q", gotURL, tc.wantURL)
			}
		})
	}
}

func TestExtractAssetNameFromTrivyReleaseURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantAsset string
		wantOK    bool
	}{
		{
			name:      "valid-release-url",
			input:     "https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_windows-64bit.zip",
			wantAsset: "trivy_0.69.1_windows-64bit.zip",
			wantOK:    true,
		},
		{
			name:   "non-trivy-url",
			input:  "https://example.com/file.zip",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAsset, gotOK := extractAssetNameFromTrivyReleaseURL(tc.input)
			if gotOK != tc.wantOK {
				t.Fatalf("gotOK=%v, want %v", gotOK, tc.wantOK)
			}
			if gotAsset != tc.wantAsset {
				t.Fatalf("gotAsset=%q, want %q", gotAsset, tc.wantAsset)
			}
		})
	}
}

func TestExtractArchiveSuffix(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantFound bool
	}{
		{
			name:      "windows-suffix",
			input:     "trivy_0.69.3_windows-64bit.zip",
			want:      "windows-64bit.zip",
			wantFound: true,
		},
		{
			name:      "linux-suffix",
			input:     "trivy_0.69.3_Linux-64bit.zip",
			want:      "Linux-64bit.zip",
			wantFound: true,
		},
		{
			name:      "invalid",
			input:     "trivy.zip",
			wantFound: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, found := extractArchiveSuffix(tc.input)
			if found != tc.wantFound {
				t.Fatalf("found=%v, want %v", found, tc.wantFound)
			}
			if got != tc.want {
				t.Fatalf("got=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestSelectLatestReleaseAssetBySuffix(t *testing.T) {
	assets := []githubReleaseAsset{
		{
			Name:               "trivy_0.69.3_windows-ARM64.zip",
			BrowserDownloadURL: "https://example.com/arm64.zip",
		},
		{
			Name:               "trivy_0.69.3_windows-64bit.zip",
			BrowserDownloadURL: "https://example.com/amd64.zip",
		},
	}

	gotURL, ok := selectLatestReleaseAssetBySuffix(assets, "windows-64bit.zip")
	if !ok {
		t.Fatalf("expected asset to be found")
	}
	if gotURL != "https://example.com/amd64.zip" {
		t.Fatalf("gotURL=%q, want %q", gotURL, "https://example.com/amd64.zip")
	}

	missingURL, missingOK := selectLatestReleaseAssetBySuffix(assets, "Linux-64bit.zip")
	if missingOK {
		t.Fatalf("expected no asset for Linux suffix, got %q", missingURL)
	}
}
