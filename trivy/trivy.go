package trivy

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var trivyArchiveNamePattern = regexp.MustCompile(`^trivy_([^_]+)_.+\.zip$`)
var trivyArchiveSuffixPattern = regexp.MustCompile(`^trivy_[^_]+_(.+\.zip)$`)
var trivyGitHubReleaseAssetURLPattern = regexp.MustCompile(`(?i)^https?://github\.com/aquasecurity/trivy/releases/download/[^/]+/(trivy_[^/]+\.zip)$`)

const trivyGitHubLatestReleaseAPI = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"

type downloadHTTPError struct {
	URL        string
	StatusCode int
}

func (e *downloadHTTPError) Error() string {
	return fmt.Sprintf("failed to download Trivy archive from %s, HTTP status code: %d", e.URL, e.StatusCode)
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubLatestReleasePayload struct {
	TagName string               `json:"tag_name"`
	Assets  []githubReleaseAsset `json:"assets"`
}

func EnsureTrivy(trivyURL, destDir string) (string, error) {
	binaryName := trivyBinaryName()
	binPath := filepath.Join(destDir, binaryName)
	if _, err := os.Stat(binPath); err == nil {
		abs, absErr := filepath.Abs(binPath)
		if absErr != nil {
			return binPath, nil
		}
		return abs, nil
	}

	zipPath, downloaded, sourceDescription, err := resolveTrivyArchivePath(trivyURL, destDir)
	if err != nil {
		return "", err
	}
	if downloaded {
		defer func() {
			_ = os.Remove(zipPath)
		}()
	}

	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to open Trivy archive %s: %w", zipPath, err)
	}
	defer zipReader.Close()

	found := false
	for _, f := range zipReader.File {
		entryName := filepath.Base(f.Name)
		if !strings.EqualFold(entryName, binaryName) && !strings.EqualFold(entryName, "trivy.exe") && entryName != "trivy" {
			continue
		}

		binFile, err := f.Open()
		if err != nil {
			return "", err
		}
		defer binFile.Close()

		outFile, err := os.Create(binPath)
		if err != nil {
			return "", err
		}
		defer outFile.Close()

		if _, err = io.Copy(outFile, binFile); err != nil {
			return "", err
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(binPath, 0o755)
		}
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("%s was not found in zip archive from %s", binaryName, sourceDescription)
	}

	abs, absErr := filepath.Abs(binPath)
	if absErr != nil {
		return binPath, nil
	}
	return abs, nil
}

func trivyBinaryName() string {
	if runtime.GOOS == "windows" {
		return "trivy.exe"
	}
	return "trivy"
}

func resolveTrivyArchivePath(trivyURL, destDir string) (string, bool, string, error) {
	source := strings.TrimSpace(trivyURL)
	if source == "" {
		return "", false, "", fmt.Errorf("trivy_url is empty; set a local ZIP path or a release URL")
	}

	if isRemoteURL(source) {
		zipPath, resolvedSource, err := downloadTrivyArchiveWithFallback(source, destDir)
		if err != nil {
			return "", false, source, err
		}
		return zipPath, true, resolvedSource, nil
	}

	if _, err := os.Stat(source); err == nil {
		return source, false, source, nil
	} else if !os.IsNotExist(err) {
		return "", false, source, err
	}

	if inferredURL, ok := inferReleaseDownloadURL(source); ok {
		zipPath, resolvedSource, err := downloadTrivyArchiveWithFallback(inferredURL, destDir)
		if err != nil {
			return "", false, inferredURL, fmt.Errorf("local Trivy archive not found (%s), and auto-download from %s failed: %w", source, inferredURL, err)
		}
		return zipPath, true, resolvedSource, nil
	}

	return "", false, source, fmt.Errorf("local Trivy archive not found: %s (set trivy_url to an existing ZIP path or release URL)", source)
}

func inferReleaseDownloadURL(source string) (string, bool) {
	assetName := strings.TrimSpace(source)
	assetName = strings.TrimRight(assetName, `/\`)
	if idx := strings.LastIndexAny(assetName, `/\`); idx >= 0 {
		assetName = assetName[idx+1:]
	}
	if assetName == "" {
		return "", false
	}
	match := trivyArchiveNamePattern.FindStringSubmatch(assetName)
	if len(match) != 2 {
		return "", false
	}

	version := strings.TrimPrefix(match[1], "v")
	if version == "" {
		return "", false
	}
	return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/%s", version, assetName), true
}

func isRemoteURL(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func downloadTrivyArchiveWithFallback(downloadURL, destDir string) (string, string, error) {
	zipPath, err := downloadToTempZip(downloadURL, destDir)
	if err == nil {
		return zipPath, downloadURL, nil
	}
	if !isNotFoundDownloadError(err) {
		return "", downloadURL, err
	}

	fallbackURL, fallbackErr := resolveLatestReleaseAssetURL(downloadURL)
	if fallbackErr != nil {
		return "", downloadURL, fmt.Errorf("%w (fallback lookup failed: %v)", err, fallbackErr)
	}
	if strings.EqualFold(strings.TrimSpace(fallbackURL), strings.TrimSpace(downloadURL)) {
		return "", downloadURL, err
	}

	zipPath, secondErr := downloadToTempZip(fallbackURL, destDir)
	if secondErr != nil {
		return "", fallbackURL, fmt.Errorf("%w (fallback URL %s also failed: %v)", err, fallbackURL, secondErr)
	}
	return zipPath, fallbackURL, nil
}

func isNotFoundDownloadError(err error) bool {
	var httpErr *downloadHTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound
}

func resolveLatestReleaseAssetURL(downloadURL string) (string, error) {
	assetName, ok := extractAssetNameFromTrivyReleaseURL(downloadURL)
	if !ok {
		return "", fmt.Errorf("URL is not a supported Trivy GitHub release asset URL: %s", downloadURL)
	}

	suffix, ok := extractArchiveSuffix(assetName)
	if !ok {
		return "", fmt.Errorf("could not derive archive suffix from asset name: %s", assetName)
	}

	releasePayload, err := fetchLatestReleasePayload()
	if err != nil {
		return "", err
	}

	if matchedURL, ok := selectLatestReleaseAssetBySuffix(releasePayload.Assets, suffix); ok {
		return matchedURL, nil
	}
	return "", fmt.Errorf("latest release %s does not contain an asset with suffix %s", releasePayload.TagName, suffix)
}

func extractAssetNameFromTrivyReleaseURL(downloadURL string) (string, bool) {
	match := trivyGitHubReleaseAssetURLPattern.FindStringSubmatch(strings.TrimSpace(downloadURL))
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}

func extractArchiveSuffix(assetName string) (string, bool) {
	match := trivyArchiveSuffixPattern.FindStringSubmatch(strings.TrimSpace(assetName))
	if len(match) != 2 {
		return "", false
	}
	return match[1], true
}

func selectLatestReleaseAssetBySuffix(assets []githubReleaseAsset, suffix string) (string, bool) {
	wantSuffix := strings.ToLower(strings.TrimSpace(suffix))
	if wantSuffix == "" {
		return "", false
	}

	for _, asset := range assets {
		assetSuffix, ok := extractArchiveSuffix(asset.Name)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(assetSuffix), wantSuffix) && strings.TrimSpace(asset.BrowserDownloadURL) != "" {
			return strings.TrimSpace(asset.BrowserDownloadURL), true
		}
	}
	return "", false
}

func fetchLatestReleasePayload() (githubLatestReleasePayload, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, trivyGitHubLatestReleaseAPI, nil)
	if err != nil {
		return githubLatestReleasePayload{}, err
	}
	req.Header.Set("User-Agent", "docker-otty")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return githubLatestReleasePayload{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return githubLatestReleasePayload{}, fmt.Errorf("latest release API request failed with HTTP status code: %d", resp.StatusCode)
	}

	var payload githubLatestReleasePayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return githubLatestReleasePayload{}, err
	}
	return payload, nil
}

func downloadToTempZip(downloadURL, destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	tmpFile, err := os.CreateTemp(destDir, "trivy-*.zip")
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", &downloadHTTPError{
			URL:        downloadURL,
			StatusCode: resp.StatusCode,
		}
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", err
	}
	return tmpFile.Name(), nil
}
