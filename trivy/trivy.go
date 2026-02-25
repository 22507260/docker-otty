package trivy

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

const trivyBinaryName = "trivy.exe"

func EnsureTrivy(trivyURL, destDir string) (string, error) {
	binPath := filepath.Join(destDir, trivyBinaryName)
	if _, err := os.Stat(binPath); err == nil {
		abs, absErr := filepath.Abs(binPath)
		if absErr != nil {
			return binPath, nil
		}
		return abs, nil
	}

	var zipPath string
	downloaded := false

	parsed, err := url.Parse(trivyURL)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		resp, err := http.Get(trivyURL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("failed to download Trivy, HTTP status code: %d", resp.StatusCode)
		}

		zipPath = filepath.Join(destDir, "trivy.zip")
		out, err := os.Create(zipPath)
		if err != nil {
			return "", err
		}
		defer out.Close()

		if _, err = io.Copy(out, resp.Body); err != nil {
			return "", err
		}
		downloaded = true
	} else {
		if _, err := os.Stat(trivyURL); err != nil {
			return "", err
		}
		zipPath = trivyURL
	}

	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer zipReader.Close()

	found := false
	for _, f := range zipReader.File {
		if filepath.Base(f.Name) != trivyBinaryName {
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
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("%s was not found in zip archive", trivyBinaryName)
	}

	if downloaded {
		_ = os.Remove(zipPath)
	}

	abs, absErr := filepath.Abs(binPath)
	if absErr != nil {
		return binPath, nil
	}
	return abs, nil
}
