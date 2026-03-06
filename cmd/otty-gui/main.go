package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"docker-otty/config"
	"docker-otty/trivy"
)

const (
	defaultAddr     = "127.0.0.1:8787"
	defaultTrivyURL = "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_windows-64bit.zip"
)

//go:embed web/*
var webFiles embed.FS

type scanRequest struct {
	Image          string `json:"image"`
	Format         string `json:"format"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Scanners       string `json:"scanners"`
	Top            int    `json:"top"`
}

type configResponse struct {
	TrivyURL   string   `json:"trivy_url"`
	ScanImages []string `json:"scan_images"`
	OutputDir  string   `json:"output_dir"`
}

type scanResponse struct {
	Image        string         `json:"image"`
	RunAt        string         `json:"run_at"`
	ReportPath   string         `json:"report_path"`
	Format       string         `json:"format"`
	Summary      scanSummary    `json:"summary"`
	Severity     severityCounts `json:"severity"`
	Explanations []string       `json:"explanations"`
	TrivyStderr  string         `json:"trivy_stderr"`
	TrivyRawJSON string         `json:"trivy_raw_json"`
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string         `json:"Target"`
	Type              string         `json:"Type"`
	Vulnerabilities   []trivyFinding `json:"Vulnerabilities"`
	Secrets           []trivyFinding `json:"Secrets"`
	Misconfigurations []trivyFinding `json:"Misconfigurations"`
}

type trivyFinding struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	ID               string `json:"ID"`
	AVDID            string `json:"AVDID"`
}

type scanSummary struct {
	DefiniteMalicious int `json:"critical_high_risk_finding_count"`
	Suspicious        int `json:"medium_low_risk_finding_count"`
	Safe              int `json:"clean_target_count"`
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type riskExplanation struct {
	Severity int
	Text     string
}

type guiState struct {
	cfg      *config.Config
	cfgPath  string
	startDir string
	mu       sync.Mutex
}

func main() {
	var cfgPath string
	var addr string
	var noOpen bool

	flagSet := flag.NewFlagSet("otty-gui", flag.ContinueOnError)
	flagSet.SetOutput(os.Stderr)
	flagSet.StringVar(&cfgPath, "config", "config.yaml", "Path to config file")
	flagSet.StringVar(&addr, "addr", defaultAddr, "Listen address")
	flagSet.BoolVar(&noOpen, "no-open", false, "Do not auto-open browser")
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	cfg, loadedPath, err := loadGUIConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load config:", err)
		os.Exit(1)
	}
	state := &guiState{
		cfg:      cfg,
		cfgPath:  loadedPath,
		startDir: ".",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", state.handleConfig)
	mux.HandleFunc("/api/scan", state.handleScan)
	mux.HandleFunc("/api/healthz", handleHealth)

	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load UI assets:", err)
		os.Exit(1)
	}
	mux.Handle("/", http.FileServer(http.FS(static)))

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to listen:", err)
		os.Exit(1)
	}
	defer listener.Close()

	url := fmt.Sprintf("http://%s", listener.Addr().String())
	fmt.Println("OTTY GUI started")
	fmt.Println("Config:", loadedPath)
	fmt.Println("Open:", url)

	if !noOpen {
		if err := openBrowser(url); err != nil {
			fmt.Println("Browser auto-open failed:", err)
			fmt.Println("Open manually:", url)
		}
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           withCORS(withNoCache(mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *guiState) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	resp := configResponse{
		TrivyURL:   s.cfg.TrivyURL,
		ScanImages: append([]string(nil), s.cfg.ScanImages...),
		OutputDir:  safeOutputDir(s.cfg.OutputDir),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *guiState) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	image := strings.TrimSpace(req.Image)
	if image == "" {
		writeJSONError(w, http.StatusBadRequest, "image is required")
		return
	}
	if !isValidImageName(image) {
		writeJSONError(w, http.StatusBadRequest, "invalid image name")
		return
	}

	format, err := normalizeReportFormat(req.Format)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}

	top := req.Top
	if top <= 0 {
		top = 5
	}

	scanners := strings.TrimSpace(req.Scanners)
	if scanners != "" {
		scanners, err = parseScanners(scanners)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	outputDir := safeOutputDir(s.cfg.OutputDir)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create output directory: %v", err))
		return
	}
	outFile := filepath.Join(outputDir, fmt.Sprintf("%s-scan-%s%s", sanitizeScanFileName(image), timestampSuffix(time.Now()), reportFileExtension(format)))

	s.mu.Lock()
	defer s.mu.Unlock()

	trivyBin, err := trivy.EnsureTrivy(s.cfg.TrivyURL, s.startDir)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("failed to prepare Trivy: %v", err))
		return
	}

	summary, severity, explanations, report, stderr, raw, err := runSingleScan(trivyBin, image, scanExecOptions{
		ReportFormat:     format,
		ExplanationLimit: top,
		TimeoutSeconds:   timeoutSeconds,
		Scanners:         scanners,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	content, err := buildReportContent(format, image, time.Now(), summary, severity, explanations, stderr, report, raw)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := os.WriteFile(outFile, []byte(content), 0o644); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("failed to write report: %v", err))
		return
	}

	resp := scanResponse{
		Image:        image,
		RunAt:        time.Now().Format(time.RFC3339),
		ReportPath:   outFile,
		Format:       format,
		Summary:      summary,
		Severity:     severity,
		Explanations: explanations,
		TrivyStderr:  stderr,
		TrivyRawJSON: raw,
	}
	writeJSON(w, http.StatusOK, resp)
}

type scanExecOptions struct {
	ReportFormat     string
	ExplanationLimit int
	TimeoutSeconds   int
	Scanners         string
}

func runSingleScan(trivyBin, image string, options scanExecOptions) (scanSummary, severityCounts, []string, trivyReport, string, string, error) {
	var summary scanSummary
	var severity severityCounts
	var parsed trivyReport
	timeoutSeconds := options.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	trivyArgs := []string{"image", "--format", "json"}
	if scanners := strings.TrimSpace(options.Scanners); scanners != "" {
		trivyArgs = append(trivyArgs, "--scanners", scanners)
	}
	trivyArgs = append(trivyArgs, image)

	cmd := exec.CommandContext(ctx, trivyBin, trivyArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return summary, severity, nil, parsed, "", "", fmt.Errorf("trivy command timed out (%d seconds)", timeoutSeconds)
	}

	trivyStdout := strings.TrimSpace(stdout.String())
	trivyStderr := strings.TrimSpace(stderr.String())

	if err != nil && trivyStdout == "" {
		return summary, severity, nil, parsed, trivyStderr, "", fmt.Errorf("trivy command failed: %w", err)
	}
	if trivyStdout == "" {
		return summary, severity, nil, parsed, trivyStderr, "", errors.New("trivy did not return JSON output")
	}
	if parseErr := json.Unmarshal(stdout.Bytes(), &parsed); parseErr != nil {
		return summary, severity, nil, parsed, trivyStderr, trivyStdout, fmt.Errorf("failed to parse trivy JSON output: %w", parseErr)
	}

	summary, severity = analyzeTrivyReport(parsed)
	limit := options.ExplanationLimit
	if limit <= 0 {
		limit = 5
	}
	explanations := buildRiskExplanations(parsed, limit)
	if len(explanations) == 0 {
		explanations = []string{"No package-level vulnerability explanation generated from this scan."}
	}

	return summary, severity, explanations, parsed, trivyStderr, trivyStdout, nil
}

func loadGUIConfig(path string) (*config.Config, string, error) {
	cfg := &config.Config{
		TrivyURL:   defaultTrivyURL,
		ScanImages: []string{"alpine:3.18"},
		OutputDir:  "./scan-results",
	}
	loaded, err := config.LoadConfig(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, "", err
		}
		absPath, absErr := filepath.Abs(path)
		if absErr != nil {
			return cfg, path, nil
		}
		return cfg, absPath, nil
	}
	if strings.TrimSpace(loaded.TrivyURL) != "" {
		cfg.TrivyURL = loaded.TrivyURL
	}
	if len(loaded.ScanImages) > 0 {
		cfg.ScanImages = append([]string(nil), loaded.ScanImages...)
	}
	if strings.TrimSpace(loaded.OutputDir) != "" {
		cfg.OutputDir = loaded.OutputDir
	}

	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		return cfg, path, nil
	}
	return cfg, absPath, nil
}

func normalizeReportFormat(value string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		return "json", nil
	}
	switch format {
	case "txt", "json", "md":
		return format, nil
	default:
		return "", fmt.Errorf("invalid format: %s (allowed: txt, json, md)", value)
	}
}

func reportFileExtension(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return ".json"
	case "md":
		return ".md"
	default:
		return ".txt"
	}
}

func parseScanners(value string) (string, error) {
	parts := strings.Split(value, ",")
	clean := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		token := strings.ToLower(strings.TrimSpace(part))
		if token == "" {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		clean = append(clean, token)
	}
	if len(clean) == 0 {
		return "", errors.New("--scanners requires at least one scanner value")
	}
	return strings.Join(clean, ","), nil
}

func analyzeTrivyReport(report trivyReport) (scanSummary, severityCounts) {
	summary := scanSummary{}
	severity := severityCounts{}
	for _, result := range report.Results {
		targetFindings := 0
		addBySeverity := func(findings []trivyFinding) {
			for _, finding := range findings {
				switch strings.ToUpper(strings.TrimSpace(finding.Severity)) {
				case "CRITICAL":
					severity.Critical++
					targetFindings++
				case "HIGH":
					severity.High++
					targetFindings++
				case "MEDIUM":
					severity.Medium++
					targetFindings++
				case "LOW":
					severity.Low++
					targetFindings++
				case "UNKNOWN":
					severity.Unknown++
					targetFindings++
				default:
					if strings.TrimSpace(finding.Severity) != "" {
						severity.Unknown++
						targetFindings++
					}
				}
			}
		}
		addBySeverity(result.Vulnerabilities)
		addBySeverity(result.Secrets)
		addBySeverity(result.Misconfigurations)
		if targetFindings == 0 {
			summary.Safe++
		}
	}
	summary.DefiniteMalicious = severity.Critical + severity.High
	summary.Suspicious = severity.Medium + severity.Low + severity.Unknown
	return summary, severity
}

func buildRiskExplanations(report trivyReport, limit int) []string {
	records := make([]riskExplanation, 0)
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if strings.TrimSpace(vuln.PkgName) == "" {
				continue
			}
			score := severityScore(vuln.Severity)
			if score == 0 {
				continue
			}
			text := formatVulnerabilityExplanation(result, vuln)
			if text == "" {
				continue
			}
			records = append(records, riskExplanation{Severity: score, Text: text})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Severity != records[j].Severity {
			return records[i].Severity > records[j].Severity
		}
		return records[i].Text < records[j].Text
	})
	if limit <= 0 {
		limit = 5
	}
	out := make([]string, 0, limit)
	seen := make(map[string]struct{})
	for _, rec := range records {
		if _, ok := seen[rec.Text]; ok {
			continue
		}
		seen[rec.Text] = struct{}{}
		out = append(out, rec.Text)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func formatVulnerabilityExplanation(result trivyResult, vuln trivyFinding) string {
	severity := strings.ToUpper(strings.TrimSpace(vuln.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}
	vulnID := firstNonEmpty(vuln.VulnerabilityID, vuln.ID, vuln.AVDID, "UNSPECIFIED-ID")
	pkg := firstNonEmpty(vuln.PkgName, "unknown-package")
	target := firstNonEmpty(strings.TrimSpace(result.Target), "unknown-target")
	installed := firstNonEmpty(vuln.InstalledVersion, "unknown")
	fix := strings.TrimSpace(vuln.FixedVersion)
	impact := firstNonEmpty(shortText(vuln.Title, 180), shortText(vuln.Description, 180), "Attackers may exploit this issue depending on service exposure.")

	remediation := "No fixed version listed yet."
	if fix != "" {
		remediation = fmt.Sprintf("Update from %s to %s.", installed, fix)
	}

	return fmt.Sprintf("[%s] %s in %s has %s. %s %s", severity, pkg, target, vulnID, impact, remediation)
}

func buildReportContent(format, image string, runAt time.Time, summary scanSummary, severity severityCounts, explanations []string, trivyStderr string, parsed trivyReport, trivyRaw string) (string, error) {
	switch format {
	case "json":
		payload := map[string]interface{}{
			"image":                            image,
			"run_at":                           runAt.Format(time.RFC3339),
			"critical_high_risk_finding_count": summary.DefiniteMalicious,
			"medium_low_risk_finding_count":    summary.Suspicious,
			"clean_target_count":               summary.Safe,
			"severity_breakdown": map[string]int{
				"critical": severity.Critical,
				"high":     severity.High,
				"medium":   severity.Medium,
				"low":      severity.Low,
				"unknown":  severity.Unknown,
			},
			"risk_explanations": explanations,
			"trivy_stderr":      trivyStderr,
			"trivy_report":      parsed,
		}
		data, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to build JSON report: %w", err)
		}
		return string(data), nil
	case "md":
		var b strings.Builder
		b.WriteString("# Trivy Scan Report\n\n")
		b.WriteString(fmt.Sprintf("- Image: `%s`\n", image))
		b.WriteString(fmt.Sprintf("- Run At: `%s`\n", runAt.Format(time.RFC3339)))
		b.WriteString(fmt.Sprintf("- Critical/High Risk Finding Count: `%d`\n", summary.DefiniteMalicious))
		b.WriteString(fmt.Sprintf("- Medium/Low Risk Finding Count: `%d`\n", summary.Suspicious))
		b.WriteString(fmt.Sprintf("- Clean Target Count: `%d`\n", summary.Safe))
		b.WriteString("\n## Severity Breakdown\n")
		b.WriteString(fmt.Sprintf("- Critical: `%d`\n", severity.Critical))
		b.WriteString(fmt.Sprintf("- High: `%d`\n", severity.High))
		b.WriteString(fmt.Sprintf("- Medium: `%d`\n", severity.Medium))
		b.WriteString(fmt.Sprintf("- Low: `%d`\n", severity.Low))
		b.WriteString(fmt.Sprintf("- Unknown: `%d`\n", severity.Unknown))
		b.WriteString("\n## Risk Explanations\n")
		b.WriteString(formatBulletList(explanations))
		b.WriteString("\n\n## Trivy Stderr\n```text\n")
		b.WriteString(trivyStderr)
		b.WriteString("\n```\n\n## Trivy JSON Report\n```json\n")
		b.WriteString(trivyRaw)
		b.WriteString("\n```\n")
		return b.String(), nil
	default:
		return fmt.Sprintf(
			"image: %s\nrun_at: %s\ncritical_high_risk_finding_count: %d\nmedium_low_risk_finding_count: %d\nclean_target_count: %d\nseverity_critical: %d\nseverity_high: %d\nseverity_medium: %d\nseverity_low: %d\nseverity_unknown: %d\n\nrisk_explanations:\n%s\n\ntrivy_stderr:\n%s\n\ntrivy_json_report:\n%s\n",
			image,
			runAt.Format(time.RFC3339),
			summary.DefiniteMalicious,
			summary.Suspicious,
			summary.Safe,
			severity.Critical,
			severity.High,
			severity.Medium,
			severity.Low,
			severity.Unknown,
			formatBulletList(explanations),
			trivyStderr,
			trivyRaw,
		), nil
	}
}

func isValidImageName(image string) bool {
	if strings.TrimSpace(image) == "" {
		return false
	}
	for _, c := range image {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != ':' && c != '/' && c != '-' && c != '_' && c != '.' && c != '@' {
			return false
		}
	}
	return true
}

func sanitizeScanFileName(image string) string {
	name := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(image)
	if name == "" {
		return "scan"
	}
	return name
}

func safeOutputDir(value string) string {
	dir := strings.TrimSpace(value)
	if dir == "" {
		return "./scan-results"
	}
	return filepath.Clean(dir)
}

func timestampSuffix(t time.Time) string {
	return t.Format("20060102-150405")
}

func severityScore(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW", "UNKNOWN":
		return 1
	case "":
		return 0
	default:
		return 1
	}
}

func shortText(text string, maxLen int) string {
	t := strings.TrimSpace(text)
	if t == "" {
		return ""
	}
	if idx := strings.Index(t, "\n"); idx >= 0 {
		t = strings.TrimSpace(t[:idx])
	}
	if idx := strings.Index(t, ". "); idx >= 0 {
		t = strings.TrimSpace(t[:idx+1])
	}
	if maxLen > 0 && len(t) > maxLen {
		t = strings.TrimSpace(t[:maxLen-3]) + "..."
	}
	return t
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		t := strings.TrimSpace(v)
		if t != "" {
			return t
		}
	}
	return ""
}

func formatBulletList(items []string) string {
	if len(items) == 0 {
		return "- none"
	}
	var b strings.Builder
	for _, item := range items {
		b.WriteString("- ")
		b.WriteString(item)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withNoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
