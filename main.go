package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"docker-otty/config"
	"docker-otty/trivy"
)

var appVersion = "1.0.0"

type appOptions struct {
	AutoYes bool
	NoInput bool
}

type pluginMetadata struct {
	SchemaVersion    string `json:"SchemaVersion"`
	Vendor           string `json:"Vendor"`
	Version          string `json:"Version"`
	ShortDescription string `json:"ShortDescription"`
	URL              string `json:"URL"`
}

type scanSummary struct {
	DefiniteMalicious int
	Suspicious        int
	Safe              int
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
	PrimaryURL       string `json:"PrimaryURL"`
	ID               string `json:"ID"`
	AVDID            string `json:"AVDID"`
}

type riskExplanation struct {
	Severity int
	Text     string
}

type severityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

type ciGateOptions struct {
	FailOn    string
	MaxMedium int
	ExitCode  int
}

type commandError struct {
	message  string
	exitCode int
}

func (e *commandError) Error() string {
	return e.message
}

func (e *commandError) ExitCode() int {
	if e.exitCode <= 0 {
		return 1
	}
	return e.exitCode
}

type multiTask struct {
	Index   int
	Image   string
	OutFile string
}

type multiResult struct {
	Task         multiTask
	Summary      scanSummary
	Severity     severityCounts
	Explanations []string
	Err          error
}

type multiSummaryImage struct {
	Image                        string `json:"image"`
	Status                       string `json:"status"`
	Report                       string `json:"report,omitempty"`
	Error                        string `json:"error,omitempty"`
	CriticalHighRiskFindingCount int    `json:"critical_high_risk_finding_count"`
	MediumLowRiskFindingCount    int    `json:"medium_low_risk_finding_count"`
	CleanTargetCount             int    `json:"clean_target_count"`
	CriticalFindingCount         int    `json:"critical_finding_count"`
	HighFindingCount             int    `json:"high_finding_count"`
	MediumFindingCount           int    `json:"medium_finding_count"`
	LowFindingCount              int    `json:"low_finding_count"`
	UnknownFindingCount          int    `json:"unknown_finding_count"`
	CIGateStatus                 string `json:"ci_gate_status,omitempty"`
}

type multiSummaryReport struct {
	RunAt                        string              `json:"run_at"`
	Format                       string              `json:"format"`
	Workers                      int                 `json:"workers"`
	TotalImages                  int                 `json:"total_images"`
	SuccessCount                 int                 `json:"success_count"`
	FailedCount                  int                 `json:"failed_count"`
	CombinedCriticalHighFindings int                 `json:"combined_critical_high_findings"`
	CombinedMediumLowFindings    int                 `json:"combined_medium_low_findings"`
	CombinedCleanTargets         int                 `json:"combined_clean_targets"`
	CombinedCriticalFindings     int                 `json:"combined_critical_findings"`
	CombinedHighFindings         int                 `json:"combined_high_findings"`
	CombinedMediumFindings       int                 `json:"combined_medium_findings"`
	CombinedLowFindings          int                 `json:"combined_low_findings"`
	CombinedUnknownFindings      int                 `json:"combined_unknown_findings"`
	Images                       []multiSummaryImage `json:"images"`
}

type scanExecOptions struct {
	ReportFormat     string
	ExplanationLimit int
	TimeoutSeconds   int
	Scanners         string
	SkipDBUpdate     bool
}

var stdinReader = bufio.NewReader(os.Stdin)

func main() {
	opts, args, err := parseGlobalOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Argument error:", err)
		os.Exit(2)
	}

	if len(args) < 1 {
		if opts.NoInput {
			printHelp()
			os.Exit(2)
		}
		interactiveMainMenu(opts)
		return
	}

	// Docker CLI plugin invocation may prefix the plugin name as the first arg.
	if args[0] == "otty" || args[0] == "docker-otty" {
		args = args[1:]
	}
	if len(args) < 1 {
		if opts.NoInput {
			printHelp()
			os.Exit(2)
		}
		interactiveMainMenu(opts)
		return
	}

	switch args[0] {
	case "docker-cli-plugin-metadata":
		printPluginMetadata()
	case "run":
		if err := runCommand(args[1:], opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCodeForError(err))
		}
	case "multi":
		if err := multiCommand(args[1:], opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCodeForError(err))
		}
	case "daemon":
		if err := daemonCommand(args[1:], opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCodeForError(err))
		}
	case "version", "--version", "-v":
		fmt.Println(appVersion)
	case "help", "--help", "-h":
		printHelp()
	default:
		fmt.Fprintln(os.Stderr, "Unknown command:", args[0])
		printHelp()
		os.Exit(2)
	}
}

func exitCodeForError(err error) int {
	type exitCoder interface {
		ExitCode() int
	}
	var coded exitCoder
	if errors.As(err, &coded) {
		code := coded.ExitCode()
		if code > 0 {
			return code
		}
	}
	return 1
}

func parseGlobalOptions(args []string) (appOptions, []string, error) {
	opts := appOptions{}
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--yes", "-y":
			opts.AutoYes = true
		case "--no-input":
			opts.NoInput = true
		default:
			remaining = append(remaining, args[i:]...)
			return opts, remaining, nil
		}
	}
	return opts, remaining, nil
}

func normalizeReportFormat(value string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(value))
	if format == "" {
		return "txt", nil
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

func parseFailOn(value string) (string, error) {
	failOn := strings.ToLower(strings.TrimSpace(value))
	if failOn == "" || failOn == "none" {
		return "", nil
	}
	if failOn == "high" || failOn == "critical" {
		return failOn, nil
	}
	return "", fmt.Errorf("invalid --fail-on value: %s (allowed: high, critical, none)", value)
}

func evaluateCIGate(severity severityCounts, options ciGateOptions) []string {
	violations := make([]string, 0)
	switch options.FailOn {
	case "high":
		if severity.Critical+severity.High > 0 {
			violations = append(violations, fmt.Sprintf("--fail-on=high violated (critical=%d, high=%d)", severity.Critical, severity.High))
		}
	case "critical":
		if severity.Critical > 0 {
			violations = append(violations, fmt.Sprintf("--fail-on=critical violated (critical=%d)", severity.Critical))
		}
	}
	if options.MaxMedium >= 0 && severity.Medium > options.MaxMedium {
		violations = append(violations, fmt.Sprintf("--max-medium=%d violated (medium=%d)", options.MaxMedium, severity.Medium))
	}
	return violations
}

func newCIGateOptions() ciGateOptions {
	return ciGateOptions{
		FailOn:    "",
		MaxMedium: -1,
		ExitCode:  1,
	}
}

func defaultScanExecOptions() scanExecOptions {
	return scanExecOptions{
		ReportFormat:     "txt",
		ExplanationLimit: 5,
		TimeoutSeconds:   300,
		Scanners:         "",
		SkipDBUpdate:     false,
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

func scannerEnabled(scannersCSV, scanner string) bool {
	scanner = strings.ToLower(strings.TrimSpace(scanner))
	if scanner == "" {
		return false
	}
	if strings.TrimSpace(scannersCSV) == "" {
		return true
	}
	for _, part := range strings.Split(scannersCSV, ",") {
		if strings.ToLower(strings.TrimSpace(part)) == scanner {
			return true
		}
	}
	return false
}

func isPlaceholderContainerImage(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return true
	}
	lower := strings.ToLower(image)
	return lower == "<none>" || lower == "<missing>"
}

func parseContainerImageOutput(output string) []string {
	lines := strings.Split(output, "\n")
	images := make([]string, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		image := strings.TrimSpace(line)
		if isPlaceholderContainerImage(image) {
			continue
		}
		if _, ok := seen[image]; ok {
			continue
		}
		seen[image] = struct{}{}
		images = append(images, image)
	}
	return images
}

func parseInstalledContainerImageOutput(output string) []string {
	return parseContainerImageOutput(output)
}

func listContainerImages(includeStopped bool) ([]string, error) {
	dockerBin, err := exec.LookPath("docker")
	if err != nil {
		return nil, errors.New("docker binary not found in PATH (required for container discovery options)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{"ps"}
	if includeStopped {
		args = append(args, "-a")
	}
	args = append(args, "--format", "{{.Image}}")
	cmd := exec.CommandContext(ctx, dockerBin, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if includeStopped {
			return nil, errors.New("docker ps -a timed out while discovering installed container images")
		}
		return nil, errors.New("docker ps timed out while discovering running container images")
	}
	if runErr != nil {
		errText := strings.TrimSpace(stderr.String())
		cmdText := "docker ps"
		if includeStopped {
			cmdText = "docker ps -a"
		}
		if errText == "" {
			return nil, fmt.Errorf("%s failed: %w", cmdText, runErr)
		}
		return nil, fmt.Errorf("%s failed: %w. stderr: %s", cmdText, runErr, errText)
	}

	return parseContainerImageOutput(stdout.String()), nil
}

func listInstalledContainerImages() ([]string, error) {
	return listContainerImages(true)
}

func listRunningContainerImages() ([]string, error) {
	return listContainerImages(false)
}

func prepareTrivyDatabases(trivyBin string, options scanExecOptions) error {
	if !scannerEnabled(options.Scanners, "vuln") {
		return nil
	}
	timeoutSeconds := options.TimeoutSeconds
	if timeoutSeconds < 300 {
		timeoutSeconds = 300
	}

	run := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, trivyBin, args...)
		out, err := cmd.CombinedOutput()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("trivy DB preparation timed out (%d seconds)", timeoutSeconds)
		}
		if err != nil {
			return fmt.Errorf("trivy %s failed: %w. output: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run("image", "--download-db-only"); err != nil {
		return err
	}
	// Java DB is optional for non-Java images. Failures here should not block scans.
	_ = run("image", "--download-java-db-only")
	return nil
}

func printHelp() {
	fmt.Println("Docker OTTY CLI Plugin")
	fmt.Println("Usage:")
	fmt.Println("  docker otty run <image>      Scan one image")
	fmt.Println("  docker otty multi <images>   Scan multiple images once")
	fmt.Println("  docker otty daemon           Start periodic scans from config")
	fmt.Println("  docker otty version          Show plugin version")
	fmt.Println("  docker otty help             Show help")
	fmt.Println("")
	fmt.Println("Common options:")
	fmt.Println("  --yes, -y        Skip confirmation questions")
	fmt.Println("  --no-input       Disable interactive prompts")
	fmt.Println("  --config <path>  Use a custom config file")
	fmt.Println("  --output-dir     Output directory for multi reports")
	fmt.Println("  --images         Comma-separated image list for multi")
	fmt.Println("  --containers, --container  Include images from installed containers")
	fmt.Println("  --running-containers, --running-container  Include images from running containers only")
	fmt.Println("  --format         Report format: txt|json|md")
	fmt.Println("  --top            Number of top risk explanations")
	fmt.Println("  --timeout        Trivy scan timeout in seconds")
	fmt.Println("  --scanners       Trivy scanners (comma-separated)")
	fmt.Println("  --workers        Worker count for multi scan")
	fmt.Println("  --fail-on        CI gate: high|critical|none")
	fmt.Println("  --max-medium     CI gate: maximum allowed medium findings")
	fmt.Println("  --exit-code      Exit code to return when CI gate fails")
	fmt.Println("  --once           Run daemon only once")
}

func printPluginMetadata() {
	meta := pluginMetadata{
		SchemaVersion:    "0.1.0",
		Vendor:           "docker-otty",
		Version:          appVersion,
		ShortDescription: "Scan container images with Trivy",
		URL:              "",
	}
	data, err := json.Marshal(meta)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to build plugin metadata:", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func interactiveMainMenu(opts appOptions) {
	fmt.Println("docker otty - Interactive Mode")
	fmt.Println("1) Single scan (run)")
	fmt.Println("2) Multiple scan (multi)")
	fmt.Println("3) Daemon mode")
	fmt.Println("4) Help")

	choice := askNonEmpty("Choose an option (1/2/3/4)")
	switch choice {
	case "1":
		if err := runCommand(nil, opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	case "2":
		if err := multiCommand(nil, opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	case "3":
		if err := daemonCommand(nil, opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	case "4":
		printHelp()
	default:
		fmt.Println("Invalid choice.")
	}
}

func runCommand(args []string, opts appOptions) error {
	configPath := "config.yaml"
	outputPath := ""
	scanOptions := defaultScanExecOptions()
	image := ""
	ciOptions := newCIGateOptions()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) {
				return errors.New("--config requires a file path")
			}
			configPath = args[i+1]
			i++
		case "--output":
			if i+1 >= len(args) {
				return errors.New("--output requires a file path")
			}
			outputPath = args[i+1]
			i++
		case "--format":
			if i+1 >= len(args) {
				return errors.New("--format requires a value (txt|json|md)")
			}
			format, err := normalizeReportFormat(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.ReportFormat = format
			i++
		case "--top":
			if i+1 >= len(args) {
				return errors.New("--top requires a positive integer")
			}
			top, err := strconv.Atoi(args[i+1])
			if err != nil || top <= 0 {
				return fmt.Errorf("invalid --top value: %s", args[i+1])
			}
			scanOptions.ExplanationLimit = top
			i++
		case "--timeout":
			if i+1 >= len(args) {
				return errors.New("--timeout requires a positive integer (seconds)")
			}
			timeout, err := strconv.Atoi(args[i+1])
			if err != nil || timeout <= 0 {
				return fmt.Errorf("invalid --timeout value: %s", args[i+1])
			}
			scanOptions.TimeoutSeconds = timeout
			i++
		case "--scanners":
			if i+1 >= len(args) {
				return errors.New("--scanners requires a comma-separated list")
			}
			scanners, err := parseScanners(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.Scanners = scanners
			i++
		case "--fail-on":
			if i+1 >= len(args) {
				return errors.New("--fail-on requires a value (high|critical|none)")
			}
			failOn, err := parseFailOn(args[i+1])
			if err != nil {
				return err
			}
			ciOptions.FailOn = failOn
			i++
		case "--max-medium":
			if i+1 >= len(args) {
				return errors.New("--max-medium requires a number")
			}
			maxMedium, err := strconv.Atoi(args[i+1])
			if err != nil || maxMedium < 0 {
				return fmt.Errorf("invalid --max-medium value: %s", args[i+1])
			}
			ciOptions.MaxMedium = maxMedium
			i++
		case "--exit-code":
			if i+1 >= len(args) {
				return errors.New("--exit-code requires a positive integer")
			}
			exitCode, err := strconv.Atoi(args[i+1])
			if err != nil || exitCode <= 0 {
				return fmt.Errorf("invalid --exit-code value: %s", args[i+1])
			}
			ciOptions.ExitCode = exitCode
			i++
		case "--help", "-h":
			fmt.Println("Usage: docker otty run <image> [--config <path>] [--output <report-file>] [--format <txt|json|md>] [--top <n>] [--timeout <seconds>] [--scanners <csv>] [--fail-on <high|critical|none>] [--max-medium <n>] [--exit-code <n>]")
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown run argument: %s", args[i])
			}
			if image != "" {
				return errors.New("multiple images provided")
			}
			image = strings.TrimSpace(args[i])
		}
	}

	if image == "" {
		if opts.NoInput {
			return errors.New("image is required: docker otty run <image>")
		}
		image = askNonEmpty("Enter Docker image to scan (example: alpine:latest)")
	}
	if !isValidImageName(image) {
		return fmt.Errorf("invalid image name: %s", image)
	}

	cfg, cfgPath, err := loadConfigInteractive(configPath, opts)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Printf("Config: %s\n", cfgPath)
	fmt.Printf("Trivy source: %s\n", cfg.TrivyURL)

	if !confirm(opts, "Check and prepare Trivy binary if needed?", true) {
		return errors.New("operation cancelled")
	}
	bin, err := trivy.EnsureTrivy(cfg.TrivyURL, ".")
	if err != nil {
		return fmt.Errorf("failed to prepare Trivy: %w", err)
	}

	outFile, err := resolveRunOutputPath(cfg.OutputDir, outputPath, image, scanOptions.ReportFormat)
	if err != nil {
		return err
	}

	if !confirm(opts, fmt.Sprintf("Start scan for image: %s?", image), true) {
		return errors.New("operation cancelled")
	}
	summary, severity, explanations, err := runSingleScan(bin, image, outFile, scanOptions)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	fmt.Println("Scan completed.")
	fmt.Printf(
		"Critical/High Risk Finding Count: %d - Medium/Low Risk Finding Count: %d - Clean Target Count: %d\n",
		summary.DefiniteMalicious, summary.Suspicious, summary.Safe,
	)
	fmt.Println("Top Trivy Risk Explanations:")
	for _, item := range explanations {
		fmt.Println("-", item)
	}
	fmt.Println("Report:", outFile)

	violations := evaluateCIGate(severity, ciOptions)
	if len(violations) > 0 {
		return &commandError{
			message:  "CI gate failed: " + strings.Join(violations, " | "),
			exitCode: ciOptions.ExitCode,
		}
	}
	return nil
}

func multiCommand(args []string, opts appOptions) error {
	configPath := "config.yaml"
	outputDirOverride := ""
	scanOptions := defaultScanExecOptions()
	workers := 4
	ciOptions := newCIGateOptions()
	images := make([]string, 0)
	includeInstalledContainers := false
	includeRunningContainers := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) {
				return errors.New("--config requires a file path")
			}
			configPath = args[i+1]
			i++
		case "--output-dir":
			if i+1 >= len(args) {
				return errors.New("--output-dir requires a directory path")
			}
			outputDirOverride = args[i+1]
			i++
		case "--images":
			if i+1 >= len(args) {
				return errors.New("--images requires a comma-separated image list")
			}
			appendImageCandidates(&images, args[i+1])
			i++
		case "--containers", "--container":
			includeInstalledContainers = true
		case "--running-containers", "--running-container":
			includeRunningContainers = true
		case "--format":
			if i+1 >= len(args) {
				return errors.New("--format requires a value (txt|json|md)")
			}
			format, err := normalizeReportFormat(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.ReportFormat = format
			i++
		case "--top":
			if i+1 >= len(args) {
				return errors.New("--top requires a positive integer")
			}
			top, err := strconv.Atoi(args[i+1])
			if err != nil || top <= 0 {
				return fmt.Errorf("invalid --top value: %s", args[i+1])
			}
			scanOptions.ExplanationLimit = top
			i++
		case "--timeout":
			if i+1 >= len(args) {
				return errors.New("--timeout requires a positive integer (seconds)")
			}
			timeout, err := strconv.Atoi(args[i+1])
			if err != nil || timeout <= 0 {
				return fmt.Errorf("invalid --timeout value: %s", args[i+1])
			}
			scanOptions.TimeoutSeconds = timeout
			i++
		case "--scanners":
			if i+1 >= len(args) {
				return errors.New("--scanners requires a comma-separated list")
			}
			scanners, err := parseScanners(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.Scanners = scanners
			i++
		case "--workers":
			if i+1 >= len(args) {
				return errors.New("--workers requires a positive integer")
			}
			parsedWorkers, err := strconv.Atoi(args[i+1])
			if err != nil || parsedWorkers <= 0 {
				return fmt.Errorf("invalid --workers value: %s", args[i+1])
			}
			workers = parsedWorkers
			i++
		case "--fail-on":
			if i+1 >= len(args) {
				return errors.New("--fail-on requires a value (high|critical|none)")
			}
			failOn, err := parseFailOn(args[i+1])
			if err != nil {
				return err
			}
			ciOptions.FailOn = failOn
			i++
		case "--max-medium":
			if i+1 >= len(args) {
				return errors.New("--max-medium requires a number")
			}
			maxMedium, err := strconv.Atoi(args[i+1])
			if err != nil || maxMedium < 0 {
				return fmt.Errorf("invalid --max-medium value: %s", args[i+1])
			}
			ciOptions.MaxMedium = maxMedium
			i++
		case "--exit-code":
			if i+1 >= len(args) {
				return errors.New("--exit-code requires a positive integer")
			}
			exitCode, err := strconv.Atoi(args[i+1])
			if err != nil || exitCode <= 0 {
				return fmt.Errorf("invalid --exit-code value: %s", args[i+1])
			}
			ciOptions.ExitCode = exitCode
			i++
		case "--help", "-h":
			fmt.Println("Usage: docker otty multi <image1> <image2> ... [--images <img1,img2>] [--containers|--container] [--running-containers|--running-container] [--config <path>] [--output-dir <dir>] [--format <txt|json|md>] [--top <n>] [--timeout <seconds>] [--scanners <csv>] [--workers <n>] [--fail-on <high|critical|none>] [--max-medium <n>] [--exit-code <n>]")
			fmt.Println("Tip: if no image is provided, scan_images from config and optional container discovery will be used.")
			return nil
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown multi argument: %s", args[i])
			}
			appendImageCandidates(&images, args[i])
		}
	}

	cfg, cfgPath, err := loadConfigInteractive(configPath, opts)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.ScanInstalledContainers {
		includeInstalledContainers = true
	}
	if cfg.ScanRunningContainers {
		includeRunningContainers = true
	}

	if len(images) == 0 {
		if len(args) == 0 && !opts.NoInput {
			if len(cfg.ScanImages) > 0 {
				useConfigImages := confirm(opts, fmt.Sprintf("Use %d image(s) from config scan_images?", len(cfg.ScanImages)), true)
				if useConfigImages {
					for _, image := range cfg.ScanImages {
						appendImageCandidates(&images, image)
					}
				} else {
					appendImageCandidates(&images, askNonEmpty("Enter Docker images separated by comma"))
				}
			} else if !includeInstalledContainers && !includeRunningContainers {
				appendImageCandidates(&images, askNonEmpty("Enter Docker images separated by comma"))
			}
		} else {
			for _, image := range cfg.ScanImages {
				appendImageCandidates(&images, image)
			}
		}
	}
	installedContainerImages := make([]string, 0)
	runningContainerImages := make([]string, 0)
	if includeInstalledContainers {
		discovered, discoverErr := listInstalledContainerImages()
		if discoverErr != nil {
			return fmt.Errorf("failed to discover installed container images: %w", discoverErr)
		}
		installedContainerImages = append(installedContainerImages, discovered...)
		images = append(images, discovered...)
	}
	if includeRunningContainers && !includeInstalledContainers {
		discovered, discoverErr := listRunningContainerImages()
		if discoverErr != nil {
			return fmt.Errorf("failed to discover running container images: %w", discoverErr)
		}
		runningContainerImages = append(runningContainerImages, discovered...)
		images = append(images, discovered...)
	}
	if len(images) == 0 {
		if opts.NoInput {
			if includeInstalledContainers {
				return errors.New("no image provided, scan_images is empty in config, and no installed containers were found")
			}
			if includeRunningContainers {
				return errors.New("no image provided, scan_images is empty in config, and no running containers were found")
			}
			return errors.New("no image provided and scan_images is empty in config")
		}
		appendImageCandidates(&images, askNonEmpty("Enter Docker images separated by comma"))
	}

	images, err = normalizeImages(images)
	if err != nil {
		return err
	}

	fmt.Printf("Config: %s\n", cfgPath)
	fmt.Printf("Trivy source: %s\n", cfg.TrivyURL)
	if includeInstalledContainers {
		fmt.Printf("Installed container images discovered: %d\n", len(installedContainerImages))
	}
	if includeRunningContainers && !includeInstalledContainers {
		fmt.Printf("Running container images discovered: %d\n", len(runningContainerImages))
	}
	fmt.Printf("Images selected for multi scan (%d): %s\n", len(images), strings.Join(images, ", "))

	if !confirm(opts, "Check and prepare Trivy binary if needed?", true) {
		return errors.New("operation cancelled")
	}
	bin, err := trivy.EnsureTrivy(cfg.TrivyURL, ".")
	if err != nil {
		return fmt.Errorf("failed to prepare Trivy: %w", err)
	}

	outDirInput := cfg.OutputDir
	if strings.TrimSpace(outputDirOverride) != "" {
		outDirInput = outputDirOverride
	}
	outDir, err := resolveOutputDir(outDirInput)
	if err != nil {
		return err
	}
	if workers > len(images) {
		workers = len(images)
	}
	if workers <= 0 {
		workers = 1
	}

	if !confirm(opts, fmt.Sprintf("Start multiple scan for %d image(s)?", len(images)), true) {
		return errors.New("operation cancelled")
	}

	workerScanOptions := scanOptions
	if workers > 1 {
		if err := prepareTrivyDatabases(bin, scanOptions); err != nil {
			fmt.Println("Warning: failed to prepare Trivy DB for parallel mode:", err)
			fmt.Println("Continuing with parallel scan; some workers may retry slower if cache is busy.")
		}
		workerScanOptions.SkipDBUpdate = true
	}

	tasks := make(chan multiTask, len(images))
	results := make(chan multiResult, len(images))
	for w := 0; w < workers; w++ {
		go func() {
			for task := range tasks {
				summary, severity, explanations, scanErr := runSingleScan(bin, task.Image, task.OutFile, workerScanOptions)
				results <- multiResult{
					Task:         task,
					Summary:      summary,
					Severity:     severity,
					Explanations: explanations,
					Err:          scanErr,
				}
			}
		}()
	}

	for idx, image := range images {
		outFile := filepath.Join(outDir, fmt.Sprintf("%s-scan-%s%s", sanitizeScanFileName(image), timestampSuffix(time.Now()), reportFileExtension(scanOptions.ReportFormat)))
		tasks <- multiTask{Index: idx, Image: image, OutFile: outFile}
	}
	close(tasks)

	orderedResults := make([]multiResult, len(images))
	for i := 0; i < len(images); i++ {
		result := <-results
		orderedResults[result.Task.Index] = result
	}

	combined := scanSummary{}
	combinedSeverity := severityCounts{}
	successCount := 0
	failedCount := 0
	ciFailures := make([]string, 0)
	summaryPayload := multiSummaryReport{
		RunAt:       time.Now().Format(time.RFC3339),
		Format:      scanOptions.ReportFormat,
		Workers:     workers,
		TotalImages: len(images),
		Images:      make([]multiSummaryImage, 0, len(images)),
	}

	for idx, result := range orderedResults {
		fmt.Printf("[%d/%d] Scanning: %s\n", idx+1, len(images), result.Task.Image)
		if result.Err != nil {
			failedCount++
			fmt.Println("Scan error:", result.Err)
			summaryPayload.Images = append(summaryPayload.Images, multiSummaryImage{
				Image:            result.Task.Image,
				Status:           "failed",
				Error:            result.Err.Error(),
				CIGateStatus:     "not-evaluated",
				CleanTargetCount: 0,
			})
			continue
		}

		successCount++
		combined.DefiniteMalicious += result.Summary.DefiniteMalicious
		combined.Suspicious += result.Summary.Suspicious
		combined.Safe += result.Summary.Safe
		combinedSeverity.Critical += result.Severity.Critical
		combinedSeverity.High += result.Severity.High
		combinedSeverity.Medium += result.Severity.Medium
		combinedSeverity.Low += result.Severity.Low
		combinedSeverity.Unknown += result.Severity.Unknown

		fmt.Printf(
			"Critical/High Risk Finding Count: %d - Medium/Low Risk Finding Count: %d - Clean Target Count: %d\n",
			result.Summary.DefiniteMalicious, result.Summary.Suspicious, result.Summary.Safe,
		)
		fmt.Println("Top Trivy Risk Explanations:")
		for _, item := range result.Explanations {
			fmt.Println("-", item)
		}
		fmt.Println("Report:", result.Task.OutFile)

		imageEntry := multiSummaryImage{
			Image:                        result.Task.Image,
			Status:                       "success",
			Report:                       result.Task.OutFile,
			CriticalHighRiskFindingCount: result.Summary.DefiniteMalicious,
			MediumLowRiskFindingCount:    result.Summary.Suspicious,
			CleanTargetCount:             result.Summary.Safe,
			CriticalFindingCount:         result.Severity.Critical,
			HighFindingCount:             result.Severity.High,
			MediumFindingCount:           result.Severity.Medium,
			LowFindingCount:              result.Severity.Low,
			UnknownFindingCount:          result.Severity.Unknown,
			CIGateStatus:                 "pass",
		}
		violations := evaluateCIGate(result.Severity, ciOptions)
		if len(violations) > 0 {
			imageEntry.CIGateStatus = "fail"
			ciFailures = append(ciFailures, fmt.Sprintf("%s => %s", result.Task.Image, strings.Join(violations, ", ")))
		}
		summaryPayload.Images = append(summaryPayload.Images, imageEntry)
	}

	summaryPayload.SuccessCount = successCount
	summaryPayload.FailedCount = failedCount
	summaryPayload.CombinedCriticalHighFindings = combined.DefiniteMalicious
	summaryPayload.CombinedMediumLowFindings = combined.Suspicious
	summaryPayload.CombinedCleanTargets = combined.Safe
	summaryPayload.CombinedCriticalFindings = combinedSeverity.Critical
	summaryPayload.CombinedHighFindings = combinedSeverity.High
	summaryPayload.CombinedMediumFindings = combinedSeverity.Medium
	summaryPayload.CombinedLowFindings = combinedSeverity.Low
	summaryPayload.CombinedUnknownFindings = combinedSeverity.Unknown

	summaryFile, summaryErr := writeMultiSummaryReport(outDir, summaryPayload)
	if summaryErr != nil {
		return summaryErr
	}

	fmt.Printf("Multiple scan finished. Success: %d, Failed: %d\n", successCount, failedCount)
	fmt.Printf(
		"Combined Critical/High Risk Findings: %d - Combined Medium/Low Risk Findings: %d - Combined Clean Targets: %d\n",
		combined.DefiniteMalicious, combined.Suspicious, combined.Safe,
	)
	fmt.Println("Summary Report:", summaryFile)

	if successCount == 0 {
		return errors.New("all scans failed")
	}

	errorParts := make([]string, 0)
	if failedCount > 0 {
		errorParts = append(errorParts, fmt.Sprintf("%d scan(s) failed", failedCount))
	}
	if len(ciFailures) > 0 {
		errorParts = append(errorParts, fmt.Sprintf("CI gate failed for %d image(s): %s", len(ciFailures), strings.Join(ciFailures, " | ")))
		return &commandError{
			message:  strings.Join(errorParts, " ; "),
			exitCode: ciOptions.ExitCode,
		}
	}
	if len(errorParts) > 0 {
		return errors.New(strings.Join(errorParts, " ; "))
	}
	return nil
}

func resolveRunOutputPath(configOutDir, explicitOutput, image, reportFormat string) (string, error) {
	ts := timestampSuffix(time.Now())
	if strings.TrimSpace(explicitOutput) != "" {
		clean := filepath.Clean(explicitOutput)
		dir := filepath.Dir(clean)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("failed to create output directory: %w", err)
		}
		ext := filepath.Ext(clean)
		base := strings.TrimSuffix(filepath.Base(clean), ext)
		if ext == "" {
			ext = reportFileExtension(reportFormat)
		}
		fileName := fmt.Sprintf("%s-%s%s", base, ts, ext)
		return filepath.Join(dir, fileName), nil
	}

	outDir := strings.TrimSpace(configOutDir)
	if outDir == "" {
		outDir = "."
	}
	outDir = filepath.Clean(outDir)
	if outDir == ".." || outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	fileName := fmt.Sprintf("%s-scan-%s%s", sanitizeScanFileName(image), ts, reportFileExtension(reportFormat))
	return filepath.Join(outDir, fileName), nil
}

func resolveOutputDir(dir string) (string, error) {
	outDir := strings.TrimSpace(dir)
	if outDir == "" {
		outDir = "."
	}
	outDir = filepath.Clean(outDir)
	if outDir == ".." || outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}
	return outDir, nil
}

func writeMultiSummaryReport(outDir string, summary multiSummaryReport) (string, error) {
	filePath := filepath.Join(outDir, fmt.Sprintf("summary-%s.json", timestampSuffix(time.Now())))
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize summary report: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write summary report: %w", err)
	}
	return filePath, nil
}

func daemonCommand(args []string, opts appOptions) error {
	configPath := "config.yaml"
	interval := 3600
	once := false
	scanOptions := defaultScanExecOptions()
	includeInstalledContainers := false
	includeRunningContainers := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 >= len(args) {
				return errors.New("--interval requires seconds value")
			}
			parsed, err := strconv.Atoi(args[i+1])
			if err != nil || parsed <= 0 {
				return fmt.Errorf("invalid interval value: %s", args[i+1])
			}
			interval = parsed
			i++
		case "--config":
			if i+1 >= len(args) {
				return errors.New("--config requires file path")
			}
			configPath = args[i+1]
			i++
		case "--format":
			if i+1 >= len(args) {
				return errors.New("--format requires a value (txt|json|md)")
			}
			format, err := normalizeReportFormat(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.ReportFormat = format
			i++
		case "--top":
			if i+1 >= len(args) {
				return errors.New("--top requires a positive integer")
			}
			top, err := strconv.Atoi(args[i+1])
			if err != nil || top <= 0 {
				return fmt.Errorf("invalid --top value: %s", args[i+1])
			}
			scanOptions.ExplanationLimit = top
			i++
		case "--timeout":
			if i+1 >= len(args) {
				return errors.New("--timeout requires a positive integer (seconds)")
			}
			timeout, err := strconv.Atoi(args[i+1])
			if err != nil || timeout <= 0 {
				return fmt.Errorf("invalid --timeout value: %s", args[i+1])
			}
			scanOptions.TimeoutSeconds = timeout
			i++
		case "--scanners":
			if i+1 >= len(args) {
				return errors.New("--scanners requires a comma-separated list")
			}
			scanners, err := parseScanners(args[i+1])
			if err != nil {
				return err
			}
			scanOptions.Scanners = scanners
			i++
		case "--containers", "--container":
			includeInstalledContainers = true
		case "--running-containers", "--running-container":
			includeRunningContainers = true
		case "--once":
			once = true
		case "--help", "-h":
			fmt.Println("Usage: docker otty daemon [--interval <seconds>] [--config <path>] [--format <txt|json|md>] [--top <n>] [--timeout <seconds>] [--scanners <csv>] [--containers|--container] [--running-containers|--running-container] [--once]")
			return nil
		default:
			return fmt.Errorf("unknown daemon argument: %s", args[i])
		}
	}

	if len(args) == 0 && !opts.NoInput {
		if confirm(opts, "Use a different config file?", false) {
			configPath = askNonEmpty("Enter config file path")
		}
		interval = askIntWithDefault("Scan interval (seconds)", interval)
	}

	cfg, cfgPath, err := loadConfigInteractive(configPath, opts)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if cfg.ScanInstalledContainers {
		includeInstalledContainers = true
	}
	if cfg.ScanRunningContainers {
		includeRunningContainers = true
	}
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	if interval <= 0 {
		interval = 3600
	}
	if len(cfg.ScanImages) == 0 && !includeInstalledContainers && !includeRunningContainers {
		return errors.New("scan_images is empty in config and container discovery is disabled")
	}

	if !once && !confirm(opts, fmt.Sprintf("Start daemon mode? Interval: %d seconds", interval), true) {
		return errors.New("operation cancelled")
	}

	bin, err := trivy.EnsureTrivy(cfg.TrivyURL, ".")
	if err != nil {
		return fmt.Errorf("failed to prepare Trivy: %w", err)
	}

	outDir, err := resolveOutputDir(cfg.OutputDir)
	if err != nil {
		return err
	}

	fmt.Printf("Daemon config: %s\n", cfgPath)
	fmt.Printf("Daemon started. Interval: %d seconds\n", interval)
	for {
		cycleImages := make([]string, 0, len(cfg.ScanImages)+8)
		for _, image := range cfg.ScanImages {
			appendImageCandidates(&cycleImages, image)
		}

		containerImages := make([]string, 0)
		if includeInstalledContainers {
			discovered, discoverErr := listInstalledContainerImages()
			if discoverErr != nil {
				if once {
					return fmt.Errorf("failed to discover installed container images: %w", discoverErr)
				}
				fmt.Println("Container discovery error:", discoverErr)
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}
			containerImages = append(containerImages, discovered...)
			cycleImages = append(cycleImages, discovered...)
			fmt.Printf("Installed container images discovered: %d\n", len(containerImages))
		} else if includeRunningContainers {
			discovered, discoverErr := listRunningContainerImages()
			if discoverErr != nil {
				if once {
					return fmt.Errorf("failed to discover running container images: %w", discoverErr)
				}
				fmt.Println("Running container discovery error:", discoverErr)
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}
			containerImages = append(containerImages, discovered...)
			cycleImages = append(cycleImages, discovered...)
			fmt.Printf("Running container images discovered: %d\n", len(containerImages))
		}

		seen := make(map[string]struct{}, len(cycleImages))
		validImages := make([]string, 0, len(cycleImages))
		for _, raw := range cycleImages {
			image := strings.TrimSpace(raw)
			if isPlaceholderContainerImage(image) {
				continue
			}
			if !isValidImageName(image) {
				fmt.Println("Skipped invalid image:", image)
				continue
			}
			if _, ok := seen[image]; ok {
				continue
			}
			seen[image] = struct{}{}
			validImages = append(validImages, image)
		}

		if len(validImages) == 0 {
			if once {
				return errors.New("no valid images to scan from scan_images and selected container discovery sources")
			}
			fmt.Println("No valid images to scan in this cycle.")
			time.Sleep(time.Duration(interval) * time.Second)
			continue
		}

		for _, image := range validImages {
			outFile := filepath.Join(outDir, fmt.Sprintf("%s-scan-%s%s", sanitizeScanFileName(image), timestampSuffix(time.Now()), reportFileExtension(scanOptions.ReportFormat)))
			fmt.Println("Scanning:", image)
			summary, _, explanations, err := runSingleScan(bin, image, outFile, scanOptions)
			if err != nil {
				fmt.Println("Scan error:", err)
				continue
			}
			fmt.Printf(
				"Critical/High Risk Finding Count: %d - Medium/Low Risk Finding Count: %d - Clean Target Count: %d\n",
				summary.DefiniteMalicious, summary.Suspicious, summary.Safe,
			)
			fmt.Println("Top Trivy Risk Explanations:")
			for _, item := range explanations {
				fmt.Println("-", item)
			}
			fmt.Println("Report written:", outFile)
		}
		if once {
			fmt.Println("Daemon loop finished due to --once.")
			return nil
		}
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func runSingleScan(trivyBin, image, outFile string, options scanExecOptions) (scanSummary, severityCounts, []string, error) {
	var summary scanSummary
	var severity severityCounts
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
	if options.SkipDBUpdate && scannerEnabled(options.Scanners, "vuln") {
		trivyArgs = append(trivyArgs, "--skip-db-update", "--skip-java-db-update")
	}
	trivyArgs = append(trivyArgs, image)

	cmd := exec.CommandContext(ctx, trivyBin, trivyArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return summary, severity, nil, fmt.Errorf("trivy command timed out (%d seconds)", timeoutSeconds)
	}

	trivyStdout := strings.TrimSpace(stdout.String())
	trivyStderr := strings.TrimSpace(stderr.String())
	if err != nil && trivyStdout == "" {
		return summary, severity, nil, fmt.Errorf("trivy command failed: %w. stderr: %s", err, trivyStderr)
	}
	if trivyStdout == "" {
		return summary, severity, nil, errors.New("trivy did not return JSON output")
	}

	var parsed trivyReport
	if parseErr := json.Unmarshal(stdout.Bytes(), &parsed); parseErr != nil {
		return summary, severity, nil, fmt.Errorf("failed to parse trivy JSON output: %w", parseErr)
	}

	summary, severity = analyzeTrivyReport(parsed)
	explanationLimit := options.ExplanationLimit
	if explanationLimit <= 0 {
		explanationLimit = 5
	}
	explanations := buildRiskExplanations(parsed, explanationLimit)
	if len(explanations) == 0 {
		explanations = []string{"No package-level vulnerability explanation could be generated from this scan."}
	}

	format, formatErr := normalizeReportFormat(options.ReportFormat)
	if formatErr != nil {
		return summary, severity, explanations, formatErr
	}
	report, reportErr := buildReportContent(format, image, time.Now(), summary, severity, explanations, trivyStderr, parsed, trivyStdout)
	if reportErr != nil {
		return summary, severity, explanations, reportErr
	}

	if writeErr := os.WriteFile(outFile, []byte(report), 0644); writeErr != nil {
		return summary, severity, explanations, fmt.Errorf("failed to write report: %w", writeErr)
	}
	if err != nil {
		return summary, severity, explanations, fmt.Errorf("trivy command failed: %w", err)
	}
	return summary, severity, explanations, nil
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
	commandHint := remediationCommandHint(result, vuln)
	if commandHint != "" {
		remediation = remediation + " Suggested command: " + commandHint
	}

	reference := strings.TrimSpace(vuln.PrimaryURL)
	refText := ""
	if reference != "" {
		refText = " Ref: " + reference
	}

	return fmt.Sprintf("[%s] %s in %s has %s. %s %s%s", severity, pkg, target, vulnID, impact, remediation, refText)
}

func remediationCommandHint(result trivyResult, vuln trivyFinding) string {
	pkg := strings.TrimSpace(vuln.PkgName)
	if pkg == "" {
		return ""
	}
	resultType := strings.ToLower(strings.TrimSpace(result.Type))
	target := strings.ToLower(strings.TrimSpace(result.Target))
	switch {
	case strings.Contains(resultType, "alpine") || strings.Contains(target, "alpine"):
		return fmt.Sprintf("apk update && apk add --upgrade %s", pkg)
	case strings.Contains(resultType, "debian") || strings.Contains(resultType, "ubuntu") ||
		strings.Contains(target, "debian") || strings.Contains(target, "ubuntu"):
		return fmt.Sprintf("apt-get update && apt-get install --only-upgrade %s", pkg)
	case strings.Contains(resultType, "redhat") || strings.Contains(resultType, "rhel") ||
		strings.Contains(resultType, "centos") || strings.Contains(target, "redhat") ||
		strings.Contains(target, "rhel") || strings.Contains(target, "centos"):
		return fmt.Sprintf("yum update -y %s", pkg)
	case strings.Contains(resultType, "node") || strings.Contains(target, "node.js"):
		return fmt.Sprintf("npm i %s@latest", pkg)
	case strings.Contains(resultType, "python") || strings.Contains(target, "python"):
		return fmt.Sprintf("pip install --upgrade %s", pkg)
	case strings.Contains(resultType, "golang") || strings.Contains(resultType, "go"):
		return fmt.Sprintf("go get -u %s", pkg)
	default:
		return ""
	}
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		t := strings.TrimSpace(v)
		if t != "" {
			return t
		}
	}
	return ""
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

func loadConfigInteractive(path string, opts appOptions) (*config.Config, string, error) {
	cfg, err := config.LoadConfig(path)
	if err == nil {
		if strings.TrimSpace(cfg.TrivyURL) == "" {
			return nil, "", errors.New("trivy_url is empty in config")
		}
		return cfg, path, nil
	}
	if opts.NoInput {
		return nil, "", err
	}

	fmt.Printf("Failed to load config (%s): %v\n", path, err)
	if !confirm(opts, "Do you want to enter another config path?", true) {
		return nil, "", err
	}

	newPath := askNonEmpty("Enter config file path")
	cfg, err = config.LoadConfig(newPath)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(cfg.TrivyURL) == "" {
		return nil, "", errors.New("trivy_url is empty in config")
	}
	return cfg, newPath, nil
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

func appendImageCandidates(images *[]string, input string) {
	for _, piece := range strings.Split(input, ",") {
		candidate := strings.TrimSpace(piece)
		if candidate == "" {
			continue
		}
		*images = append(*images, candidate)
	}
}

func normalizeImages(images []string) ([]string, error) {
	normalized := make([]string, 0, len(images))
	seen := make(map[string]struct{}, len(images))
	invalid := make([]string, 0)

	for _, raw := range images {
		image := strings.TrimSpace(raw)
		if image == "" {
			continue
		}
		if !isValidImageName(image) {
			invalid = append(invalid, image)
			continue
		}
		if _, ok := seen[image]; ok {
			continue
		}
		seen[image] = struct{}{}
		normalized = append(normalized, image)
	}

	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid image name(s): %s", strings.Join(invalid, ", "))
	}
	if len(normalized) == 0 {
		return nil, errors.New("no valid images to scan")
	}
	return normalized, nil
}

func sanitizeScanFileName(image string) string {
	name := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(image)
	if name == "" {
		return "scan"
	}
	return name
}

func confirm(opts appOptions, question string, defaultYes bool) bool {
	if opts.AutoYes {
		return true
	}
	if opts.NoInput {
		return defaultYes
	}
	return askYesNo(question, defaultYes)
}

func askYesNo(question string, defaultYes bool) bool {
	hint := "Y/n"
	if !defaultYes {
		hint = "y/N"
	}
	for {
		fmt.Printf("%s [%s]: ", question, hint)
		input := readLine()
		if input == "" {
			return defaultYes
		}
		switch strings.ToLower(input) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		default:
			fmt.Println("Please enter y or n.")
		}
	}
}

func timestampSuffix(t time.Time) string {
	return t.Format("20060102-150405")
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

func askNonEmpty(question string) string {
	for {
		fmt.Printf("%s: ", question)
		input := strings.TrimSpace(readLine())
		if input != "" {
			return input
		}
		fmt.Println("This field cannot be empty.")
	}
}

func askIntWithDefault(question string, def int) int {
	for {
		fmt.Printf("%s [%d]: ", question, def)
		input := strings.TrimSpace(readLine())
		if input == "" {
			return def
		}
		v, err := strconv.Atoi(input)
		if err == nil && v > 0 {
			return v
		}
		fmt.Println("Please enter a positive integer.")
	}
}

func readLine() string {
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return strings.TrimSpace(line)
	}
	return strings.TrimSpace(line)
}
