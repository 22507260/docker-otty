import React from "react";
import { createDockerDesktopClient } from "@docker/extension-api-client";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";

const ddClient = createDockerDesktopClient();
const TRIVY_IMAGE = "aquasec/trivy:0.69.3";
const TRIVY_CACHE_VOLUME = "otty-trivy-cache";
const TRIVY_TIMEOUT = "10m";
const MAX_RAW_OUTPUT_LENGTH = 250000;

type SeveritySummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  totalFindings: number;
  targetCount: number;
  cleanTargetCount: number;
};

const initialSummary: SeveritySummary = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  unknown: 0,
  totalFindings: 0,
  targetCount: 0,
  cleanTargetCount: 0,
};

function countSeverityValue(value: unknown, summary: SeveritySummary): void {
  const level = String(value ?? "").trim().toUpperCase();
  switch (level) {
    case "CRITICAL":
      summary.critical++;
      summary.totalFindings++;
      break;
    case "HIGH":
      summary.high++;
      summary.totalFindings++;
      break;
    case "MEDIUM":
      summary.medium++;
      summary.totalFindings++;
      break;
    case "LOW":
      summary.low++;
      summary.totalFindings++;
      break;
    case "UNKNOWN":
      summary.unknown++;
      summary.totalFindings++;
      break;
    default:
      if (level !== "") {
        summary.unknown++;
        summary.totalFindings++;
      }
      break;
  }
}

function parseTrivySummary(rawJson: string): SeveritySummary {
  const summary = { ...initialSummary };
  const parsed = JSON.parse(rawJson) as { Results?: any[] };
  const results = Array.isArray(parsed.Results) ? parsed.Results : [];
  summary.targetCount = results.length;

  for (const result of results) {
    let targetFindings = 0;
    const groups = [
      result?.Vulnerabilities,
      result?.Secrets,
      result?.Misconfigurations,
    ];
    for (const group of groups) {
      if (!Array.isArray(group)) {
        continue;
      }
      for (const finding of group) {
        const before = summary.totalFindings;
        countSeverityValue(finding?.Severity, summary);
        if (summary.totalFindings > before) {
          targetFindings++;
        }
      }
    }
    if (targetFindings === 0) {
      summary.cleanTargetCount++;
    }
  }

  return summary;
}

function extractJsonPayload(output: string): string {
  const trimmed = output.trim();
  if (!trimmed) {
    throw new Error("Trivy did not produce JSON output.");
  }

  try {
    JSON.parse(trimmed);
    return trimmed;
  } catch {
    const firstBrace = trimmed.indexOf("{");
    const lastBrace = trimmed.lastIndexOf("}");
    if (firstBrace >= 0 && lastBrace > firstBrace) {
      const candidate = trimmed.slice(firstBrace, lastBrace + 1);
      JSON.parse(candidate);
      return candidate;
    }
  }

  throw new Error("Trivy output was not valid JSON.");
}

function buildFailureMessage(code: number | undefined, stderrText: string, stdoutText: string): string {
  if (stderrText) {
    return stderrText;
  }
  if (stdoutText) {
    return stdoutText.slice(0, 800);
  }
  return `Trivy command failed (exit code: ${code ?? "unknown"}).`;
}

function truncateRawOutput(output: string): string {
  if (output.length <= MAX_RAW_OUTPUT_LENGTH) {
    return output;
  }
  return `${output.slice(0, MAX_RAW_OUTPUT_LENGTH)}\n\n[Output truncated for UI performance.]`;
}

export function App() {
  const [image, setImage] = React.useState("alpine:latest");
  const [isScanning, setIsScanning] = React.useState(false);
  const [summary, setSummary] = React.useState<SeveritySummary | null>(null);
  const [rawOutput, setRawOutput] = React.useState("");
  const [errorMessage, setErrorMessage] = React.useState("");
  const [lastRunAt, setLastRunAt] = React.useState("");

  const runScan = async () => {
    const targetImage = image.trim();
    if (!targetImage) {
      setErrorMessage("Image name is required.");
      return;
    }

    setIsScanning(true);
    setErrorMessage("");
    setSummary(null);
    setRawOutput("");

    try {
      const result = await ddClient.docker.cli.exec("run", [
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        `${TRIVY_CACHE_VOLUME}:/root/.cache/trivy`,
        TRIVY_IMAGE,
        "image",
        "--format",
        "json",
        "--quiet",
        "--timeout",
        TRIVY_TIMEOUT,
        "--cache-dir",
        "/root/.cache/trivy",
        "--scanners",
        "vuln",
        targetImage,
      ]);

      const stderrText = (result.stderr || "").trim();
      const stdoutText = (result.stdout || "").trim();

      if ((result.code ?? 0) !== 0) {
        throw new Error(buildFailureMessage(result.code, stderrText, stdoutText));
      }

      const jsonPayload = extractJsonPayload(stdoutText);
      const parsedSummary = parseTrivySummary(jsonPayload);
      setSummary(parsedSummary);
      setRawOutput(truncateRawOutput(jsonPayload));
      setLastRunAt(new Date().toISOString());
      ddClient.desktopUI.toast.success("Scan completed.");
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "An unknown error occurred during scan execution.";
      setErrorMessage(message);
      ddClient.desktopUI.toast.error("Scan failed.");
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4">Docker OTTY Scanner</Typography>
      <Typography variant="body1" color="text.secondary" sx={{ mt: 1 }}>
        Run Trivy-based image scans directly from Docker Desktop and review severity results.
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        The first scan can take a few minutes while Trivy downloads its vulnerability database.
      </Typography>

      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mt: 3 }}>
        <TextField
          label="Image"
          placeholder="alpine:latest"
          value={image}
          onChange={(event) => setImage(event.target.value)}
          fullWidth
        />
        <Button variant="contained" onClick={runScan} disabled={isScanning} sx={{ minWidth: 140 }}>
          {isScanning ? "Scanning..." : "Run Scan"}
        </Button>
      </Stack>

      {isScanning && (
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 2 }}>
          <CircularProgress size={20} />
          <Typography variant="body2">Running scan...</Typography>
        </Stack>
      )}

      {errorMessage && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {errorMessage}
        </Alert>
      )}

      {summary && (
        <Paper elevation={0} sx={{ mt: 3, p: 2, border: "1px solid", borderColor: "divider" }}>
          <Typography variant="h6">Scan Summary</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Last run: {lastRunAt}
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Total Findings: {summary.totalFindings}
          </Typography>
          <Typography variant="body2">Critical: {summary.critical}</Typography>
          <Typography variant="body2">High: {summary.high}</Typography>
          <Typography variant="body2">Medium: {summary.medium}</Typography>
          <Typography variant="body2">Low: {summary.low}</Typography>
          <Typography variant="body2">Unknown: {summary.unknown}</Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Targets: {summary.targetCount} (clean: {summary.cleanTargetCount})
          </Typography>
        </Paper>
      )}

      <TextField
        label="Raw Trivy JSON Output"
        sx={{ mt: 3, width: "100%" }}
        multiline
        minRows={10}
        value={rawOutput}
        InputProps={{ readOnly: true }}
      />
    </Box>
  );
}
