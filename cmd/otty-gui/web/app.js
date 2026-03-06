const imageInput = document.getElementById("image");
const formatInput = document.getElementById("format");
const timeoutInput = document.getElementById("timeout");
const scannersInput = document.getElementById("scanners");
const runBtn = document.getElementById("runBtn");
const statusEl = document.getElementById("status");

const mCritical = document.getElementById("mCritical");
const mHigh = document.getElementById("mHigh");
const mMedium = document.getElementById("mMedium");
const mLow = document.getElementById("mLow");
const mUnknown = document.getElementById("mUnknown");
const mSafe = document.getElementById("mSafe");
const reportPath = document.getElementById("reportPath");
const runAt = document.getElementById("runAt");
const explanations = document.getElementById("explanations");
const rawJson = document.getElementById("rawJson");

function setStatus(message, type) {
  statusEl.textContent = message;
  statusEl.className = "status";
  if (type) {
    statusEl.classList.add(type);
  }
}

function renderExplanations(items) {
  explanations.innerHTML = "";
  if (!Array.isArray(items) || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No explanation available.";
    explanations.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    explanations.appendChild(li);
  }
}

function setMetrics(severity, summary) {
  mCritical.textContent = String(severity?.critical ?? 0);
  mHigh.textContent = String(severity?.high ?? 0);
  mMedium.textContent = String(severity?.medium ?? 0);
  mLow.textContent = String(severity?.low ?? 0);
  mUnknown.textContent = String(severity?.unknown ?? 0);
  mSafe.textContent = String(summary?.clean_target_count ?? 0);
}

async function loadDefaults() {
  try {
    const res = await fetch("/api/config");
    if (!res.ok) {
      return;
    }
    const cfg = await res.json();
    if (Array.isArray(cfg.scan_images) && cfg.scan_images.length > 0) {
      imageInput.value = String(cfg.scan_images[0]);
    }
  } catch {
    // Keep UI defaults if config endpoint cannot be reached.
  }
}

async function runScan() {
  const payload = {
    image: imageInput.value.trim(),
    format: formatInput.value,
    timeout_seconds: Number(timeoutInput.value),
    scanners: scannersInput.value.trim(),
    top: 5,
  };

  runBtn.disabled = true;
  setStatus("Scanning...", "");
  rawJson.value = "";
  reportPath.textContent = "-";
  runAt.textContent = "-";
  renderExplanations([]);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || "Scan failed");
    }

    setMetrics(data.severity, data.summary);
    renderExplanations(data.explanations);
    reportPath.textContent = data.report_path || "-";
    runAt.textContent = data.run_at || "-";
    rawJson.value = data.trivy_raw_json || "";
    setStatus("Scan completed", "ok");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    setStatus(message, "error");
  } finally {
    runBtn.disabled = false;
  }
}

runBtn.addEventListener("click", runScan);
loadDefaults();
