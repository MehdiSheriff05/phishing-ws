const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const resultContentEl = document.getElementById("resultContent");
const reportSpamBtn = document.getElementById("reportSpamBtn");
const reportNotSpamBtn = document.getElementById("reportNotSpamBtn");
const blockDomainBtn = document.getElementById("blockDomainBtn");
const allowDomainBtn = document.getElementById("allowDomainBtn");

let lastScanPayload = null;
let lastPrediction = null;

function getApiBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiBaseUrl"], (result) => {
      resolve(result.apiBaseUrl || "http://127.0.0.1:8000");
    });
  });
}

async function apiPost(path, body) {
  const apiBaseUrl = await getApiBaseUrl();
  const response = await fetch(`${apiBaseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw new Error(`API ${path} failed (${response.status})`);
  }
  return response.json();
}

function extractPrimaryDomainFromPayload(payload) {
  if (!payload?.links?.length) return "";
  for (const link of payload.links) {
    const href = (link.href || "").trim();
    if (!href) continue;
    try {
      const url = new URL(href);
      const host = (url.hostname || "").replace(/^www\./, "").toLowerCase();
      if (host) return host;
    } catch (_) {
      const fallback = href.replace(/^https?:\/\//i, "").split("/")[0].replace(/^www\./, "").toLowerCase();
      if (fallback && fallback.includes(".")) return fallback;
    }
  }
  return "";
}

function renderResult(data) {
  const probPct = (data.probability_phishing * 100).toFixed(2);
  const labelClass = data.label === "phishing" ? "phishing" : "legitimate";

  const flagsHtml = (data.flags || []).length
    ? `<ul>${data.flags.map((f) => `<li>${f}</li>`).join("")}</ul>`
    : "<div>No warning flags found.</div>";

  resultContentEl.innerHTML = `
    <div>Label: <span class="${labelClass}">${data.label}</span></div>
    <div>Phishing probability: <strong>${probPct}%</strong></div>
    <div>Flags:</div>
    ${flagsHtml}
  `;
  resultEl.hidden = false;
}

scanBtn.addEventListener("click", () => {
  statusEl.textContent = "Scanning...";
  resultEl.hidden = true;
  scanBtn.disabled = true;

  chrome.runtime.sendMessage({ type: "SCAN_CURRENT_PAGE" }, (response) => {
    scanBtn.disabled = false;

    if (chrome.runtime.lastError) {
      statusEl.textContent = `Error: ${chrome.runtime.lastError.message}`;
      return;
    }

    if (!response?.ok) {
      statusEl.textContent = `Error: ${response?.error || "Unknown error"}`;
      return;
    }

    const result = response.data || {};
    lastScanPayload = result.payload || null;
    lastPrediction = result.prediction || null;

    if (!lastPrediction) {
      statusEl.textContent = "Error: invalid prediction response.";
      return;
    }

    statusEl.textContent = "Scan complete.";
    renderResult(lastPrediction);
  });
});

reportSpamBtn.addEventListener("click", async () => {
  if (!lastScanPayload) {
    statusEl.textContent = "Run a scan first.";
    return;
  }
  try {
    await apiPost("/feedback/report-spam", {
      visible_text: lastScanPayload.visible_text || "",
      links: lastScanPayload.links || [],
      source: "extension_popup"
    });
    statusEl.textContent = "Saved: marked as spam.";
  } catch (error) {
    statusEl.textContent = `Error: ${error.message || error}`;
  }
});

reportNotSpamBtn.addEventListener("click", async () => {
  if (!lastScanPayload) {
    statusEl.textContent = "Run a scan first.";
    return;
  }
  try {
    await apiPost("/feedback/report-not-spam", {
      visible_text: lastScanPayload.visible_text || "",
      links: lastScanPayload.links || [],
      source: "extension_popup"
    });
    statusEl.textContent = "Saved: marked as not spam.";
  } catch (error) {
    statusEl.textContent = `Error: ${error.message || error}`;
  }
});

blockDomainBtn.addEventListener("click", async () => {
  const domain = extractPrimaryDomainFromPayload(lastScanPayload);
  if (!domain) {
    statusEl.textContent = "No link domain found to block.";
    return;
  }
  try {
    await apiPost("/preferences/block", { domain });
    statusEl.textContent = `Blocked domain: ${domain}`;
  } catch (error) {
    statusEl.textContent = `Error: ${error.message || error}`;
  }
});

allowDomainBtn.addEventListener("click", async () => {
  const domain = extractPrimaryDomainFromPayload(lastScanPayload);
  if (!domain) {
    statusEl.textContent = "No link domain found to allow.";
    return;
  }
  try {
    await apiPost("/preferences/allow", { domain });
    statusEl.textContent = `Allowlisted domain: ${domain}`;
  } catch (error) {
    statusEl.textContent = `Error: ${error.message || error}`;
  }
});
