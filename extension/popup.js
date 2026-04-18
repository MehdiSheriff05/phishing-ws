const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const resultContentEl = document.getElementById("resultContent");
const blockDomainBtn = document.getElementById("blockDomainBtn");
const allowDomainBtn = document.getElementById("allowDomainBtn");

// These variables keep the latest scan available for the allowlist and blocklist buttons.
let lastScanPayload = null;
let lastPrediction = null;

// Read the currently selected browser tab so scans target the page the user is viewing.
function getActiveTabInfo() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      // Chrome extension APIs report errors through runtime.lastError.
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!tabs || !tabs[0]?.id) {
        reject(new Error("No active tab found"));
        return;
      }
      // Store both ID and URL so cached scan results can be tied to the correct page.
      resolve({ tabId: tabs[0].id, tabUrl: tabs[0].url || "" });
    });
  });
}

// Read the backend URL from extension storage, falling back to the local FastAPI server.
function getApiBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiBaseUrl"], (result) => {
      resolve(result.apiBaseUrl || "http://127.0.0.1:8000");
    });
  });
}

// Send a JSON POST request to FastAPI for actions such as blocklisting and allowlisting.
async function apiPost(path, body) {
  const apiBaseUrl = await getApiBaseUrl();
  // Preference actions call FastAPI directly from the popup.
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

// Find the first link domain in the scanned page because preferences are domain-based.
function extractPrimaryDomainFromPayload(payload) {
  if (!payload?.links?.length) return "";
  for (const link of payload.links) {
    // The first valid linked domain is treated as the page's main actionable domain.
    const href = (link.href || "").trim();
    if (!href) continue;
    try {
      const url = new URL(href);
      const host = (url.hostname || "").replace(/^www\./, "").toLowerCase();
      if (host) return host;
    } catch (_) {
      // Fallback parsing handles plain domains that are not valid absolute URLs.
      const fallback = href.replace(/^https?:\/\//i, "").split("/")[0].replace(/^www\./, "").toLowerCase();
      if (fallback && fallback.includes(".")) return fallback;
    }
  }
  return "";
}

// Show the prediction result in the popup using the label, probability, and backend flags.
function renderResult(data) {
  const probValue = Number(data.probability_phishing || 0).toFixed(2);
  const labelClass = data.label === "phishing" ? "phishing" : "legitimate";

  // Flags are the explanation list, so they are shown directly under the score.
  const flagsHtml = (data.flags || []).length
    ? `<ul>${data.flags.map((f) => `<li>${f}</li>`).join("")}</ul>`
    : "<div>No warning flags found.</div>";

  // The popup intentionally keeps the result compact for screenshots and demos.
  resultContentEl.innerHTML = `
    <div>Label: <span class="${labelClass}">${data.label}</span></div>
    <div>Phishing probability: <strong>${probValue}</strong></div>
    <div>Flags:</div>
    ${flagsHtml}
  `;
  resultEl.hidden = false;
}

// Store a scan response locally so follow-up actions operate on the same scanned page.
function handleScanResponse(response, successStatus = "Scan complete.") {
  if (chrome.runtime.lastError) {
    statusEl.textContent = `Error: ${chrome.runtime.lastError.message}`;
    return;
  }

  if (!response?.ok) {
    statusEl.textContent = `Error: ${response?.error || "Unknown error"}`;
    return;
  }

  const result = response.data || {};
  // Store the latest payload/prediction for allowlist and blocklist button actions.
  lastScanPayload = result.payload || null;
  lastPrediction = result.prediction || null;

  if (!lastPrediction) {
    statusEl.textContent = "Error: invalid prediction response.";
    return;
  }

  statusEl.textContent = successStatus;
  renderResult(lastPrediction);
}

// Ask the background service worker to scan the current tab and return the prediction.
function requestScan(tabInfo, { preferCached = false, successStatus = "Scan complete." } = {}) {
  return new Promise((resolve, reject) => {
    // The service worker performs extraction and API calls because it has the right permissions.
    chrome.runtime.sendMessage(
      { type: "SCAN_CURRENT_PAGE", ...tabInfo, preferCached },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response?.ok) {
          reject(new Error(response?.error || "Unknown error"));
          return;
        }
        handleScanResponse(response, successStatus);
        resolve(response.data || {});
      }
    );
  });
}

// Load a cached auto-scan result quickly, then refresh so Gmail/page changes do not show stale results.
async function loadAutoScanResult() {
  let tabInfo;
  try {
    // Loading cached results avoids an empty popup while a fresh scan is running.
    tabInfo = await getActiveTabInfo();
    const { tabId, tabUrl } = tabInfo;
    chrome.runtime.sendMessage(
      { type: "GET_LAST_SCAN_FOR_ACTIVE_TAB", tabId, tabUrl },
      (response) => {
        if (!chrome.runtime.lastError && response?.ok && response.data?.prediction) {
          lastScanPayload = response.data.payload || null;
          lastPrediction = response.data.prediction || null;
          if (lastPrediction) {
            statusEl.textContent = "Auto scan result loaded. Refreshing...";
            renderResult(lastPrediction);
          }
        }
      }
    );
  } catch (_) {
    return;
  }

  try {
    // A fresh scan prevents Gmail page changes from displaying stale keyword explanations.
    await requestScan(tabInfo, { preferCached: false, successStatus: "Scan refreshed for current page." });
  } catch (_) {}
}

// Manual scans always request fresh page content instead of reusing stale cached data.
scanBtn.addEventListener("click", async () => {
  statusEl.textContent = "Scanning...";
  resultEl.hidden = true;
  scanBtn.disabled = true;

  let tabInfo;
  try {
    // Manual scanning always targets the currently active tab.
    tabInfo = await getActiveTabInfo();
  } catch (error) {
    scanBtn.disabled = false;
    statusEl.textContent = `Error: ${error.message || error}`;
    return;
  }

  try {
    await requestScan(tabInfo, { preferCached: false, successStatus: "Scan complete." });
  } catch (error) {
    statusEl.textContent = `Error: ${error.message || error}`;
  } finally {
    scanBtn.disabled = false;
  }
});

// Blocklisting tells the backend to force a warning whenever this linked domain appears again.
blockDomainBtn.addEventListener("click", async () => {
  // The popup blocks domains, not entire URLs, because domains are easier to understand.
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

// Allowlisting lowers risk for clean pages, but the backend still warns if content looks phishing-like.
allowDomainBtn.addEventListener("click", async () => {
  // Allowlist reduces false positives but does not suppress strong phishing evidence.
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

// Start with the latest auto-scan result so the popup has useful information immediately.
loadAutoScanResult();
