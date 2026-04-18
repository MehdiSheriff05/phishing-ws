const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const lastScanAtByTab = new Map();
const AUTO_SCAN_DEBOUNCE_MS = 1200;
const NOTIF_ID_PREFIX = "scan-result-";
const LIKELY_PHISHING_THRESHOLD = 0.6;
const LAST_SCAN_STORAGE_PREFIX = "lastScanResult:";
const LOW_CONTENT_TEXT_LEN = 80;
const LOW_CONTENT_LINK_COUNT = 2;
const FRESH_SCAN_WINDOW_MS = 15000;

// Read the FastAPI base URL from Chrome storage so the extension can work in local demos.
function getApiBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiBaseUrl"], (result) => {
      resolve(result.apiBaseUrl || DEFAULT_API_BASE_URL);
    });
  });
}

// Find the active browser tab because manual scans should scan what the user is viewing.
function getActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!tabs || !tabs[0]?.id) {
        reject(new Error("No active tab found"));
        return;
      }
      resolve(tabs[0]);
    });
  });
}

// Avoid Chrome-internal pages because extensions cannot inject normal content scripts there.
function isRestrictedUrl(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("edge://") ||
    url.startsWith("about:") ||
    url.startsWith("https://chrome.google.com/webstore")
  );
}

// Inject the content script on demand when Chrome has not already loaded it into the tab.
function injectContentScript(tabId) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId },
        files: ["content.js"]
      },
      () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve();
      }
    );
  });
}

// Ask content.js to extract visible text and links from the page before calling the API.
function requestPageData(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL_DATA" }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response?.ok) {
        reject(new Error(response?.error || "Failed to extract page data"));
        return;
      }
      resolve(response.data);
    });
  });
}

// Run a full scan for one tab: collect page data, call FastAPI, and return the prediction.
async function runScanForTab(tabId) {
  const tab = await new Promise((resolve, reject) => {
    chrome.tabs.get(tabId, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(result);
    });
  });

  if (isRestrictedUrl(tab.url)) {
    throw new Error("This page is restricted by Chrome. Open a normal website or webmail tab.");
  }

  let payload;
  try {
    payload = await requestPageData(tabId);
  } catch (error) {
    // Recover from "Receiving end does not exist" by injecting content script and retrying once.
    await injectContentScript(tabId);
    payload = await requestPageData(tabId);
  }

  const textLen = (payload?.visible_text || "").trim().length;
  const linkCount = Array.isArray(payload?.links) ? payload.links.length : 0;
  if (textLen < LOW_CONTENT_TEXT_LEN && linkCount < LOW_CONTENT_LINK_COUNT) {
    // Early auto scans can happen before page content settles; retry extraction once.
    await new Promise((resolve) => setTimeout(resolve, 1200));
    try {
      payload = await requestPageData(tabId);
    } catch (_) {}
  }

  const apiBaseUrl = await getApiBaseUrl();

  const response = await fetch(`${apiBaseUrl}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Backend error (${response.status})`);
  }

  const prediction = await response.json();
  return { prediction, payload, tabUrl: tab.url || "" };
}

// Convenience wrapper used by notification actions when the active tab should be rescanned.
async function scanCurrentPage() {
  const tab = await getActiveTab();
  return runScanForTab(tab.id);
}

// Retrieve a recent scan result so the popup can show immediate context while refreshing.
function getStoredScanForTab(tabId, pageUrl = "") {
  return new Promise((resolve) => {
    const key = `${LAST_SCAN_STORAGE_PREFIX}${tabId}`;
    chrome.storage.local.get([key], (result) => {
      const saved = result[key] || null;
      if (!saved) {
        resolve(null);
        return;
      }
      if (pageUrl && saved.pageUrl && saved.pageUrl !== pageUrl) {
        resolve(null);
        return;
      }
      const ageMs = Date.now() - Number(saved.updatedAt || 0);
      if (ageMs > FRESH_SCAN_WINDOW_MS) {
        resolve(null);
        return;
      }
      resolve(saved);
    });
  });
}

// Choose a clearer notification title for blocklist and allowlist risk cases.
function getNotificationTitle(prediction) {
  const flags = (prediction.flags || []).join(" ").toLowerCase();
  if (flags.includes("blocklist warning")) return "Blocked Site Warning";
  if (flags.includes("allowlist caution")) return "Allowlisted Site Looks Risky";
  return "Phishing Scan Complete";
}

// Display a browser notification when the scan detects medium or high phishing risk.
function showScanNotification(scanResult) {
  const prediction = scanResult.prediction || scanResult;
  const probability = Number(prediction.probability_phishing || 0).toFixed(2);
  const flagsText = (prediction.flags || []).slice(0, 2).join(" | ");
  const message = [
    `Label: ${prediction.label} (p=${probability})`,
    flagsText || "No warning flags.",
    "Open popup to scan manually anytime."
  ].join("\n");

  chrome.notifications.create(`${NOTIF_ID_PREFIX}${Date.now()}`, {
    type: "basic",
    iconUrl: "icon128.png",
    title: getNotificationTitle(prediction),
    message,
    buttons: [{ title: "Scan Again" }]
  });
}

// Save the last result and update the extension badge so users see risk without opening the popup.
function saveLastScanResult(tabId, scanResult, pageUrl = "") {
  const prediction = scanResult.prediction || scanResult;
  const payload = scanResult.payload || {};
  const key = `${LAST_SCAN_STORAGE_PREFIX}${tabId}`;
  chrome.storage.local.set({
    [key]: {
      tabId,
      pageUrl,
      updatedAt: Date.now(),
      prediction,
      payload
    }
  });

  const badge = prediction.label === "phishing" ? "!" : "";
  chrome.action.setBadgeText({ tabId, text: badge });
  chrome.action.setBadgeBackgroundColor({ tabId, color: prediction.label === "phishing" ? "#B91C1C" : "#0F766E" });
}

// Convert the probability score into display-friendly risk levels.
function getRiskLevel(probabilityPhishing) {
  if (probabilityPhishing >= 0.75) return "high";
  if (probabilityPhishing >= LIKELY_PHISHING_THRESHOLD) return "medium";
  return "low";
}

// Treat either an explicit phishing label or a high probability as a warning-worthy result.
function isLikelyPhishing(prediction) {
  if (!prediction) return false;
  return prediction.label === "phishing" || (prediction.probability_phishing || 0) >= LIKELY_PHISHING_THRESHOLD;
}

// Automatically scan page changes while avoiding repeated scans during fast Gmail updates.
function maybeAutoScan(tabId, _reason = "event") {
  const now = Date.now();
  const previous = lastScanAtByTab.get(tabId) || 0;
  if (now - previous < AUTO_SCAN_DEBOUNCE_MS) {
    return;
  }

  runScanForTab(tabId)
    .then((result) => {
      lastScanAtByTab.set(tabId, Date.now());
      const prediction = result.prediction || result;
      saveLastScanResult(tabId, result, result.tabUrl || "");
      const riskLevel = getRiskLevel(prediction.probability_phishing || 0);
      if ((riskLevel === "medium" || riskLevel === "high") && isLikelyPhishing(prediction)) {
        showScanNotification(result);
      }
    })
    .catch((error) => {
      const msg = String(error?.message || error || "");
      if (msg.toLowerCase().includes("restricted")) {
        return;
      }
      // Keep silent on transient auto-scan errors.
    });
}

// Route messages from popup.js and content.js into scan, cache, and auto-scan operations.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_CURRENT_PAGE") {
    const requestedTabId = Number(message.tabId || 0);
    const requestedTabUrl = String(message.tabUrl || "");
    const doScan = async () => {
      if (message.preferCached && requestedTabId > 0) {
        const cached = await getStoredScanForTab(requestedTabId, requestedTabUrl);
        if (cached?.prediction) {
          return { prediction: cached.prediction, payload: cached.payload || {}, tabUrl: cached.pageUrl || requestedTabUrl };
        }
      }
      if (requestedTabId > 0) {
        return runScanForTab(requestedTabId);
      }
      return scanCurrentPage();
    };

    doScan()
      .then(async (data) => {
        try {
          if (requestedTabId > 0) {
            saveLastScanResult(requestedTabId, data, requestedTabUrl || data.tabUrl || "");
          } else {
            const tab = await getActiveTab();
            saveLastScanResult(tab.id, data, tab.url || data.tabUrl || "");
          }
        } catch (_) {}
        sendResponse({ ok: true, data });
      })
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  if (message?.type === "AUTO_SCAN_TRIGGER") {
    if (_sender?.tab?.id) {
      maybeAutoScan(_sender.tab.id, "content_script");
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "GET_LAST_SCAN_FOR_ACTIVE_TAB") {
    const requestedTabId = Number(message.tabId || 0);
    const requestedTabUrl = String(message.tabUrl || "");
    const withKnownTab = requestedTabId > 0;
    const run = async () => {
      if (withKnownTab) {
        return getStoredScanForTab(requestedTabId, requestedTabUrl);
      }
      const tab = await getActiveTab();
      return getStoredScanForTab(tab.id, tab.url || "");
    };
    run()
      .then((data) => sendResponse({ ok: true, data: data || null }))
      .catch((error) => sendResponse({ ok: false, error: String(error.message || error) }));
    return true;
  }

  return false;
});

// Let users click the notification button to immediately rescan the active page.
chrome.notifications.onButtonClicked.addListener(async (_notificationId, buttonIndex) => {
  if (buttonIndex !== 0) {
    return;
  }
  try {
    const tab = await getActiveTab();
    const result = await runScanForTab(tab.id);
    showScanNotification(result);
  } catch (_) {
    // Intentionally ignore errors in notification action.
  }
});

// Scan completed page loads so warnings appear without requiring the popup.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") {
    return;
  }
  if (!tab || isRestrictedUrl(tab.url)) {
    return;
  }
  maybeAutoScan(tabId, "tab_updated");
});

// Scan when users switch tabs because the visible page has changed.
chrome.tabs.onActivated.addListener(({ tabId }) => {
  maybeAutoScan(tabId, "tab_activated");
});

// Scan normal navigations, including webmail page loads.
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) {
    return;
  }
  maybeAutoScan(details.tabId, "webnav_completed");
});

// Scan single-page-app route changes, which is important for Gmail message navigation.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) {
    return;
  }
  maybeAutoScan(details.tabId, "webnav_history_state");
});
