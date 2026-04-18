const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";
const lastScanAtByTab = new Map();
const AUTO_SCAN_DEBOUNCE_MS = 1200;
const NOTIF_ID_PREFIX = "scan-result-";
const LIKELY_PHISHING_THRESHOLD = 0.6;
const LAST_SCAN_STORAGE_PREFIX = "lastScanResult:";
const LOW_CONTENT_TEXT_LEN = 80;
const LOW_CONTENT_LINK_COUNT = 2;
const FRESH_SCAN_WINDOW_MS = 15000;

// These constants control local API routing, notification labels, debouncing, and cache freshness.

// Read the FastAPI base URL from Chrome storage so the extension can work in local demos.
function getApiBaseUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiBaseUrl"], (result) => {
      // The options page can override this URL when the backend is deployed remotely.
      resolve(result.apiBaseUrl || DEFAULT_API_BASE_URL);
    });
  });
}

// Find the active browser tab because manual scans should scan what the user is viewing.
function getActiveTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      // runtime.lastError is Chrome's way of reporting async API failures.
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!tabs || !tabs[0]?.id) {
        reject(new Error("No active tab found"));
        return;
      }
      // Returning the full tab gives downstream code access to both id and URL.
      resolve(tabs[0]);
    });
  });
}

// Avoid Chrome-internal pages because extensions cannot inject normal content scripts there.
function isRestrictedUrl(url) {
  // Chrome blocks content-script access to internal pages for security reasons.
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
    // Injection is a fallback for tabs opened before the extension was loaded.
    chrome.scripting.executeScript(
      {
        target: { tabId },
        files: ["content.js"]
      },
      () => {
        // If injection fails, scanning cannot safely continue for this tab.
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
    // content.js returns the same visible_text and links shape expected by FastAPI.
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
  // First retrieve tab metadata so restricted pages can be rejected early.
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
    // In the normal case, content.js is already available and can extract page data.
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

  // Send the extracted page content to FastAPI for rule checks and ML prediction.
  const response = await fetch(`${apiBaseUrl}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Backend error (${response.status})`);
  }

  // The returned object includes the predicted label, score, and explanation flags.
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
      // Missing cache means the popup should request a fresh scan.
      const saved = result[key] || null;
      if (!saved) {
        resolve(null);
        return;
      }
      if (pageUrl && saved.pageUrl && saved.pageUrl !== pageUrl) {
        resolve(null);
        return;
      }
      // Old cache is ignored to avoid showing stale Gmail results.
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
  // Special titles make allowlist/blocklist policy warnings easier to explain in a demo.
  const flags = (prediction.flags || []).join(" ").toLowerCase();
  if (flags.includes("blocklist warning")) return "Blocked Site Warning";
  if (flags.includes("allowlist caution")) return "Allowlisted Site Looks Risky";
  return "Phishing Scan Complete";
}

// Display a browser notification when the scan detects medium or high phishing risk.
function showScanNotification(scanResult) {
  const prediction = scanResult.prediction || scanResult;
  const probability = Number(prediction.probability_phishing || 0).toFixed(2);
  // Only the first flags are shown because Chrome notifications have limited space.
  const flagsText = (prediction.flags || []).slice(0, 2).join(" | ");
  const message = [
    `Label: ${prediction.label} (p=${probability})`,
    flagsText || "No warning flags.",
    "Open popup to scan manually anytime."
  ].join("\n");

  // The notification lets users see warnings without manually opening the extension popup.
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
  // Local storage lets the popup display the last auto-scan result immediately.
  chrome.storage.local.set({
    [key]: {
      tabId,
      pageUrl,
      updatedAt: Date.now(),
      prediction,
      payload
    }
  });

  // A red exclamation badge gives a lightweight browser-level warning.
  const badge = prediction.label === "phishing" ? "!" : "";
  chrome.action.setBadgeText({ tabId, text: badge });
  chrome.action.setBadgeBackgroundColor({ tabId, color: prediction.label === "phishing" ? "#B91C1C" : "#0F766E" });
}

// Convert the probability score into display-friendly risk levels.
function getRiskLevel(probabilityPhishing) {
  // These user-facing levels are simpler than showing only raw probability values.
  if (probabilityPhishing >= 0.75) return "high";
  if (probabilityPhishing >= LIKELY_PHISHING_THRESHOLD) return "medium";
  return "low";
}

// Treat either an explicit phishing label or a high probability as a warning-worthy result.
function isLikelyPhishing(prediction) {
  // Either the backend label or probability threshold can trigger a user warning.
  if (!prediction) return false;
  return prediction.label === "phishing" || (prediction.probability_phishing || 0) >= LIKELY_PHISHING_THRESHOLD;
}

// Automatically scan page changes while avoiding repeated scans during fast Gmail updates.
function maybeAutoScan(tabId, _reason = "event") {
  const now = Date.now();
  const previous = lastScanAtByTab.get(tabId) || 0;
  // Debouncing prevents repeated scans while Gmail updates the DOM several times.
  if (now - previous < AUTO_SCAN_DEBOUNCE_MS) {
    return;
  }

  runScanForTab(tabId)
    .then((result) => {
      lastScanAtByTab.set(tabId, Date.now());
      const prediction = result.prediction || result;
      // Save every scan so the popup can show the latest result without rescanning first.
      saveLastScanResult(tabId, result, result.tabUrl || "");
      const riskLevel = getRiskLevel(prediction.probability_phishing || 0);
      if ((riskLevel === "medium" || riskLevel === "high") && isLikelyPhishing(prediction)) {
        showScanNotification(result);
      }
    })
    .catch((error) => {
      const msg = String(error?.message || error || "");
      // Restricted-page failures are expected and should not distract the user.
      if (msg.toLowerCase().includes("restricted")) {
        return;
      }
      // Keep silent on transient auto-scan errors.
    });
}

// Route messages from popup.js and content.js into scan, cache, and auto-scan operations.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_CURRENT_PAGE") {
    // Popup-initiated scans may include a known tab id and URL.
    const requestedTabId = Number(message.tabId || 0);
    const requestedTabUrl = String(message.tabUrl || "");
    const doScan = async () => {
      if (message.preferCached && requestedTabId > 0) {
        // Cached results make the popup feel instant, then popup.js can refresh afterward.
        const cached = await getStoredScanForTab(requestedTabId, requestedTabUrl);
        if (cached?.prediction) {
          return { prediction: cached.prediction, payload: cached.payload || {}, tabUrl: cached.pageUrl || requestedTabUrl };
        }
      }
      if (requestedTabId > 0) {
        return runScanForTab(requestedTabId);
      }
      // Fallback scans the currently active tab if the popup did not supply one.
      return scanCurrentPage();
    };

    doScan()
      .then(async (data) => {
        try {
          // Store the result after manual scans too, keeping popup and auto-scan behavior aligned.
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
    // content.js sends this when page content or Gmail state changes.
    if (_sender?.tab?.id) {
      maybeAutoScan(_sender.tab.id, "content_script");
    }
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "GET_LAST_SCAN_FOR_ACTIVE_TAB") {
    // The popup uses this path to load the most recent auto-scan result.
    const requestedTabId = Number(message.tabId || 0);
    const requestedTabUrl = String(message.tabUrl || "");
    const withKnownTab = requestedTabId > 0;
    const run = async () => {
      if (withKnownTab) {
        // Known tab requests avoid accidentally reading cache for another active tab.
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
    // The button performs the same scan path as a manual popup scan.
    const tab = await getActiveTab();
    const result = await runScanForTab(tab.id);
    showScanNotification(result);
  } catch (_) {
    // Intentionally ignore errors in notification action.
  }
});

// Scan completed page loads so warnings appear without requiring the popup.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only scan after the page has completed loading, not on every loading state.
  if (changeInfo.status !== "complete") {
    return;
  }
  if (!tab || isRestrictedUrl(tab.url)) {
    return;
  }
  // A completed page load is a strong signal that content may have changed.
  maybeAutoScan(tabId, "tab_updated");
});

// Scan when users switch tabs because the visible page has changed.
chrome.tabs.onActivated.addListener(({ tabId }) => {
  // Switching tabs changes what the user sees, so refresh the risk state.
  maybeAutoScan(tabId, "tab_activated");
});

// Scan normal navigations, including webmail page loads.
chrome.webNavigation.onCompleted.addListener((details) => {
  // frameId 0 means the top-level page, not an embedded iframe.
  if (details.frameId !== 0) {
    return;
  }
  maybeAutoScan(details.tabId, "webnav_completed");
});

// Scan single-page-app route changes, which is important for Gmail message navigation.
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  // Gmail changes messages through history updates without full page reloads.
  if (details.frameId !== 0) {
    return;
  }
  maybeAutoScan(details.tabId, "webnav_history_state");
});
