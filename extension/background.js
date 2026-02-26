const DEFAULT_API_BASE = "http://127.0.0.1:5000";
const FALLBACK_API_BASE = "http://localhost:5000";
const lastNotifiedByTab = new Map();

function senderDomain(email) {
  if (!email || !email.includes("@")) return "";
  return email.split("@").pop().toLowerCase();
}

function safeStorageGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function safeStorageSet(value) {
  return new Promise((resolve) => chrome.storage.local.set(value, resolve));
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ANALYZE_EMAIL") {
    analyzeEmail(message.payload)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "GET_ALLOWLIST") {
    chrome.storage.local.get(["allowlistDomains"], (data) => {
      sendResponse({ domains: data.allowlistDomains || [] });
    });
    return true;
  }

  if (message?.type === "SET_ALLOWLIST") {
    chrome.storage.local.set({ allowlistDomains: message.domains || [] }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "GET_BLOCKLIST") {
    chrome.storage.local.get(["blocklistDomains"], (data) => {
      sendResponse({ domains: data.blocklistDomains || [] });
    });
    return true;
  }

  if (message?.type === "SET_BLOCKLIST") {
    chrome.storage.local.set({ blocklistDomains: message.domains || [] }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "GET_API_BASE") {
    chrome.storage.local.get(["apiBaseUrl"], (data) => {
      sendResponse({ apiBaseUrl: data.apiBaseUrl || DEFAULT_API_BASE });
    });
    return true;
  }

  if (message?.type === "SET_API_BASE") {
    const url = String(message.apiBaseUrl || "").trim();
    chrome.storage.local.set({ apiBaseUrl: url || DEFAULT_API_BASE }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "GET_LATEST_ANALYSIS") {
    chrome.storage.local.get(["latestAnalysis"], (data) => {
      sendResponse({ latest: data.latestAnalysis || null });
    });
    return true;
  }

  if (message?.type === "AUTO_ANALYZE_EMAIL") {
    runAutoAnalysis(message.payload, sender?.tab?.id, message?.fingerprint || "")
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }

  if (message?.type === "TEST_NOTIFICATION") {
    const sampleResult = {
      risk_score: 68,
      risk_level: "medium",
      reasons: ["Test notification from Phish Guard extension."]
    };
    const samplePayload = {
      subject: "Notification test",
      sender_name: "phish-guard.local",
      page_source: "webpage"
    };
    notifyRisk(sampleResult, samplePayload, sender?.tab?.id)
      .then((status) => sendResponse({ ok: true, status }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true;
  }
});

async function getApiBases() {
  const data = await safeStorageGet(["apiBaseUrl"]);
  const preferred = (data.apiBaseUrl || DEFAULT_API_BASE).trim();
  const bases = [preferred];
  if (preferred === DEFAULT_API_BASE) bases.push(FALLBACK_API_BASE);
  if (preferred === FALLBACK_API_BASE) bases.push(DEFAULT_API_BASE);
  return [...new Set(bases)];
}

async function doAnalyzeRequest(base, payload) {
  const response = await fetch(`${base}/analyze-email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return response;
}

async function analyzeEmail(payload) {
  const apiBases = await getApiBases();
  let lastError = "No API base configured";

  for (const base of apiBases) {
    try {
      const response = await doAnalyzeRequest(base, payload);
      if (!response.ok) {
        const body = await response.text();
        lastError = `API error ${response.status} from ${base}: ${body || response.statusText}`;
        // Retry fallback host for common local mismatch errors.
        if (response.status === 403 || response.status === 404) continue;
        throw new Error(lastError);
      }
      const result = await response.json();
      return result;
    } catch (err) {
      lastError = String(err);
      continue;
    }
  }

  throw new Error(lastError);
}

function shouldNotify(result, payload) {
  const level = String(result?.risk_level || "low");
  const isWebpage = String(payload?.page_source || "") === "webpage";
  return isWebpage && (level === "medium" || level === "high");
}

function showFallbackBanner(tabId, level, score, reason, source) {
  if (typeof tabId !== "number") return;
  chrome.tabs.sendMessage(tabId, {
    type: "SHOW_RISK_BANNER",
    payload: { level: level.toLowerCase(), score, reason, source }
  });
}

function notifyRisk(result, payload, tabId) {
  const level = String(result.risk_level || "medium").toUpperCase();
  const score = result.risk_score;
  const source = payload?.subject || payload?.sender_name || payload?.sender_email || "Current page";
  const reason = (result.reasons && result.reasons[0]) || "Potential phishing indicators detected.";
  const message = `${source}\nScore: ${score}\n${reason}`.slice(0, 500);

  return new Promise((resolve) => {
    chrome.notifications.create(
      `phish_guard_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon128.png"),
        title: `${level} phishing risk detected`,
        message,
        priority: level === "HIGH" ? 2 : 1,
        requireInteraction: level === "HIGH"
      },
      (notificationId) => {
        const err = chrome.runtime.lastError?.message;
        if (err) {
          // Fallback when desktop notifications are blocked by browser/OS settings.
          showFallbackBanner(tabId, level, score, reason, source);
          resolve({ ok: false, error: err, notificationId: null, fallbackBanner: true });
          return;
        }
        resolve({ ok: true, error: null, notificationId, fallbackBanner: false });
      }
    );
  });
}

async function runAutoAnalysis(payload, tabId, fingerprint) {
  const data = await safeStorageGet(["allowlistDomains", "blocklistDomains"]);
  const allowlist = data.allowlistDomains || [];
  const blocklist = data.blocklistDomains || [];
  const domain = senderDomain(payload?.sender_email || "");

  let result;
  if (blocklist.includes(domain)) {
    result = {
      risk_score: 100,
      risk_level: "high",
      reasons: [`${domain} is blocklisted. Treat this as highly suspicious.`],
      indicators: { text: 0, url: 0, sender: 100, attachment: 0 },
      recommended_action: "Do not interact with this email."
    };
  } else if (allowlist.includes(domain)) {
    result = {
      risk_score: 0,
      risk_level: "low",
      reasons: [`${domain} is allow-listed. Analysis skipped.`],
      indicators: { text: 0, url: 0, sender: 0, attachment: 0 },
      recommended_action: "Sender is trusted by your local allow-list."
    };
  } else {
    result = await analyzeEmail(payload);
  }

  await safeStorageSet({
    latestAnalysis: {
      payload,
      result,
      analyzedAt: new Date().toISOString()
    }
  });

  if (typeof tabId === "number") {
    const level = String(result.risk_level || "low");
    const badgeText = level === "high" ? "HIGH" : level === "medium" ? "MED" : "LOW";
    const badgeColor = level === "high" ? "#b83232" : level === "medium" ? "#b7791f" : "#2d7d46";
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  }

  if (shouldNotify(result, payload)) {
    const notifyKey = `${fingerprint || payload?.subject || ""}:${result.risk_level}`;
    const previous = typeof tabId === "number" ? lastNotifiedByTab.get(tabId) : "";
    if (notifyKey && notifyKey !== previous) {
      notifyRisk(result, payload, tabId);
      if (typeof tabId === "number") {
        lastNotifiedByTab.set(tabId, notifyKey);
      }
    }
  }

  return result;
}
