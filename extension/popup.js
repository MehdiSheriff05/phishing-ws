const analyzeBtn = document.getElementById("analyzeBtn");
const testNotificationBtn = document.getElementById("testNotificationBtn");
const saveApiBtn = document.getElementById("saveApiBtn");
const saveAllowlistBtn = document.getElementById("saveAllowlistBtn");
const saveBlocklistBtn = document.getElementById("saveBlocklistBtn");
const apiBaseInput = document.getElementById("apiBaseInput");
const allowlistInput = document.getElementById("allowlistInput");
const blocklistInput = document.getElementById("blocklistInput");
const statusNode = document.getElementById("status");

const resultNode = document.getElementById("result");
const bannerNode = document.getElementById("banner");
const scoreNode = document.getElementById("score");
const levelNode = document.getElementById("level");
const reasonsNode = document.getElementById("reasons");

function setStatus(text) {
  statusNode.innerText = text;
}

function parseDomains(text) {
  return text
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

function senderDomain(email) {
  if (!email || !email.includes("@")) return "";
  return email.split("@").pop().toLowerCase();
}

function renderResult(result) {
  resultNode.classList.remove("hidden");
  scoreNode.innerText = String(result.risk_score);
  levelNode.innerText = result.risk_level;

  bannerNode.className = `banner ${result.risk_level}`;
  bannerNode.innerText = `Risk: ${result.risk_level.toUpperCase()}`;

  reasonsNode.innerHTML = "";
  (result.reasons || []).forEach((reason) => {
    const li = document.createElement("li");
    li.innerText = reason;
    reasonsNode.appendChild(li);
  });
}

function getAllowlist() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_ALLOWLIST" }, (res) => {
      resolve(res?.domains || []);
    });
  });
}

function setAllowlist(domains) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "SET_ALLOWLIST", domains }, () => resolve());
  });
}

function getApiBase() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_API_BASE" }, (res) => {
      resolve(res?.apiBaseUrl || "http://127.0.0.1:5000");
    });
  });
}

function setApiBase(apiBaseUrl) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "SET_API_BASE", apiBaseUrl }, () => resolve());
  });
}

function getBlocklist() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_BLOCKLIST" }, (res) => {
      resolve(res?.domains || []);
    });
  });
}

function setBlocklist(domains) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "SET_BLOCKLIST", domains }, () => resolve());
  });
}

function queryActiveTab() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0]));
  });
}

function sendExtractMessage(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "EXTRACT_EMAIL" }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response?.ok) {
        reject(new Error("Failed to extract page content"));
        return;
      }
      resolve(response.payload);
    });
  });
}

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

function extractFromTab(tabId) {
  return sendExtractMessage(tabId).catch(async (err) => {
    const message = String(err?.message || err);
    if (!message.includes("Receiving end does not exist")) {
      throw err;
    }

    await injectContentScript(tabId);
    return sendExtractMessage(tabId);
  });
}

function analyzePayload(payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: "ANALYZE_EMAIL", payload }, (response) => {
      if (!response?.ok) {
        reject(response?.error || "Unknown backend error");
        return;
      }
      resolve(response.result);
    });
  });
}

async function initAllowlist() {
  const apiBase = await getApiBase();
  apiBaseInput.value = apiBase;

  const domains = await getAllowlist();
  allowlistInput.value = domains.join(", ");

  const blocked = await getBlocklist();
  blocklistInput.value = blocked.join(", ");

  chrome.runtime.sendMessage({ type: "GET_LATEST_ANALYSIS" }, (res) => {
    if (res?.latest?.result) {
      renderResult(res.latest.result);
      setStatus(`Last auto analysis: ${res.latest.analyzedAt}`);
    }
  });
}

saveApiBtn.addEventListener("click", async () => {
  const url = (apiBaseInput.value || "").trim();
  await setApiBase(url);
  setStatus("API URL saved.");
});

saveAllowlistBtn.addEventListener("click", async () => {
  const domains = parseDomains(allowlistInput.value);
  await setAllowlist(domains);
  setStatus("Allow-list saved.");
});

saveBlocklistBtn.addEventListener("click", async () => {
  const domains = parseDomains(blocklistInput.value);
  await setBlocklist(domains);
  setStatus("Blocklist saved.");
});

testNotificationBtn.addEventListener("click", async () => {
  setStatus("Triggering test notification...");
  chrome.runtime.sendMessage({ type: "TEST_NOTIFICATION" }, (response) => {
    if (chrome.runtime.lastError) {
      setStatus(`Error: ${chrome.runtime.lastError.message}`);
      return;
    }
    if (!response?.ok) {
      setStatus("Error: failed to trigger test notification");
      return;
    }
    const s = response.status || {};
    if (s.ok && s.notificationId) {
      setStatus(`Notification created (${s.notificationId}). Check Notification Center.`);
      return;
    }
    if (!s.ok && s.error) {
      setStatus(`Notification blocked: ${s.error}`);
      return;
    }
    if (s.fallbackBanner) {
      setStatus("System notification blocked. Fallback banner triggered.");
      return;
    }
    setStatus("Test notification requested.");
  });
});

analyzeBtn.addEventListener("click", async () => {
  setStatus("Extracting page content...");
  try {
    const tab = await queryActiveTab();
    if (!tab?.id) throw new Error("No active tab found");

    const payload = await extractFromTab(tab.id);
    const domain = senderDomain(payload.sender_email);
    const allowlist = await getAllowlist();
    const blocklist = await getBlocklist();

    if (blocklist.includes(domain)) {
      renderResult({
        risk_score: 100,
        risk_level: "high",
        reasons: [`${domain} is blocklisted. Treat this as highly suspicious.`]
      });
      setStatus("Blocked domain detected.");
      return;
    }

    if (allowlist.includes(domain)) {
      renderResult({
        risk_score: 0,
        risk_level: "low",
        reasons: [`${domain} is allow-listed. Analysis skipped.`]
      });
      setStatus("Skipped due to allow-list.");
      return;
    }

    setStatus("Analyzing via backend...");
    const result = await analyzePayload(payload);
    renderResult(result);
    setStatus("Done");
  } catch (err) {
    const msg = String(err?.message || err);
    if (
      msg.includes("Cannot access a chrome:// URL") ||
      msg.includes("The extensions gallery cannot be scripted")
    ) {
      setStatus("Error: This page is restricted. Open a normal website and retry.");
      return;
    }
    setStatus(`Error: ${msg}`);
  }
});

initAllowlist();
