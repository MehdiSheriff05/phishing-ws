function isVisible(element) {
  const style = window.getComputedStyle(element);
  return style && style.display !== "none" && style.visibility !== "hidden";
}

function isGmailPage() {
  return window.location.hostname === "mail.google.com";
}

function getGmailScanRoot() {
  const selectors = [
    "div[role='main'] .a3s.aiL",
    "div[role='main'] .a3s",
    "div[role='main'] [data-message-id] .a3s",
    "div[role='main'] [data-message-id]",
    "div[role='main'] [role='listitem'] [data-message-id]"
  ];

  for (const selector of selectors) {
    const candidates = Array.from(document.querySelectorAll(selector)).filter((element) => {
      if (!(element instanceof HTMLElement)) return false;
      if (!isVisible(element)) return false;
      const text = (element.innerText || element.textContent || "").replace(/\s+/g, " ").trim();
      return text.length >= 20;
    });
    if (candidates.length > 0) {
      return candidates[candidates.length - 1];
    }
  }

  const main = document.querySelector("div[role='main']");
  if (main instanceof HTMLElement && isVisible(main)) {
    return main;
  }

  return document.body;
}

function getScanRoot() {
  if (isGmailPage()) {
    return getGmailScanRoot();
  }
  return document.body;
}

function extractVisibleText(root = document.body) {
  const nodes = Array.from(root.querySelectorAll("*"));
  const chunks = [];

  for (const node of nodes) {
    if (!isVisible(node)) continue;
    if (node.children.length > 0) continue;

    const text = (node.textContent || "").replace(/\s+/g, " ").trim();
    if (text.length >= 2) {
      chunks.push(text);
    }
  }

  return chunks.join(" ").slice(0, 20000);
}

function extractLinks(root = document.body) {
  return Array.from(root.querySelectorAll("a[href]"))
    .map((a) => ({
      text: (a.innerText || a.textContent || "").replace(/\s+/g, " ").trim().slice(0, 300),
      href: (a.href || a.getAttribute("href") || "").trim()
    }))
    .filter((l) => l.href)
    .slice(0, 200);
}

function getPageFingerprint() {
  const title = document.title || "";
  const url = window.location.href || "";
  const heading =
    (document.querySelector("h1,h2,[role='heading']")?.textContent || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 200);
  return `${url}||${title}||${heading}`;
}

let lastFingerprint = "";
let scanTriggerTimer = null;

function queueAutoScanTrigger() {
  if (scanTriggerTimer) {
    clearTimeout(scanTriggerTimer);
  }
  scanTriggerTimer = setTimeout(() => {
    chrome.runtime.sendMessage({ type: "AUTO_SCAN_TRIGGER" });
  }, 900);
}

function checkPageStateChange() {
  const fingerprint = getPageFingerprint();
  if (fingerprint !== lastFingerprint) {
    lastFingerprint = fingerprint;
    queueAutoScanTrigger();
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "EXTRACT_EMAIL_DATA") {
    try {
      const scanRoot = getScanRoot();
      const visible_text = extractVisibleText(scanRoot);
      const links = extractLinks(scanRoot);
      sendResponse({ ok: true, data: { visible_text, links } });
    } catch (error) {
      sendResponse({ ok: false, error: String(error) });
    }
  }

  return true;
});

// Trigger automatic scan after initial page load/reload.
chrome.runtime.sendMessage({ type: "AUTO_SCAN_TRIGGER" });
lastFingerprint = getPageFingerprint();

// Detect SPA transitions (e.g., opening different Gmail emails).
const stateObserver = new MutationObserver(() => {
  checkPageStateChange();
});
stateObserver.observe(document.documentElement, { subtree: true, childList: true, attributes: false });

window.addEventListener("popstate", checkPageStateChange);
window.addEventListener("hashchange", checkPageStateChange);
setInterval(checkPageStateChange, 1200);
