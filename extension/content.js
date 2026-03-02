function isVisible(element) {
  const style = window.getComputedStyle(element);
  return style && style.display !== "none" && style.visibility !== "hidden";
}

function extractVisibleText() {
  const nodes = Array.from(document.querySelectorAll("body *"));
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

function extractLinks() {
  return Array.from(document.querySelectorAll("a[href]"))
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
      const visible_text = extractVisibleText();
      const links = extractLinks();
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
