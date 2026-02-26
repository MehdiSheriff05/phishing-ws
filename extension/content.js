function textFrom(selector) {
  const node = document.querySelector(selector);
  return node?.innerText?.trim() || "";
}

function extractSenderEmail(raw) {
  if (!raw) return "";
  const match = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : raw.trim();
}

function isGmail() {
  return location.hostname === "mail.google.com";
}

function dedupe(arr) {
  return [...new Set(arr.filter(Boolean))];
}

function firstEmailInText(text) {
  const match = (text || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : "";
}

function getGmailContext() {
  const subject = textFrom("h2.hP") || textFrom("[data-thread-perm-id] h2");
  const senderName = textFrom("span.gD") || textFrom(".go span[email]");
  const senderEmailRaw =
    document.querySelector("span.gD")?.getAttribute("email") ||
    document.querySelector(".go span[email]")?.getAttribute("email") ||
    senderName;

  const bodyNode = document.querySelector("div.a3s.aiL") || document.querySelector(".ii.gt");
  const bodyText = bodyNode?.innerText?.trim() || "";

  const urlSet = new Set();
  (bodyNode?.querySelectorAll("a[href]") || []).forEach((a) => {
    const href = a.getAttribute("href");
    if (href && href.startsWith("http")) urlSet.add(href);
  });

  const attachmentNodes = document.querySelectorAll("div.aQH span.aZo, div.aQH div.aV3");
  const attachments = [];
  attachmentNodes.forEach((node) => {
    const filename = (node.getAttribute("download_url") || node.innerText || "").trim();
    if (!filename) return;
    const segments = filename.split(".");
    const extension = segments.length > 1 ? segments.pop().toLowerCase() : "";
    attachments.push({
      filename,
      extension,
      size_kb: 0,
      mime_type: "application/octet-stream"
    });
  });

  return {
    sender_email: extractSenderEmail(senderEmailRaw),
    sender_name: senderName,
    subject,
    body_text: bodyText,
    urls: [...urlSet],
    attachments,
    page_source: "gmail"
  };
}

function getWebpageContext() {
  const hostname = location.hostname || "unknown.local";
  const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 20000);
  const senderEmail = firstEmailInText(bodyText) || `no-reply@${hostname}`;

  const links = [];
  document.querySelectorAll("a[href]").forEach((a) => {
    const href = a.href;
    if (href && href.startsWith("http")) links.push(href);
  });

  const urls = dedupe([location.href, ...links]).slice(0, 80);
  return {
    sender_email: senderEmail,
    sender_name: hostname,
    subject: document.title || hostname,
    body_text: bodyText,
    urls,
    attachments: [],
    page_source: "webpage"
  };
}

function getPageContext() {
  return isGmail() ? getGmailContext() : getWebpageContext();
}

function fingerprintEmail(context) {
  const base = [
    context.sender_email || "",
    context.subject || "",
    (context.body_text || "").slice(0, 400),
    (context.urls || []).join("|")
  ].join("||");
  return btoa(unescape(encodeURIComponent(base))).slice(0, 120);
}

let lastFingerprint = "";
let autoAnalyzeTimer = null;

function queueAutoAnalyze() {
  if (autoAnalyzeTimer) {
    clearTimeout(autoAnalyzeTimer);
  }
  autoAnalyzeTimer = setTimeout(() => {
    const context = getPageContext();
    if (!context.sender_email || !context.subject || !context.body_text) return;

    if (context.page_source === "webpage" && context.body_text.length < 80) return;

    const fp = fingerprintEmail(context);
    if (fp === lastFingerprint) return;
    lastFingerprint = fp;

    chrome.storage.local.set({ latestEmailContext: context, latestEmailFingerprint: fp });
    chrome.runtime.sendMessage({ type: "AUTO_ANALYZE_EMAIL", payload: context, fingerprint: fp });
  }, 700);
}

function onLocationMaybeChanged(callback) {
  let lastHref = location.href;
  const observer = new MutationObserver(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      callback(lastHref);
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

function removeExistingRiskBanner() {
  const old = document.getElementById("__phish_guard_banner");
  if (old) old.remove();
}

function showRiskBanner({ level, score, reason, source }) {
  removeExistingRiskBanner();

  const color = level === "high" ? "#b83232" : "#b7791f";
  const banner = document.createElement("div");
  banner.id = "__phish_guard_banner";
  banner.style.position = "fixed";
  banner.style.top = "16px";
  banner.style.right = "16px";
  banner.style.zIndex = "2147483647";
  banner.style.maxWidth = "380px";
  banner.style.background = "#111827";
  banner.style.color = "#ffffff";
  banner.style.borderLeft = `6px solid ${color}`;
  banner.style.borderRadius = "10px";
  banner.style.padding = "12px";
  banner.style.boxShadow = "0 10px 30px rgba(0,0,0,0.35)";
  banner.style.fontFamily = "Arial, sans-serif";
  banner.innerHTML = `
    <div style="font-weight:700; margin-bottom:6px;">${String(level || "medium").toUpperCase()} phishing risk</div>
    <div style="font-size:12px; margin-bottom:6px;">${source || "Current page"}</div>
    <div style="font-size:12px; margin-bottom:6px;">Score: ${score}</div>
    <div style="font-size:12px; opacity:0.92;">${reason || "Potential phishing indicators detected."}</div>
    <button id="__phish_guard_close" style="margin-top:10px; background:${color}; color:#fff; border:0; border-radius:6px; padding:6px 9px; cursor:pointer;">Dismiss</button>
  `;
  document.body.appendChild(banner);
  document
    .getElementById("__phish_guard_close")
    ?.addEventListener("click", () => removeExistingRiskBanner());
}

onLocationMaybeChanged(() => {
  const context = getPageContext();
  chrome.storage.local.set({ latestEmailContext: context });
  queueAutoAnalyze();
});

window.addEventListener("popstate", queueAutoAnalyze);
window.addEventListener("hashchange", queueAutoAnalyze);

queueAutoAnalyze();

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "EXTRACT_EMAIL") {
    const context = getPageContext();
    chrome.storage.local.set({ latestEmailContext: context });
    sendResponse({ ok: true, payload: context });
    return true;
  }

  if (message?.type === "SHOW_RISK_BANNER") {
    showRiskBanner(message.payload || {});
    sendResponse({ ok: true });
    return true;
  }
});
