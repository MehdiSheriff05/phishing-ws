const inputEl = document.getElementById("apiBaseUrl");
const saveBtn = document.getElementById("saveBtn");
const statusEl = document.getElementById("status");

const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

function loadOptions() {
  chrome.storage.sync.get(["apiBaseUrl"], (result) => {
    inputEl.value = result.apiBaseUrl || DEFAULT_API_BASE_URL;
  });
}

saveBtn.addEventListener("click", () => {
  const apiBaseUrl = inputEl.value.trim() || DEFAULT_API_BASE_URL;
  chrome.storage.sync.set({ apiBaseUrl }, () => {
    if (chrome.runtime.lastError) {
      statusEl.textContent = `Error: ${chrome.runtime.lastError.message}`;
      return;
    }
    statusEl.textContent = "Saved.";
  });
});

loadOptions();
