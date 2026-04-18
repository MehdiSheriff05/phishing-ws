const inputEl = document.getElementById("apiBaseUrl");
const saveBtn = document.getElementById("saveBtn");
const statusEl = document.getElementById("status");

// This local URL is used during development when FastAPI runs on the same machine.
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

// Load the saved backend URL so the extension knows where to send prediction requests.
function loadOptions() {
  chrome.storage.sync.get(["apiBaseUrl"], (result) => {
    // If the user has never saved a URL, fall back to the local backend.
    inputEl.value = result.apiBaseUrl || DEFAULT_API_BASE_URL;
  });
}

// Save the backend URL into Chrome sync storage so popup and service worker can reuse it.
saveBtn.addEventListener("click", () => {
  const apiBaseUrl = inputEl.value.trim() || DEFAULT_API_BASE_URL;
  chrome.storage.sync.set({ apiBaseUrl }, () => {
    // Chrome reports storage failures through runtime.lastError instead of throwing exceptions.
    if (chrome.runtime.lastError) {
      statusEl.textContent = `Error: ${chrome.runtime.lastError.message}`;
      return;
    }
    // A short message confirms the setting was saved for the user.
    statusEl.textContent = "Saved.";
  });
});

// Run on page load so the options screen is populated immediately.
loadOptions();
