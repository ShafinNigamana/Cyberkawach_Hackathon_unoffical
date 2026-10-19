document.addEventListener("DOMContentLoaded", () => {
  const urlInput = document.getElementById("backend-url");
  const saveBtn = document.getElementById("save-btn");
  const statusBadge = document.getElementById("status-badge");

  chrome.storage.sync.get({ backendUrl: "http://127.0.0.1:8000" }, (items) => {
    urlInput.value = items.backendUrl;
  });

  saveBtn.addEventListener("click", () => {
    const backendUrl = urlInput.value.trim();
    chrome.storage.sync.set({ backendUrl }, () => {
      saveBtn.textContent = "Saved!";
      setTimeout(() => {
        saveBtn.textContent = "Save Configuration";
      }, 1500);
    });
  });
});
