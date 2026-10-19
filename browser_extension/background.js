/**
 * CyberKawach Download Interceptor Background Service Worker (Manifest v3)
 * 
 * Intercepts new download events, temporarily pauses the download,
 * dispatches the download URL to CyberKawach's backend streaming inspection engine,
 * and either resumes or cancels the download according to the scan verdict.
 */

const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";

// Maintain state of active inspections
const pendingDownloads = new Map();

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const url = downloadItem.finalUrl || downloadItem.url;
  const downloadId = downloadItem.id;
  const filename = downloadItem.filename || "file";

  // Ignore internal/data/blob/extension URLs
  if (!url || url.startsWith("blob:") || url.startsWith("data:") || url.startsWith("chrome-extension:")) {
    return;
  }

  // Prevent recursive intercept of downloads released by CyberKawach itself
  if (url.includes("/api/scan/") && url.endsWith("/download")) {
    return;
  }

  console.log(`[CyberKawach] Intercepted new download #${downloadId}: ${filename} (${url})`);

  // 1. Immediately pause the download to prevent execution before scanner approval
  try {
    await chrome.downloads.pause(downloadId);
    console.log(`[CyberKawach] Paused download #${downloadId} for quarantine inspection.`);
  } catch (err) {
    console.warn(`[CyberKawach] Could not pause download #${downloadId}:`, err);
  }

  // 2. Fetch configured backend host
  chrome.storage.sync.get({ backendUrl: DEFAULT_BACKEND_URL }, async (items) => {
    const backendUrl = items.backendUrl.replace(/\/$/, "");

    try {
      // 3. Dispatch URL to CyberKawach platform-managed scanner
      const scanResponse = await fetch(`${backendUrl}/api/scan/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          download_url: url,
          custom_filename: filename
        })
      });

      if (!scanResponse.ok) {
        console.error(`[CyberKawach] Scanner error: HTTP ${scanResponse.status}`);
        // Default fail-safe: keep paused or prompt user
        showNotification(
          "Scanner Warning",
          `Unable to complete threat inspection for ${filename}. Proceed with caution.`
        );
        return;
      }

      const scanResult = await scanResponse.json();
      console.log(`[CyberKawach] Scan result for #${downloadId}:`, scanResult);

      // 4. Enforce strict Zero-Trust release policy
      if (scanResult.state === "CLEAN" && scanResult.release_policy === "ALLOWED") {
        console.log(`[CyberKawach] File is CLEAN. Resuming download #${downloadId}.`);
        await chrome.downloads.resume(downloadId);
        showNotification(
          "Download Verified Clean",
          `${filename} has passed multi-engine threat inspection.`
        );
      } else {
        console.warn(`[CyberKawach] THREAT DETECTED! Cancelling download #${downloadId}.`, scanResult.threat_signatures);
        await chrome.downloads.cancel(downloadId);
        try {
          await chrome.downloads.erase({ id: downloadId });
        } catch (_) {}

        showNotification(
          "Malicious Download Blocked!",
          `Blocked ${filename}! Detected threats: ${scanResult.threat_signatures.join(", ") || "Policy violation"}`
        );
      }
    } catch (fetchErr) {
      console.error("[CyberKawach] Failed to connect to CyberKawach scanning daemon:", fetchErr);
    }
  });
});

function showNotification(title, message) {
  if (chrome.notifications) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><text y='20' font-size='20'>🛡️</text></svg>",
      title: `CyberKawach: ${title}`,
      message: message,
      priority: 2
    });
  }
}
