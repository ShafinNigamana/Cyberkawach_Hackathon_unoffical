# CyberKawach Browser Extension & Endpoint Agent Specification (Phase 7)

## 1. Architectural Scope & Threat Boundary

Web applications running inside browser sandboxes cannot inspect arbitrary system-level downloads initiated by external applications or other browser tabs due to standard Operating System (OS) and browser security sandboxing boundaries.

To deliver end-to-end download protection across all citizen workflows, CyberKawach implements a two-tier download architecture:

| Tier | Download Origin | Interception Mechanism | Inspection Pipeline | Release Gate |
|---|---|---|---|---|
| **Tier 1: Platform-Managed Downloads** | CyberKawach Web App (`/api/scan/file`, `/api/scan/url`) | Backend Streaming Proxy (`httpx.stream`) | In-memory SHA-256 calculation + sandbox quarantine storage (`data/quarantine/{sha256}.bin`) | Zero-Trust Download Gate (`GET /api/scan/{id}/download`) returns `HTTP 403 Forbidden` if state != `CLEAN` |
| **Tier 2: External Browser Downloads** | Chrome, Edge, Brave, Firefox (web browsing, webmail, attachments) | WebExtension Manifest v3 with `chrome.downloads` and `chrome.webRequest` APIs | Intercepts `chrome.downloads.onCreated`, immediately pauses the download stream, and forwards URL/chunks to CyberKawach scanner | Automatically resumes download upon `CLEAN` response; permanently cancels and alerts user if `MALICIOUS` or `SUSPICIOUS` |

---

## 2. WebExtension Manifest v3 Architecture

### 2.1 Extension Permissions & Security Context
The browser extension requires:
- `downloads`: To listen to `chrome.downloads.onCreated` and manage download lifecycle (`pause`, `resume`, `cancel`, `erase`).
- `downloads.shelf`: To prevent the browser shelf from auto-revealing untrusted files before scanner approval.
- `storage`: To persist user settings, scan history, and active backend endpoint URLs.
- `declarativeNetRequest` / `webRequest`: To inspect HTTP headers (`Content-Disposition`, `Content-Type`) before payload delivery.

### 2.2 Lifecycle Workflow
```mermaid
sequenceDiagram
    autonumber
    actor User as Citizen / Browser
    participant Browser as Chrome/Edge (Extension API)
    participant Ext as CyberKawach Background Worker
    participant API as CyberKawach Backend (/api/scan/url)
    participant Sandbox as Quarantine Storage & AV Engines

    User->>Browser: Clicks Download Link (.exe, .zip, .apk, .pdf)
    Browser->>Ext: chrome.downloads.onCreated(downloadItem)
    Note over Ext: IMMEDIATELY PAUSE DOWNLOAD<br/>chrome.downloads.pause(downloadId)
    Ext->>API: POST /api/scan/url { download_url: item.url }
    API->>Sandbox: Stream chunks, compute SHA-256, verify Magic Bytes
    Sandbox->>Sandbox: Scan EICAR, Archive-Bomb ratio, ClamAV
    Sandbox-->>API: Return FileScanRecord (state, release_policy)
    API-->>Ext: JSON Response { state: "CLEAN"|"MALICIOUS", release_policy }
    
    alt If Clean (release_policy == "ALLOWED")
        Ext->>Browser: chrome.downloads.resume(downloadId)
        Ext->>User: Display Green Notification: "File verified clean by CyberKawach"
    else If Malicious / Suspicious (release_policy == "BLOCKED")
        Ext->>Browser: chrome.downloads.cancel(downloadId)
        Ext->>Browser: chrome.downloads.erase({ id: downloadId })
        Ext->>User: Display Red Banner: "Threat Blocked! Quarantined by CyberKawach"
    end
```

---

## 3. Local Endpoint Agent (Windows / Linux Daemon)

For non-browser downloads (e.g. downloads through Telegram Desktop, WhatsApp Desktop, Discord, cURL, or email clients), an endpoint agent can monitor the citizen's designated Downloads directory using OS filesystem notifications:

- **Windows:** Win32 `ReadDirectoryChangesW` or .NET `FileSystemWatcher` targeting `%USERPROFILE%\Downloads`.
- **Linux:** `inotify` or `fanotify` hooks on `/home/$USER/Downloads`.
- **Operational Rule:**
  1. Detect newly created `.tmp` or `.crdownload` file stream.
  2. Apply deny-read ACL / permission lock on the target file until hash verification completes.
  3. Transmit file hash to `POST /api/scan/file`.
  4. If malicious, atomically move to quarantined vault directory (`%LOCALAPPDATA%\CyberKawach\quarantine\`) and alert the user.
