/**
 * Cyber Fraud Guardian API Client
 * Interfaces directly with FastAPI backend routes
 */

const API_BASE = '';

export async function analyzeMessage({ message, urls = [], user_state = 'received', language = 'en', input_type = 'sms' }) {
  const payload = {
    message: message.trim(),
    urls: Array.isArray(urls) ? urls : urls.split('\n').map(u => u.trim()).filter(Boolean),
    user_state,
    language,
    input_type,
  };

  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Network error occurred during analysis.' }));
    throw new Error(errorData.detail || errorData.error || `Server responded with ${response.status}`);
  }

  return response.json();
}

export async function updateUserState(incidentId, userState) {
  const response = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/state`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify({ user_state: userState }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Failed to update user state.' }));
    throw new Error(errorData.detail || errorData.error || 'Failed to update state');
  }

  return response.json();
}

export async function fetchIncidentOsint(incidentId) {
  const response = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/osint`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Failed to enrich OSINT.' }));
    throw new Error(errorData.detail || errorData.error || 'OSINT enrichment failed');
  }

  return response.json();
}

export async function uploadScreenshot(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/api/upload/screenshot`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: 'Screenshot upload failed.' }));
    throw new Error(errorData.detail || errorData.error || 'Screenshot upload failed');
  }

  return response.json();
}

export async function fetchHealth() {
  const response = await fetch(`${API_BASE}/api/health`);
  if (!response.ok) throw new Error('Health check failed');
  return response.json();
}

export async function fetchVerificationStatus() {
  const response = await fetch(`${API_BASE}/api/verification/status`);
  if (!response.ok) throw new Error('Verification status check failed');
  return response.json();
}

export function getExportUrl(incidentId, format = 'html') {
  return `${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/export?format=${format}`;
}
