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
    response_language: language,
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

export async function updateUserState(incidentId, userState, responseLanguage = null) {
  const payload = { user_state: userState };
  if (responseLanguage) {
    payload.response_language = responseLanguage;
    payload.language = responseLanguage;
  }

  const response = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/state`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(payload),
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

export function getExportUrl(incidentId, format = 'html', lang = 'en') {
  return `${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/export?format=${format}&lang=${lang}`;
}

export async function translateText(text, targetLang, sourceLang = 'en') {
  if (!text || !text.trim() || targetLang === sourceLang) {
    return text;
  }
  try {
    const response = await fetch(`${API_BASE}/api/translate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: JSON.stringify({
        text,
        target_lang: targetLang,
        source_lang: sourceLang,
      }),
    });
    if (!response.ok) return text;
    const data = await response.json();
    return data.translated_text || text;
  } catch (err) {
    console.warn('Translation proxy error:', err);
    return text;
  }
}

export async function translateTexts(texts, targetLang, sourceLang = 'en') {
  if (!texts || !texts.length || targetLang === sourceLang) {
    return texts;
  }
  try {
    const response = await fetch(`${API_BASE}/api/translate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: JSON.stringify({
        texts,
        target_lang: targetLang,
        source_lang: sourceLang,
      }),
    });
    if (!response.ok) return texts;
    const data = await response.json();
    return data.translated_texts || texts;
  } catch (err) {
    console.warn('Batch translation proxy error:', err);
    return texts;
  }
}
