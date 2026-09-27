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

  const token = localStorage.getItem('cf_auth_token');
  const headers = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: 'POST',
    headers,
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

// ─── Citizen Authentication & Neo4j History Helpers ───

export function getAuthToken() {
  return localStorage.getItem('cf_auth_token');
}

export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('cf_auth_token', token);
  } else {
    localStorage.removeItem('cf_auth_token');
  }
}

export async function registerCitizen({ email, password, display_name, phone, preferred_language = 'en' }) {
  const response = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify({ email, password, display_name, phone, preferred_language }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: 'Registration failed' }));
    throw new Error(err.detail || err.error || 'Failed to register citizen account');
  }
  const data = await response.json();
  if (data.session_token) {
    setAuthToken(data.session_token);
  }
  return data;
}

export async function loginCitizen({ email, password }) {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: 'Invalid email or password' }));
    throw new Error(err.detail || err.error || 'Failed to login');
  }
  const data = await response.json();
  if (data.session_token) {
    setAuthToken(data.session_token);
  }
  return data;
}

export async function logoutCitizen() {
  const token = getAuthToken();
  if (token) {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Requested-With': 'XMLHttpRequest',
        },
      });
    } catch (e) {
      console.warn('Logout error:', e);
    }
  }
  setAuthToken(null);
}

export async function fetchCurrentUser() {
  const token = getAuthToken();
  if (!token) return null;
  try {
    const response = await fetch(`${API_BASE}/api/auth/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'X-Requested-With': 'XMLHttpRequest',
      },
    });
    if (!response.ok) {
      if (response.status === 401) {
        setAuthToken(null);
      }
      return null;
    }
    return response.json();
  } catch (e) {
    return null;
  }
}

export async function fetchMyChecks() {
  const token = getAuthToken();
  if (!token) return { incidents: [], total: 0 };
  const response = await fetch(`${API_BASE}/api/incidents`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Requested-With': 'XMLHttpRequest',
    },
  });
  if (!response.ok) return { incidents: [], total: 0 };
  return response.json();
}

export async function fetchIncidentGraph(incidentId) {
  const token = getAuthToken();
  const headers = { 'X-Requested-With': 'XMLHttpRequest' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const response = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/graph`, { headers });
  if (!response.ok) throw new Error('Failed to load relationship graph');
  return response.json();
}

