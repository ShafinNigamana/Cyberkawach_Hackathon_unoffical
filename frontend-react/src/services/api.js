/**
 * API Service Layer — single source of truth for all backend communication.
 *
 * This module is designed to be reusable across React Web and future React Native.
 * It contains ZERO UI logic.
 */

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

/**
 * Safe JSON parser for error responses.
 */
async function parseErrorResponse(response) {
  try {
    const data = await response.json();
    return data.detail || data.error || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

/**
 * POST /api/analyze — submit content for fraud analysis.
 *
 * @param {Object} params
 * @param {string} params.message - The suspicious message text
 * @param {string} [params.inputType='text'] - Input type
 * @param {string} [params.userState='received'] - User interaction state
 * @param {string[]} [params.urls=[]] - Additional URLs to analyze
 * @param {string} [params.language='en'] - ISO language code
 * @returns {Promise<Object>} AnalyzeResponse
 */
export async function analyzeMessage({ message, inputType = 'text', userState = 'received', urls = [], language = 'en' }) {
  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message,
      input_type: inputType,
      user_state: userState,
      urls: urls.filter(u => u && u.trim()),
      language,
    }),
  });

  if (!response.ok) {
    const errorMsg = await parseErrorResponse(response);
    throw new Error(errorMsg);
  }

  return response.json();
}

/**
 * POST /api/incidents/{id}/state — update user state for adaptive response.
 *
 * @param {string} incidentId
 * @param {string} userState
 * @returns {Promise<Object>} AnalyzeResponse (updated)
 */
export async function updateUserState(incidentId, userState) {
  const response = await fetch(`${API_BASE}/api/incidents/${encodeURIComponent(incidentId)}/state`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_state: userState }),
  });

  if (!response.ok) {
    const errorMsg = await parseErrorResponse(response);
    throw new Error(errorMsg);
  }

  return response.json();
}

/**
 * POST /api/upload/screenshot — secure file upload.
 *
 * @param {File} file
 * @returns {Promise<Object>} FileUploadResponse
 */
export async function uploadScreenshot(file) {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/api/upload/screenshot`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const errorMsg = await parseErrorResponse(response);
    throw new Error(errorMsg);
  }

  return response.json();
}

/**
 * GET /api/health — check system health.
 *
 * @returns {Promise<Object>} HealthResponse
 */
export async function checkHealth() {
  const response = await fetch(`${API_BASE}/api/health`);

  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`);
  }

  return response.json();
}
