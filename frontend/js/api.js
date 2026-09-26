/**
 * API client — communicates with the FastAPI backend.
 */

const API_BASE = 'http://localhost:8000';

const API = {
    /**
     * POST /api/analyze — submit a message for analysis.
     */
    async analyze(message, inputType, userState, urls, language) {
        const selectedLang = language || (window.I18N ? window.I18N.currentLang : 'en');
        const response = await fetch(`${API_BASE}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                input_type: inputType,
                user_state: userState,
                urls: urls.filter(u => u.trim()),
                language: selectedLang,
            }),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(error.detail || error.error || `HTTP ${response.status}`);
        }

        return response.json();
    },

    /**
     * POST /api/incidents/{id}/state — update user state for adaptive response.
     */
    async updateState(incidentId, userState) {
        const response = await fetch(`${API_BASE}/api/incidents/${incidentId}/state`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_state: userState }),
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: 'Unknown error' }));
            throw new Error(error.detail || error.error || `HTTP ${response.status}`);
        }

        return response.json();
    },

    /**
     * POST /api/incidents/{id}/osint — fetch asynchronous OSINT enrichment.
     */
    async getIncidentOsint(incidentId) {
        const response = await fetch(`${API_BASE}/api/incidents/${incidentId}/osint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });

        if (!response.ok) {
            return null;
        }

        return response.json();
    },

    /**
     * GET /api/health — check system status.
     */
    async health() {
        const response = await fetch(`${API_BASE}/api/health`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    },
};
