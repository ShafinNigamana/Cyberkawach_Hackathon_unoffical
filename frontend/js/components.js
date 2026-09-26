/**
 * UI component renderers — pure functions that return HTML strings.
 * Each evidence item renders as its own labeled element with source.
 */

const Components = {
    /**
     * Render the risk score banner.
     */
    riskBanner(risk, category) {
        const scorePercent = Math.round((risk.score || 0) * 100);
        const level = risk.level || 'UNKNOWN';
        const categoryLabel = category
            ? category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
            : 'Unknown Category';

        return { level, scorePercent, categoryLabel };
    },

    /**
     * Render a single evidence item.
     */
    evidenceItem(item) {
        const confidencePercent = Math.round((item.confidence || 0) * 100);
        return `
            <div class="evidence-item">
                <div class="evidence-type-indicator" data-type="${this.escapeHtml(item.type)}"></div>
                <div class="evidence-body">
                    <div class="evidence-source">${this.escapeHtml(item.source)}</div>
                    <div class="evidence-description">${this.escapeHtml(item.description)}</div>
                </div>
                <div class="evidence-confidence">${confidencePercent}%</div>
            </div>
        `;
    },

    /**
     * Render a threat intel item.
     */
    threatIntelItem(ti) {
        let statusClass = 'error';
        let statusText = 'Unavailable';

        if (ti.match === true) {
            statusClass = 'match';
            statusText = 'MATCH';
        } else if (ti.match === false) {
            statusClass = 'clean';
            statusText = 'Clean';
        }

        const sourceLabel = {
            'safe_browsing': 'Google Safe Browsing',
            'phishtank': 'PhishTank',
            'urlhaus': 'URLhaus',
            'abuseipdb': 'AbuseIPDB',
        }[ti.source] || ti.source;

        const details = ti.error
            ? `Error: ${this.escapeHtml(ti.error)}`
            : this.escapeHtml(ti.details || '');

        return `
            <div class="threat-intel-item">
                <div class="threat-intel-source">${this.escapeHtml(sourceLabel)}</div>
                <span class="threat-intel-status ${statusClass}">${statusText}</span>
                <div class="threat-intel-details">${details}</div>
            </div>
        `;
    },

    /**
     * Render URL analysis items.
     */
    urlItem(urlSignal) {
        const signalTags = (urlSignal.signals || [])
            .map(s => `<span class="url-signal-tag">${this.escapeHtml(s.replace(/_/g, ' '))}</span>`)
            .join('');

        return `
            <div class="url-item">
                <div class="url-domain">${this.escapeHtml(urlSignal.domain || urlSignal.url)}</div>
                ${signalTags ? `<div class="url-signals">${signalTags}</div>` : ''}
            </div>
        `;
    },

    /**
     * Render the explanation section.
     */
    explanation(expl) {
        if (!expl) return '<p style="color: var(--color-text-tertiary)">No explanation available.</p>';

        let html = '';

        if (expl.summary) {
            html += `<p class="explanation-summary">${this.escapeHtml(expl.summary)}</p>`;
        }

        if (expl.reasons && expl.reasons.length) {
            html += `
                <div class="explanation-section">
                    <div class="explanation-section-title">Key Reasons</div>
                    <ul class="explanation-list">
                        ${expl.reasons.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (expl.uncertainty) {
            html += `<div class="explanation-uncertainty">${this.escapeHtml(expl.uncertainty)}</div>`;
        }

        return html;
    },

    /**
     * Render the attack path.
     */
    attackPath(steps) {
        if (!steps || !steps.length) return '';

        const stepsHtml = steps.map((step, i) => `
            <div class="attack-path-step">
                <div class="attack-path-number">${i + 1}</div>
                <div class="attack-path-text">${this.escapeHtml(step)}</div>
            </div>
        `).join('');

        return `<div class="attack-path-steps">${stepsHtml}</div>`;
    },

    /**
     * Render the adaptive response.
     */
    response(resp) {
        if (!resp) return '<p style="color: var(--color-text-tertiary)">No response guidance available.</p>';

        const urgencyClass = resp.urgency || 'normal';
        const listClass = urgencyClass === 'critical' || urgencyClass === 'urgent' ? 'urgent' : 'normal';

        let html = `<span class="response-urgency-badge ${urgencyClass}">${urgencyClass.toUpperCase()}</span>`;

        if (resp.immediate_actions && resp.immediate_actions.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">Immediate Actions</div>
                    <ul class="response-list ${listClass}">
                        ${resp.immediate_actions.map(a => `<li>${this.escapeHtml(a)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (resp.recovery_steps && resp.recovery_steps.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">Recovery Steps</div>
                    <ul class="response-list normal">
                        ${resp.recovery_steps.map(s => `<li>${this.escapeHtml(s)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (resp.reporting_info && resp.reporting_info.length) {
            html += `
                <div class="response-section">
                    <div class="response-section-title">Report This</div>
                    <ul class="response-list normal">
                        ${resp.reporting_info.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        return html;
    },

    /**
     * HTML-escape for safe rendering.
     */
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },
};
