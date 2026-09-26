/**
 * UI component renderers — pure functions that return HTML strings.
 * Upgraded with epistemic status badges, factual observation vs interpretation,
 * negative bounds ("What the Guardian Cannot Conclude"), and traceable attack paths.
 */

const Components = {
    /**
     * Render the risk score banner data.
     */
    riskBanner(risk, category) {
        const scorePercent = Math.round((risk.score || 0) * 100);
        const level = risk.level || 'UNKNOWN';
        const categoryLabel = category
            ? category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
            : 'Unknown Category';
        const evidenceSufficiency = risk.evidence_sufficiency || 'SUFFICIENT';

        return { level, scorePercent, categoryLabel, evidenceSufficiency };
    },

    /**
     * Render a single evidence item with epistemic status and factual separation.
     */
    evidenceItem(item) {
        const confidencePercent = item.confidence != null ? `${Math.round(item.confidence * 100)}%` : '--';
        const status = (item.status || 'OBSERVED').toUpperCase();
        const reliability = (item.reliability || '').replace(/_/g, ' ');

        let factRow = '';
        if (item.observed_value) {
            factRow = `
                <div class="evidence-fact-row">
                    <span class="evidence-fact-label">Observed Fact:</span>
                    <span class="evidence-fact-val">${this.escapeHtml(item.observed_value)}</span>
                </div>
            `;
        }

        let interpRow = '';
        if (item.interpretation) {
            interpRow = `
                <div class="evidence-interp-row">
                    <span class="evidence-interp-label">Significance:</span>
                    <span class="evidence-interp-val">${this.escapeHtml(item.interpretation)}</span>
                </div>
            `;
        }

        let groupTag = '';
        if (item.correlation_group) {
            groupTag = `<span class="evidence-group-tag">${this.escapeHtml(item.correlation_group)}</span>`;
        }

        return `
            <div class="evidence-item" data-status="${this.escapeHtml(status.toLowerCase())}">
                <div class="evidence-type-indicator" data-type="${this.escapeHtml(item.type)}"></div>
                <div class="evidence-body">
                    <div class="evidence-header">
                        <span class="epistemic-badge epistemic-badge--${this.escapeHtml(status.toLowerCase())}">${this.escapeHtml(status)}</span>
                        ${reliability ? `<span class="reliability-badge">${this.escapeHtml(reliability)}</span>` : ''}
                        <span class="evidence-source">${this.escapeHtml(item.source)}</span>
                        ${groupTag}
                    </div>
                    <div class="evidence-description">${this.escapeHtml(item.description)}</div>
                    ${factRow}
                    ${interpRow}
                </div>
                <div class="evidence-confidence">${confidencePercent}</div>
            </div>
        `;
    },

    /**
     * Render a threat intel item with 4-state intelligence status.
     */
    threatIntelItem(ti) {
        let statusClass = 'error';
        let statusText = 'UNAVAILABLE';

        const intelStatus = ti.intel_status || (ti.match === true ? 'KNOWN_MALICIOUS' : ti.match === false ? 'NO_KNOWN_MATCH' : 'SOURCE_UNAVAILABLE');

        if (intelStatus === 'KNOWN_MALICIOUS' || ti.match === true) {
            statusClass = 'match';
            statusText = 'KNOWN MALICIOUS';
        } else if (intelStatus === 'NO_KNOWN_MATCH' || ti.match === false) {
            statusClass = 'clean';
            statusText = 'NO KNOWN MATCH';
        } else if (intelStatus === 'SOURCE_UNAVAILABLE') {
            statusClass = 'unavailable';
            statusText = 'FEED UNAVAILABLE';
        } else {
            statusClass = 'error';
            statusText = 'FEED ERROR';
        }

        const sourceLabel = {
            'safe_browsing': 'Google Safe Browsing v4',
            'openphish': 'OpenPhish Community Feed',
            'phishtank': 'PhishTank Database',
            'urlhaus': 'URLhaus Community Feed',
            'abuseipdb': 'AbuseIPDB Feed',
        }[ti.source] || ti.source;

        let details = ti.details || ti.error || '';
        if (!details && intelStatus === 'NO_KNOWN_MATCH') {
            details = 'No active listing in feed (absence does not guarantee URL is safe)';
        }

        return `
            <div class="threat-intel-item">
                <div class="threat-intel-source">${this.escapeHtml(sourceLabel)}</div>
                <span class="threat-intel-status ${statusClass}">${this.escapeHtml(statusText)}</span>
                <div class="threat-intel-details">${this.escapeHtml(details)}</div>
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
     * Render the explanation section with negative bounds.
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

        // Epistemic Negative Bounds: What the system explicitly cannot conclude
        const negativeBounds = expl.what_cannot_be_concluded || [];
        if (negativeBounds.length) {
            html += `
                <div class="negative-bounds-section">
                    <div class="negative-bounds-header">
                        <svg class="icon icon--small" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                        What the Guardian Cannot Conclude
                    </div>
                    <ul class="negative-bounds-list">
                        ${negativeBounds.map(b => `<li>${this.escapeHtml(b)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        if (expl.uncertainty) {
            html += `<div class="explanation-uncertainty"><strong>Uncertainty Assessment:</strong> ${this.escapeHtml(expl.uncertainty)}</div>`;
        }

        return html;
    },

    /**
     * Render the attack path with traceable causal stages and citations.
     */
    attackPath(steps, structuredSteps) {
        if (structuredSteps && structuredSteps.length) {
            const stageLabels = {
                'lure': 'Initial Lure / Engagement',
                'redirection': 'Redirection / Infrastructure',
                'exploitation': 'Solicitation / Exploitation',
                'monetization': 'Potential Consequence / Risk',
                'execution': 'Action Execution',
            };

            const stepsHtml = structuredSteps.map((s, i) => {
                const stageLabel = stageLabels[s.causal_stage] || s.causal_stage;
                const badgesHtml = (s.evidence_indices || []).map(idx =>
                    `<span class="step-evidence-tag">Evidence [${idx}]</span>`
                ).join(' ');

                return `
                    <div class="attack-path-step" data-stage="${this.escapeHtml(s.causal_stage || 'lure')}">
                        <div class="attack-path-number">${s.step_number || (i + 1)}</div>
                        <div class="attack-path-body">
                            <div class="attack-path-stage-header">
                                <span class="attack-path-stage-badge ${this.escapeHtml(s.causal_stage || 'lure')}">${this.escapeHtml(stageLabel)}</span>
                                ${badgesHtml}
                            </div>
                            <div class="attack-path-text">${this.escapeHtml(s.description)}</div>
                            ${s.intended_consequence ? `<div class="attack-path-intended"><strong>Objective:</strong> ${this.escapeHtml(s.intended_consequence)}</div>` : ''}
                        </div>
                    </div>
                `;
            }).join('');

            return `<div class="attack-path-steps">${stepsHtml}</div>`;
        }

        if (!steps || !steps.length) return '';

        const stepsHtml = steps.map((step, i) => `
            <div class="attack-path-step">
                <div class="attack-path-number">${i + 1}</div>
                <div class="attack-path-body">
                    <div class="attack-path-text">${this.escapeHtml(step)}</div>
                </div>
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
