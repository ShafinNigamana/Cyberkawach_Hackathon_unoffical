/**
 * Main application logic — wires the UI to the API.
 */

(function () {
    'use strict';

    // ─── DOM references ───
    const form = document.getElementById('analyze-form');
    const messageInput = document.getElementById('message-input');
    const inputType = document.getElementById('input-type');
    const userState = document.getElementById('user-state');
    const urlsInput = document.getElementById('urls-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const sampleBtn = document.getElementById('sample-btn');
    const samplesDropdown = document.getElementById('samples-dropdown');
    const samplesList = document.getElementById('samples-list');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const healthStatus = document.getElementById('health-status');

    // Result panels
    const riskBanner = document.getElementById('risk-banner');
    const riskCircle = document.getElementById('risk-circle');
    const riskScore = document.getElementById('risk-score');
    const riskLevel = document.getElementById('risk-level');
    const riskCategory = document.getElementById('risk-category');
    const riskMeta = document.getElementById('risk-meta');
    const explanationSource = document.getElementById('explanation-source');
    const explanationContent = document.getElementById('explanation-content');
    const evidenceCount = document.getElementById('evidence-count');
    const evidenceList = document.getElementById('evidence-list');
    const threatIntelList = document.getElementById('threat-intel-list');
    const urlPanel = document.getElementById('url-panel');
    const urlList = document.getElementById('url-list');
    const responseContent = document.getElementById('response-content');
    const stateButtons = document.getElementById('state-buttons');
    const attackPathPanel = document.getElementById('attack-path-panel');
    const attackPathContent = document.getElementById('attack-path-content');
    const metaTime = document.getElementById('meta-time');
    const metaModules = document.getElementById('meta-modules');
    const metaIncidentId = document.getElementById('meta-incident-id');

    // ─── State ───
    let currentResult = null;
    let sampleMessages = [];

    // ─── Health check ───
    async function checkHealth() {
        try {
            const health = await API.health();
            healthStatus.textContent = 'System Online';
            healthStatus.classList.remove('error');
        } catch (e) {
            healthStatus.textContent = 'Backend Offline';
            healthStatus.classList.add('error');
        }
    }

    // ─── Load sample messages ───
    async function loadSamples() {
        try {
            const resp = await fetch('/../fixtures/sample_messages.json');
            if (!resp.ok) {
                // Try alternative path
                const resp2 = await fetch('/fixtures/sample_messages.json');
                if (resp2.ok) {
                    sampleMessages = await resp2.json();
                }
            } else {
                sampleMessages = await resp.json();
            }
        } catch (e) {
            // Inline fallback samples
            sampleMessages = [
                {
                    id: 'demo-banking',
                    label: 'SBI KYC Scam (Banking)',
                    input_type: 'sms',
                    message: 'Dear Customer, Your SBI account has been BLOCKED due to incomplete KYC verification. Update your KYC immediately to avoid permanent account closure. Click here: https://sbi-kyc-update.xyz/verify?ref=8827361 or call 9876543210. Last date: 24 hours. -SBI Team',
                },
                {
                    id: 'demo-courier',
                    label: 'Fake Delivery (Courier)',
                    input_type: 'sms',
                    message: 'Your parcel from Amazon could not be delivered due to incorrect address. Please reschedule delivery by paying Rs. 25 customs charge: https://amaz0n-delivery.top/reschedule Track: AWB7839201. -Delhivery',
                },
                {
                    id: 'demo-govt',
                    label: 'Income Tax Refund (Government)',
                    input_type: 'email',
                    message: 'Subject: Income Tax Refund - Rs 18,500 Credited\n\nDear Taxpayer,\n\nYour income tax refund of Rs 18,500 has been approved. Due to outdated bank details, the refund could not be processed. Please update your bank account details within 48 hours to receive your refund:\n\nhttps://incometax-refund.click/update-bank\n\nFailure to update will result in cancellation of refund.\n\nRegards,\nIncome Tax Department, Govt. of India',
                },
                {
                    id: 'demo-lottery',
                    label: 'Lottery Prize Scam',
                    input_type: 'chat',
                    message: 'CONGRATULATIONS! You have WON Rs 25,00,000 in the Google Annual Lottery 2026! Your ticket number: GL-29384. To claim your prize, pay the processing fee of Rs 4,999 via Google Pay to merchant@gpay. Contact: lottery.winner2026@gmail.com. Hurry, offer expires in 12 hours!',
                },
            ];
        }

        // Render sample buttons
        samplesList.innerHTML = sampleMessages
            .map(s => `<button type="button" class="sample-item" data-id="${Components.escapeHtml(s.id)}">${Components.escapeHtml(s.label)}</button>`)
            .join('');
    }

    // ─── Toggle samples dropdown ───
    sampleBtn.addEventListener('click', () => {
        samplesDropdown.hidden = !samplesDropdown.hidden;
    });

    // ─── Load sample into form ───
    samplesList.addEventListener('click', (e) => {
        const btn = e.target.closest('.sample-item');
        if (!btn) return;

        const sample = sampleMessages.find(s => s.id === btn.dataset.id);
        if (!sample) return;

        messageInput.value = sample.message;
        if (sample.input_type) inputType.value = sample.input_type;
        samplesDropdown.hidden = true;
        messageInput.focus();
    });

    // ─── Form submission ───
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const message = messageInput.value.trim();
        if (!message) return;

        const urls = urlsInput.value.split('\n').map(u => u.trim()).filter(Boolean);

        // Show loading
        loading.hidden = false;
        results.hidden = true;
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = 'Analyzing...';

        try {
            const result = await API.analyze(
                message,
                inputType.value,
                userState.value,
                urls
            );

            currentResult = result;
            renderResults(result);
        } catch (err) {
            alert(`Analysis failed: ${err.message}\n\nMake sure the backend is running on port 8000.`);
        } finally {
            loading.hidden = true;
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                Analyze Message
            `;
        }
    });

    // ─── Render full results ───
    function renderResults(data) {
        results.hidden = false;

        // Risk banner
        const risk = Components.riskBanner(data.risk, data.fraud_category);
        riskBanner.setAttribute('data-level', risk.level);
        riskScore.textContent = risk.scorePercent;
        riskLevel.textContent = risk.level;
        riskCategory.textContent = risk.categoryLabel;
        riskMeta.textContent = `${data.modules_executed?.length || 0} modules executed · ${data.processing_time_ms?.toFixed(0) || '?'}ms`;

        // Sufficiency badge
        const suff = data.risk?.evidence_sufficiency || 'SUFFICIENT';
        const suffBadge = document.getElementById('sufficiency-badge');
        if (suffBadge) {
            suffBadge.className = `sufficiency-badge sufficiency-badge--${suff.toLowerCase()}`;
            suffBadge.textContent = suff === 'INSUFFICIENT' ? '⚠ INSUFFICIENT EVIDENCE' : '✓ SUFFICIENT EVIDENCE';
        }

        // Explanation
        if (data.explanation) {
            explanationSource.textContent = data.explanation.is_fallback ? 'Deterministic' : 'Gemini';
            explanationContent.innerHTML = Components.explanation(data.explanation);
        } else {
            explanationSource.textContent = '';
            explanationContent.innerHTML = '<p style="color: var(--color-text-tertiary)">No explanation generated.</p>';
        }

        // Evidence items
        evidenceCount.textContent = data.evidence?.length || 0;
        evidenceList.innerHTML = (data.evidence || [])
            .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
            .map(item => Components.evidenceItem(item))
            .join('');

        // Threat intelligence
        threatIntelList.innerHTML = (data.threat_intel || [])
            .map(ti => Components.threatIntelItem(ti))
            .join('');

        if (!data.threat_intel?.length) {
            threatIntelList.innerHTML = '<p style="color: var(--color-text-tertiary); font-size: 0.8125rem;">No threat intelligence data (APIs may not be configured).</p>';
        }

        // URLs
        if (data.urls && data.urls.length) {
            urlPanel.hidden = false;
            urlList.innerHTML = data.urls.map(u => Components.urlItem(u)).join('');
        } else {
            urlPanel.hidden = true;
        }

        // Adaptive response
        responseContent.innerHTML = Components.response(data.response);

        // Update state buttons
        const currentState = data.response?.user_state || 'received';
        stateButtons.querySelectorAll('.btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.state === currentState);
        });

        // Attack path
        if (data.explanation?.attack_path?.length || data.explanation?.structured_attack_path?.length) {
            attackPathPanel.hidden = false;
            attackPathContent.innerHTML = Components.attackPath(data.explanation.attack_path, data.explanation.structured_attack_path);
        } else {
            attackPathPanel.hidden = true;
        }

        // Meta
        metaTime.textContent = `${data.processing_time_ms?.toFixed(0) || '?'}ms`;
        metaModules.textContent = `Modules: ${(data.modules_executed || []).join(', ')}`;
        metaIncidentId.textContent = data.incident_id || '';

        if (data.modules_failed?.length) {
            metaModules.textContent += ` | Failed: ${data.modules_failed.join(', ')}`;
        }

        // Scroll to results
        riskBanner.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ─── State switcher (demo feature) ───
    stateButtons.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-state]');
        if (!btn || !currentResult) return;

        const newState = btn.dataset.state;

        try {
            const updated = await API.updateState(currentResult.incident_id, newState);
            currentResult = updated;

            // Re-render response section
            responseContent.innerHTML = Components.response(updated.response);
            stateButtons.querySelectorAll('.btn').forEach(b => {
                b.classList.toggle('active', b.dataset.state === newState);
            });
        } catch (err) {
            console.error('State update failed:', err);
        }
    });

    // ─── Initialize ───
    checkHealth();
    loadSamples();

    // Periodic health check
    setInterval(checkHealth, 30000);
})();
