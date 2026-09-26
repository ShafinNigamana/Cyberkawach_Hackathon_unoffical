/**
 * Cyber Fraud Guardian — Citizen Threat Triage Client
 * Public Sector Product UI Controller
 */

(function () {
    'use strict';

    // ─── DOM References ───
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
    const charCounter = document.getElementById('char-counter');

    // Action tools
    const btnPasteClip = document.getElementById('btn-paste-clip');
    const btnClearInput = document.getElementById('btn-clear-input');
    const presetChips = document.getElementById('quick-preset-chips');
    const toastContainer = document.getElementById('toast-container');
    const themeToggle = document.getElementById('theme-toggle');
    const themeLabel = document.getElementById('theme-label');

    // Font size controls
    const btnFontDec = document.getElementById('btn-font-dec');
    const btnFontReset = document.getElementById('btn-font-reset');
    const btnFontInc = document.getElementById('btn-font-inc');

    // Dossier actions
    const displayIncidentId = document.getElementById('display-incident-id');
    const btnCopyCaseId = document.getElementById('btn-copy-case-id');
    const btnPrintReport = document.getElementById('btn-print-report');
    const btnCopyFullReport = document.getElementById('btn-copy-full-report');

    // Result panels
    const riskBanner = document.getElementById('risk-banner');
    const riskCircle = document.getElementById('risk-circle');
    const riskScore = document.getElementById('risk-score');
    const riskLevel = document.getElementById('risk-level');
    const riskCategory = document.getElementById('risk-category');
    const riskMeta = document.getElementById('risk-meta');
    const sufficiencyBadge = document.getElementById('sufficiency-badge');
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

    // Preloaded high-impact Indian fraud presets
    const PRESET_MESSAGES = {
        'electricity': {
            message: 'Dear Customer, Your electricity power supply will be disconnected tonight at 09:30 PM from the electricity office due to your previous month bill was not updated. Please immediately contact our power officer 9876543210. Thank you.',
            type: 'sms',
            state: 'received'
        },
        'sbi-kyc': {
            message: 'Dear SBI Customer, Your bank account has been SUSPENDED due to pending KYC verification. To avoid permanent blockage, update your Aadhaar and PAN immediately at: https://sbi-kyc-verify-urgent.com/login or call 1800-11-2211.',
            type: 'sms',
            state: 'received',
            urls: 'https://sbi-kyc-verify-urgent.com/login'
        },
        'courier': {
            message: 'India Post: Your parcel consignment ID PB938472918IN cannot be dispatched due to incorrect delivery address. Update your address and pay standard re-delivery fee of Rs 25 at: http://indiapost-parcel-redelivery.org/tracking to avoid return.',
            type: 'sms',
            state: 'received',
            urls: 'http://indiapost-parcel-redelivery.org/tracking'
        },
        'upi-refund': {
            message: 'Dear Customer, your cashback refund of Rs. 4,999 from Google Pay / PhonePe is pending approval. Scan the QR code or approve the pending Collect Request in your UPI app and enter your UPI PIN to credit your bank account.',
            type: 'chat',
            state: 'received'
        },
        'telegram-task': {
            message: 'Earn Rs 3,000 to Rs 8,000 daily from home! Part-time online job: simply like YouTube videos, submit screenshot, and receive instant payments to your bank. No experience needed. Contact HR manager on Telegram @daily_income_team to start.',
            type: 'chat',
            state: 'received'
        },
        'digital-arrest': {
            message: 'URGENT LEGAL SUMMONS - CBI & Cyber Crime Police: An illegal consignment containing contraband and forged passports linked to your Aadhaar card has been intercepted at customs. Non-bailable arrest warrant issued. Connect immediately via video call for digital arrest and verification.',
            type: 'chat',
            state: 'received'
        },
        'legit-sbi': {
            message: '948201 is your OTP for purchase of Rs 1,250.00 at Amazon India using SBI Netbanking. Never share OTP or passwords with anyone. State Bank of India never calls asking for OTP. Visit official https://onlinesbi.sbi for secure banking.',
            type: 'sms',
            state: 'received',
            urls: 'https://onlinesbi.sbi'
        }
    };

    // ─── Toast Notification System ───
    function showToast(message, duration = 3000) {
        if (!toastContainer) return;
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            <span>${Components.escapeHtml(message)}</span>
        `;
        toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(8px)';
            toast.style.transition = 'all 0.25s ease';
            setTimeout(() => toast.remove(), 250);
        }, duration);
    }

    // ─── Character Counter ───
    function updateCharCounter() {
        if (!messageInput || !charCounter) return;
        const len = messageInput.value.length;
        charCounter.textContent = `${len} character${len === 1 ? '' : 's'}`;
    }

    messageInput.addEventListener('input', updateCharCounter);

    // ─── Paste Tool ───
    if (btnPasteClip) {
        btnPasteClip.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    messageInput.value = text;
                    updateCharCounter();
                    messageInput.focus();
                    showToast('Pasted content from clipboard');
                }
            } catch (err) {
                const manual = prompt('Paste your suspicious message here:');
                if (manual) {
                    messageInput.value = manual;
                    updateCharCounter();
                }
            }
        });
    }

    // ─── Clear Tool ───
    if (btnClearInput) {
        btnClearInput.addEventListener('click', () => {
            messageInput.value = '';
            if (urlsInput) urlsInput.value = '';
            updateCharCounter();
            messageInput.focus();
            showToast('Form cleared');
        });
    }

    // ─── Quick Preset Chips ───
    if (presetChips) {
        presetChips.addEventListener('click', (e) => {
            const chip = e.target.closest('[data-preset]');
            if (!chip) return;

            const presetKey = chip.dataset.preset;
            const data = PRESET_MESSAGES[presetKey];
            if (!data) return;

            messageInput.value = data.message;
            if (inputType) inputType.value = data.type;
            if (userState) userState.value = data.state;
            if (urlsInput) urlsInput.value = data.urls || '';

            updateCharCounter();
            messageInput.focus();
            showToast(`Loaded: ${chip.textContent.trim()}`);

            // Smooth scroll to form
            form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        });
    }

    // ─── Accessibility: Theme Switcher ───
    function initTheme() {
        const savedTheme = localStorage.getItem('cfg_theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        if (themeLabel) {
            themeLabel.textContent = savedTheme === 'dark' ? 'Light Mode' : 'Dark Mode';
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('cfg_theme', next);
            if (themeLabel) {
                themeLabel.textContent = next === 'dark' ? 'Light Mode' : 'Dark Mode';
            }
            showToast(`Switched to ${next === 'dark' ? 'Dark Shield' : 'Light Gov'} mode`);
        });
    }

    // ─── Accessibility: Font Sizing ───
    function setFontSize(size) {
        document.documentElement.setAttribute('data-font-size', size);
        [btnFontDec, btnFontReset, btnFontInc].forEach(b => {
            if (b) b.classList.remove('active');
        });
        if (size === 'small' && btnFontDec) btnFontDec.classList.add('active');
        if (size === 'normal' && btnFontReset) btnFontReset.classList.add('active');
        if (size === 'large' && btnFontInc) btnFontInc.classList.add('active');
    }

    if (btnFontDec) btnFontDec.addEventListener('click', () => setFontSize('small'));
    if (btnFontReset) btnFontReset.addEventListener('click', () => setFontSize('normal'));
    if (btnFontInc) btnFontInc.addEventListener('click', () => setFontSize('large'));

    // ─── Copy Case Ref ID ───
    if (btnCopyCaseId) {
        btnCopyCaseId.addEventListener('click', () => {
            const incId = currentResult?.incident_id || displayIncidentId?.textContent || '';
            if (!incId || incId.includes('PENDING')) {
                showToast('No active incident reference to copy');
                return;
            }
            navigator.clipboard.writeText(incId).then(() => {
                showToast(`Incident ID copied: ${incId}`);
            });
        });
    }

    // ─── Print Report / Save PDF ───
    if (btnPrintReport) {
        btnPrintReport.addEventListener('click', () => {
            window.print();
        });
    }

    // ─── Copy Full Advisory ───
    if (btnCopyFullReport) {
        btnCopyFullReport.addEventListener('click', () => {
            if (!currentResult) {
                showToast('Please analyze a message first');
                return;
            }

            const incId = currentResult.incident_id || 'N/A';
            const risk = currentResult.risk || {};
            const score = Math.round((risk.score || 0) * 100);
            const level = risk.level || 'UNKNOWN';
            const cat = (currentResult.fraud_category || 'Unknown').replace(/_/g, ' ').toUpperCase();
            const actions = currentResult.response?.immediate_actions || [];

            const reportText = [
                '====================================================',
                'CYBER FRAUD GUARDIAN — OFFICIAL CITIZEN ADVISORY',
                `Incident Reference: ${incId}`,
                `Timestamp: ${new Date().toISOString()}`,
                '====================================================',
                `ASSESSMENT: ${level} (${score}/100)`,
                `CATEGORY: ${cat}`,
                `EVIDENTIARY SUFFICIENCY: ${risk.evidence_sufficiency || 'SUFFICIENT'}`,
                '----------------------------------------------------',
                'EXPLANATION SUMMARY:',
                currentResult.explanation?.summary || 'N/A',
                '----------------------------------------------------',
                'IMMEDIATE ACTION DIRECTIVES:',
                ...actions.map((a, i) => `${i + 1}. ${a}`),
                '----------------------------------------------------',
                'EMERGENCY REPORTING:',
                'National Cyber Crime Helpline: 1930 (24x7)',
                'National Reporting Portal: https://cybercrime.gov.in',
                '===================================================='
            ].join('\n');

            navigator.clipboard.writeText(reportText).then(() => {
                showToast('Full Citizen Advisory copied to clipboard');
            });
        });
    }

    // ─── Backend Health Check ───
    async function checkHealth() {
        try {
            const health = await API.health();
            if (healthStatus) {
                healthStatus.textContent = 'System Operational';
                healthStatus.classList.remove('error');
            }
        } catch (e) {
            if (healthStatus) {
                healthStatus.textContent = 'Backend Offline';
                healthStatus.classList.add('error');
            }
        }
    }

    // ─── Load Sample Messages ───
    async function loadSamples() {
        try {
            const resp = await fetch('/fixtures/accuracy_matrix_cases.json');
            if (resp.ok) {
                const cases = await resp.json();
                sampleMessages = cases.slice(0, 10).map(c => ({
                    id: c.id,
                    label: c.name,
                    input_type: c.category === 'banking' ? 'sms' : 'chat',
                    message: c.message
                }));
            }
        } catch (e) {
            sampleMessages = Object.entries(PRESET_MESSAGES).map(([k, v]) => ({
                id: k,
                label: v.message.slice(0, 40) + '...',
                input_type: v.type,
                message: v.message
            }));
        }

        if (samplesList && sampleMessages.length) {
            samplesList.innerHTML = sampleMessages
                .map(s => `<button type="button" class="sample-item" data-id="${Components.escapeHtml(s.id)}">${Components.escapeHtml(s.label)}</button>`)
                .join('');
        }
    }

    if (sampleBtn && samplesDropdown) {
        sampleBtn.addEventListener('click', () => {
            samplesDropdown.hidden = !samplesDropdown.hidden;
        });
    }

    if (samplesList) {
        samplesList.addEventListener('click', (e) => {
            const btn = e.target.closest('.sample-item');
            if (!btn) return;

            const sample = sampleMessages.find(s => s.id === btn.dataset.id);
            if (!sample) return;

            messageInput.value = sample.message;
            if (sample.input_type && inputType) inputType.value = sample.input_type;
            if (samplesDropdown) samplesDropdown.hidden = true;
            updateCharCounter();
            messageInput.focus();
            showToast('Sample scenario loaded');
        });
    }

    // ─── Form Submission ───
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const message = messageInput.value.trim();
        if (!message) return;

        const urls = urlsInput.value.split('\n').map(u => u.trim()).filter(Boolean);

        // Show loading state
        loading.hidden = false;
        loading.style.display = 'flex';
        results.hidden = true;
        results.style.display = 'none';
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `
            <div class="loading-spinner" style="width: 16px; height: 16px; border-width: 2px;"></div>
            <span>Evaluating Evidence...</span>
        `;

        try {
            const result = await API.analyze(
                message,
                inputType.value,
                userState.value,
                urls
            );

            currentResult = result;
            // IMMEDIATELY HIDE LOADING BEFORE RENDERING RESULTS
            loading.hidden = true;
            loading.style.display = 'none';
            renderResults(result);
            showToast('Threat analysis completed');
        } catch (err) {
            loading.hidden = true;
            loading.style.display = 'none';
            alert(`Analysis failed: ${err.message}\n\nPlease verify that the backend is running on port 8000.`);
        } finally {
            loading.hidden = true;
            loading.style.display = 'none';
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = `
                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>Analyze & Verify Message</span>
            `;
        }
    });

    // ─── Render Results Dashboard ───
    function renderResults(data) {
        // Enforce strict hidden on loading
        loading.hidden = true;
        loading.style.display = 'none';
        results.hidden = false;
        results.style.display = 'block';

        // Update Dossier Ref ID
        const incId = data.incident_id || 'INC-2026-UNSPECIFIED';
        if (displayIncidentId) displayIncidentId.textContent = incId;
        if (metaIncidentId) metaIncidentId.textContent = incId;

        // Risk Banner
        const risk = Components.riskBanner(data.risk, data.fraud_category);
        riskBanner.setAttribute('data-level', risk.level);
        riskScore.textContent = risk.scorePercent;
        riskLevel.textContent = risk.level;
        riskCategory.textContent = risk.categoryLabel;
        riskMeta.textContent = `${data.modules_executed?.length || 0} modules evaluated · ${data.processing_time_ms?.toFixed(0) || '?'}ms response`;

        // Evidentiary Sufficiency Badge
        const suff = (data.risk?.evidence_sufficiency || 'SUFFICIENT').toUpperCase();
        if (sufficiencyBadge) {
            sufficiencyBadge.className = `sufficiency-badge sufficiency-badge--${suff.toLowerCase()}`;
            if (suff === 'INSUFFICIENT') {
                sufficiencyBadge.textContent = '⚠ INSUFFICIENT EVIDENCE';
            } else if (suff === 'PARTIAL') {
                sufficiencyBadge.textContent = '⚡ PARTIAL EVIDENCE';
            } else {
                sufficiencyBadge.textContent = '✓ SUFFICIENT EVIDENCE';
            }
        }

        // Grounded Explanation
        if (data.explanation) {
            explanationSource.textContent = data.explanation.is_fallback ? 'Deterministic Fallback' : 'Gemini Grounded';
            explanationContent.innerHTML = Components.explanation(data.explanation);
        } else {
            explanationSource.textContent = '';
            explanationContent.innerHTML = '<p style="color: var(--color-text-tertiary)">No explanation generated.</p>';
        }

        // Factual Evidence Items
        evidenceCount.textContent = data.evidence?.length || 0;
        evidenceList.innerHTML = (data.evidence || [])
            .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
            .map(item => Components.evidenceItem(item))
            .join('');

        // Threat Intelligence Feeds
        threatIntelList.innerHTML = (data.threat_intel || [])
            .map(ti => Components.threatIntelItem(ti))
            .join('');

        if (!data.threat_intel?.length) {
            threatIntelList.innerHTML = '<p style="color: var(--color-text-tertiary); font-size: 0.85rem;">No active threat intelligence matches reported in feeds.</p>';
        }

        // URL Analysis
        if (data.urls && data.urls.length) {
            urlPanel.hidden = false;
            urlList.innerHTML = data.urls.map(u => Components.urlItem(u)).join('');
        } else {
            urlPanel.hidden = true;
        }

        // Adaptive Response Guidance
        responseContent.innerHTML = Components.response(data.response);

        // Update State Simulation Buttons
        const currentState = data.response?.user_state || 'received';
        stateButtons.querySelectorAll('.btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.state === currentState);
        });

        // Traceable Causal Attack Path
        if (data.explanation?.attack_path?.length || data.explanation?.structured_attack_path?.length) {
            attackPathPanel.hidden = false;
            attackPathContent.innerHTML = Components.attackPath(data.explanation.attack_path, data.explanation.structured_attack_path);
        } else {
            attackPathPanel.hidden = true;
        }

        // Meta Footer
        if (metaTime) metaTime.textContent = `${data.processing_time_ms?.toFixed(0) || '?'}ms`;
        if (metaModules) metaModules.textContent = `Modules: ${(data.modules_executed || []).join(', ')}`;

        // Scroll to results banner smoothly
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ─── State Switcher (Interactive Citizen Journey Simulator) ───
    if (stateButtons) {
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
                showToast(`Situation updated to: ${btn.textContent.trim()}`);
            } catch (err) {
                console.error('State update failed:', err);
                showToast('Unable to update situation state');
            }
        });
    }

    // ─── Initial Startup ───
    initTheme();
    updateCharCounter();
    checkHealth();
    loadSamples();

    // Heartbeat every 30s
    setInterval(checkHealth, 30000);
})();
