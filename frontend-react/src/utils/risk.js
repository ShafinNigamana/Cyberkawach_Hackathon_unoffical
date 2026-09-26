/**
 * Risk-level utility helpers.
 * Maps backend RiskLevel enum values to display properties.
 */

const RISK_MAP = {
  CRITICAL: {
    label: 'CRITICAL',
    color: 'var(--risk-critical)',
    bg: 'var(--risk-critical-bg)',
  },
  HIGH: {
    label: 'HIGH RISK',
    color: 'var(--risk-high)',
    bg: 'var(--risk-high-bg)',
  },
  MEDIUM: {
    label: 'MEDIUM',
    color: 'var(--risk-medium)',
    bg: 'var(--risk-medium-bg)',
  },
  LOW: {
    label: 'LOW',
    color: 'var(--risk-low)',
    bg: 'var(--risk-low-bg)',
  },
  UNKNOWN: {
    label: 'UNKNOWN',
    color: 'var(--risk-unknown)',
    bg: 'var(--risk-unknown-bg)',
  },
};

export function getRiskDisplay(level) {
  return RISK_MAP[level] || RISK_MAP.UNKNOWN;
}

/**
 * Format risk score from 0-1 to 0-100 display.
 */
export function formatRiskScore(score) {
  if (score == null || isNaN(score)) return '—';
  return Math.round(score * 100);
}

/**
 * Format processing time in ms to human-readable.
 */
export function formatTime(ms) {
  if (ms == null) return '';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/**
 * Safely truncate text.
 */
export function truncate(text, maxLen = 100) {
  if (!text) return '';
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + '…';
}

/**
 * Map evidence type to human-readable label.
 */
export function evidenceTypeLabel(type) {
  const labels = {
    rule_match: 'Rule Match',
    url_analysis: 'URL Analysis',
    brand_mismatch: 'Brand Mismatch',
    threat_intel_hit: 'Threat Intelligence Hit',
    threat_intel_miss: 'Threat Intelligence Miss',
    laya_signal: 'Laya Signal',
    ioc_extracted: 'Indicator Extracted',
    pattern_match: 'Pattern Match',
    domain_age: 'Domain Age',
    redirect_chain: 'Redirect Chain',
    campaign_link: 'Campaign Link',
  };
  return labels[type] || type;
}

/**
 * Map user_state enum to human-readable label.
 */
export function userStateLabel(state) {
  const labels = {
    received: 'I only received the message',
    clicked: 'I clicked the link',
    entered_credentials: 'I entered credentials',
    paid: 'I made a payment',
  };
  return labels[state] || state;
}
