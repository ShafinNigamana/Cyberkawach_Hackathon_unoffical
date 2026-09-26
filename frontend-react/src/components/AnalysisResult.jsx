import { getRiskDisplay, formatRiskScore, evidenceTypeLabel } from '../utils/risk.js';
import './AnalysisResult.css';

/**
 * Full analysis result display.
 * Renders all fields from the actual AnalyzeResponse.
 */
export default function AnalysisResult({ result, onUpdateState, loading }) {
  if (!result) return null;

  const { risk, evidence, urls, brands, threat_intel, explanation, response, fraud_category, laya } = result;
  const riskDisplay = getRiskDisplay(risk?.level);

  return (
    <div className="analysis-result">
      {/* Risk header */}
      <section className="result-risk-header" aria-label="Risk assessment">
        <div className="risk-badge" style={{ background: riskDisplay.bg, color: riskDisplay.color }}>
          {riskDisplay.label}
        </div>
        <div className="risk-score-row">
          <span className="risk-score" style={{ color: riskDisplay.color }}>
            {formatRiskScore(risk?.score)}
          </span>
          <span className="risk-score-max">/ 100</span>
        </div>
        {fraud_category && (
          <div className="risk-category">{fraud_category.replace(/_/g, ' ').toUpperCase()}</div>
        )}
        {risk?.contributing_factors?.length > 0 && (
          <ul className="risk-factors">
            {risk.contributing_factors.map((f, i) => (
              <li key={i} className="risk-factor">{f}</li>
            ))}
          </ul>
        )}
      </section>

      {/* Explanation */}
      {explanation && (
        <section className="result-section" aria-label="Explanation">
          <h2 className="section-title">
            {explanation.is_fallback ? 'Analysis Summary' : 'Why this matters'}
          </h2>
          {explanation.summary && (
            <p className="explanation-summary">{explanation.summary}</p>
          )}
          {explanation.reasons?.length > 0 && (
            <div className="explanation-reasons">
              <h3 className="subsection-title">Why this was flagged</h3>
              <ul className="reason-list">
                {explanation.reasons.map((r, i) => (
                  <li key={i} className="reason-item">{r}</li>
                ))}
              </ul>
            </div>
          )}
          {explanation.uncertainty && (
            <p className="explanation-uncertainty">{explanation.uncertainty}</p>
          )}
          <p className="explanation-model">
            {explanation.is_fallback ? 'Deterministic analysis' : `Model: ${explanation.model_used || 'Unknown'}`}
          </p>
        </section>
      )}

      {/* Evidence */}
      {evidence?.length > 0 && (
        <section className="result-section" aria-label="Evidence">
          <h2 className="section-title">Evidence</h2>
          <div className="evidence-table-wrap">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Description</th>
                  <th>Source</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((item, i) => (
                  <tr key={i}>
                    <td className="evidence-type">{evidenceTypeLabel(item.type)}</td>
                    <td>{item.description}</td>
                    <td className="evidence-source">{item.source}</td>
                    <td className="evidence-confidence">
                      {item.confidence != null ? `${Math.round(item.confidence * 100)}%` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* URL/Domain findings */}
      {urls?.length > 0 && (
        <section className="result-section" aria-label="URL analysis">
          <h2 className="section-title">URL & Domain Findings</h2>
          {urls.map((u, i) => (
            <div key={i} className="url-finding">
              <div className="url-finding-header">
                <span className="url-finding-domain">{u.domain || 'Unknown domain'}</span>
                {u.is_shortened && <span className="url-tag">Shortened</span>}
              </div>
              <div className="url-finding-url">{u.url}</div>
              {u.signals?.length > 0 && (
                <div className="url-signals">
                  {u.signals.map((s, j) => (
                    <span key={j} className="url-signal">{s.replace(/_/g, ' ')}</span>
                  ))}
                </div>
              )}
              {u.redirect_chain?.length > 0 && (
                <div className="url-redirects">
                  <span className="url-redirect-label">Redirect chain:</span>
                  {u.redirect_chain.map((r, j) => (
                    <span key={j} className="url-redirect-step">{r}</span>
                  ))}
                </div>
              )}
              {u.final_url && u.final_url !== u.url && (
                <div className="url-final">Final: {u.final_url}</div>
              )}
            </div>
          ))}
        </section>
      )}

      {/* Brand impersonation */}
      {brands?.length > 0 && (
        <section className="result-section" aria-label="Brand impersonation">
          <h2 className="section-title">Brand Impersonation</h2>
          <div className="evidence-table-wrap">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Claimed Organization</th>
                  <th>Verification</th>
                  <th>Confidence</th>
                  <th>Legitimate Domain</th>
                </tr>
              </thead>
              <tbody>
                {brands.map((b, i) => (
                  <tr key={i}>
                    <td className="brand-name">{b.brand_name}</td>
                    <td className="brand-match-type">
                      {b.match_type ? b.match_type.replace(/_/g, ' ') : 'Unknown'}
                    </td>
                    <td>{Math.round(b.confidence * 100)}%</td>
                    <td>{b.legitimate_domain || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Threat intelligence */}
      {threat_intel?.length > 0 && (
        <section className="result-section" aria-label="Threat intelligence">
          <h2 className="section-title">Threat Intelligence</h2>
          <div className="evidence-table-wrap">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Result</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {threat_intel.map((ti, i) => (
                  <tr key={i}>
                    <td className="ti-source">{ti.source.replace(/_/g, ' ')}</td>
                    <td>
                      {ti.error ? (
                        <span className="ti-status ti-status--unavailable">Unavailable</span>
                      ) : ti.match === true ? (
                        <span className="ti-status ti-status--match">MATCH</span>
                      ) : ti.match === false ? (
                        <span className="ti-status ti-status--no-match">No match</span>
                      ) : (
                        <span className="ti-status ti-status--unavailable">Unavailable</span>
                      )}
                    </td>
                    <td>{ti.error || ti.details || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Laya (if available) */}
      {laya?.available && (
        <section className="result-section" aria-label="Laya triage">
          <h2 className="section-title">Fast Triage (Laya)</h2>
          <div className="laya-grid">
            <div className="laya-item">
              <span className="laya-label">Fraud probability</span>
              <span className="laya-value">{laya.fraud != null ? `${Math.round(laya.fraud * 100)}%` : '—'}</span>
            </div>
            {laya.fraud_category && (
              <div className="laya-item">
                <span className="laya-label">Category</span>
                <span className="laya-value">{laya.fraud_category.replace(/_/g, ' ')}</span>
              </div>
            )}
            <div className="laya-item">
              <span className="laya-label">Brand impersonation</span>
              <span className="laya-value">{laya.brand_impersonation != null ? `${Math.round(laya.brand_impersonation * 100)}%` : '—'}</span>
            </div>
            <div className="laya-item">
              <span className="laya-label">Credential request</span>
              <span className="laya-value">{laya.credential_request != null ? `${Math.round(laya.credential_request * 100)}%` : '—'}</span>
            </div>
            <div className="laya-item">
              <span className="laya-label">Payment request</span>
              <span className="laya-value">{laya.payment_request != null ? `${Math.round(laya.payment_request * 100)}%` : '—'}</span>
            </div>
            {laya.latency_ms != null && (
              <div className="laya-item">
                <span className="laya-label">Latency</span>
                <span className="laya-value">{Math.round(laya.latency_ms)}ms</span>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Attack path */}
      {explanation?.attack_path?.length > 0 && (
        <section className="result-section" aria-label="Potential attack path">
          <h2 className="section-title">Potential Attack Path</h2>
          <div className="attack-path">
            {explanation.attack_path.map((step, i) => (
              <div key={i} className="attack-step">
                <div className="attack-step-marker">{String(i + 1).padStart(2, '0')}</div>
                <div className="attack-step-text">{step}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* User action assessment */}
      <section className="result-section" aria-label="User action assessment">
        <h2 className="section-title">What happened after you received it?</h2>
        <div className="user-actions">
          {[
            { value: 'received', label: 'I only received the message' },
            { value: 'clicked', label: 'I clicked the link' },
            { value: 'entered_credentials', label: 'I entered credentials' },
            { value: 'paid', label: 'I made a payment' },
          ].map((action) => (
            <button
              key={action.value}
              className={`user-action-btn ${response?.user_state === action.value ? 'user-action-btn--active' : ''}`}
              onClick={() => onUpdateState(result.incident_id, action.value)}
              disabled={loading}
              type="button"
            >
              {action.label}
            </button>
          ))}
        </div>
      </section>

      {/* Adaptive response */}
      {response && (
        <section className="result-section" aria-label="Recommended actions">
          <h2 className="section-title">
            Your next steps
            {response.urgency === 'critical' && (
              <span className="urgency-badge urgency-badge--critical">URGENT</span>
            )}
          </h2>
          {response.immediate_actions?.length > 0 && (
            <div className="response-group">
              <h3 className="subsection-title">Immediate actions</h3>
              <ol className="action-list">
                {response.immediate_actions.map((a, i) => (
                  <li key={i} className="action-item">{a}</li>
                ))}
              </ol>
            </div>
          )}
          {response.recovery_steps?.length > 0 && (
            <div className="response-group">
              <h3 className="subsection-title">Recovery steps</h3>
              <ol className="action-list">
                {response.recovery_steps.map((s, i) => (
                  <li key={i} className="action-item">{s}</li>
                ))}
              </ol>
            </div>
          )}
          {response.reporting_info?.length > 0 && (
            <div className="response-group">
              <h3 className="subsection-title">Report to</h3>
              <ul className="report-list">
                {response.reporting_info.map((r, i) => (
                  <li key={i} className="report-item">{r}</li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* Processing metadata */}
      <footer className="result-footer">
        <span>Incident: {result.incident_id}</span>
        {result.processing_time_ms != null && (
          <span>Processed in {Math.round(result.processing_time_ms)}ms</span>
        )}
        <span>
          Modules: {result.modules_executed?.length || 0} executed
          {result.modules_failed?.length > 0 && `, ${result.modules_failed.length} failed`}
        </span>
      </footer>
    </div>
  );
}
