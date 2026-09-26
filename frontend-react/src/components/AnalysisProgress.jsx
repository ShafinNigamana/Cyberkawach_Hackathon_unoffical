import './AnalysisProgress.css';

/**
 * Loading/progress state during analysis.
 */
export default function AnalysisProgress({ stage }) {
  return (
    <div className="analysis-progress" role="status" aria-live="polite">
      <div className="progress-spinner" aria-hidden="true" />
      <p className="progress-title">Analyzing your submission</p>
      {stage && <p className="progress-stage">{stage}</p>}
      <ol className="progress-steps">
        <li>Extract indicators</li>
        <li>Analyze content patterns</li>
        <li>Check threat intelligence</li>
        <li>Build risk assessment</li>
        <li>Generate guidance</li>
      </ol>
    </div>
  );
}
