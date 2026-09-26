import './ErrorDisplay.css';

/**
 * Error/fallback display.
 * Shows user-safe error messages, never raw stack traces.
 */
export default function ErrorDisplay({ message, onRetry }) {
  return (
    <div className="error-display" role="alert">
      <div className="error-icon" aria-hidden="true">!</div>
      <h2 className="error-title">Analysis could not be completed</h2>
      <p className="error-message">{message}</p>
      {onRetry && (
        <button className="btn btn--primary error-retry" onClick={onRetry} type="button">
          Try again
        </button>
      )}
    </div>
  );
}
