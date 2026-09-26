import './App.css';
import Navbar from './components/Navbar.jsx';
import AnalyzeInput from './components/AnalyzeInput.jsx';
import AnalysisProgress from './components/AnalysisProgress.jsx';
import AnalysisResult from './components/AnalysisResult.jsx';
import ErrorDisplay from './components/ErrorDisplay.jsx';
import { useAnalysis } from './hooks/useAnalysis.js';

/**
 * Main application.
 * Single-page analysis workspace.
 */
export default function App() {
  const { result, loading, error, stage, analyze, updateState, reset } = useAnalysis();

  const handleAnalyze = ({ message, inputType, urls }) => {
    analyze({ message, inputType, urls });
  };

  return (
    <div className="app">
      <Navbar />
      <main className="main-content">
        <div className="page-container">
          {/* Header — only when no result */}
          {!result && !loading && !error && (
            <header className="page-header">
              <h1 className="page-title">Check before you trust.</h1>
              <p className="page-subtitle">
                Analyze a suspicious message, screenshot, or link and understand
                what it means, why it is risky, and what to do next.
              </p>
            </header>
          )}

          {/* Back to new analysis — when showing result */}
          {(result || error) && (
            <button className="back-button" onClick={reset} type="button">
              ← New analysis
            </button>
          )}

          {/* Input — only when no result and not loading */}
          {!result && !loading && !error && (
            <AnalyzeInput onAnalyze={handleAnalyze} loading={loading} />
          )}

          {/* Loading */}
          {loading && !result && (
            <AnalysisProgress stage={stage} />
          )}

          {/* Error */}
          {error && (
            <ErrorDisplay message={error} onRetry={reset} />
          )}

          {/* Result */}
          {result && (
            <AnalysisResult
              result={result}
              onUpdateState={updateState}
              loading={loading}
            />
          )}
        </div>
      </main>
    </div>
  );
}
