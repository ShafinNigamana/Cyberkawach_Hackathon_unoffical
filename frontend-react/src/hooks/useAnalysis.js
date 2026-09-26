import { useState, useCallback } from 'react';
import { analyzeMessage, updateUserState } from '../services/api.js';

/**
 * Custom hook encapsulating the analysis workflow.
 * Manages loading, result, and error states.
 */
export function useAnalysis() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [stage, setStage] = useState(''); // for progress display

  const analyze = useCallback(async ({ message, inputType, userState, urls, language }) => {
    setLoading(true);
    setError(null);
    setResult(null);
    setStage('Submitting for analysis…');

    try {
      const data = await analyzeMessage({ message, inputType, userState, urls, language });
      setResult(data);
      setStage('');
    } catch (err) {
      setError(err.message || 'Analysis failed. Please try again.');
      setStage('');
    } finally {
      setLoading(false);
    }
  }, []);

  const updateState = useCallback(async (incidentId, newState) => {
    setLoading(true);
    setError(null);

    try {
      const data = await updateUserState(incidentId, newState);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Failed to update. Please try again.');
    } finally {
      setLoading(false);
    }
  }, []);

  const reset = useCallback(() => {
    setResult(null);
    setLoading(false);
    setError(null);
    setStage('');
  }, []);

  return { result, loading, error, stage, analyze, updateState, reset };
}
