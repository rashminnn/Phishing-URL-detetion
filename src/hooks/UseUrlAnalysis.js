import { useState, useCallback } from 'react';
import { analyzeUrl } from '../services/api';

const useUrlAnalysis = () => {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyzeUrlHook = useCallback(async (url) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await analyzeUrl(url);
      setResult(response);
      return response;
    } catch (err) {
      setError(err.message || 'An error occurred during analysis');
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    result,
    loading,
    error,
    analyzeUrl: analyzeUrlHook
  };
};

export default useUrlAnalysis;