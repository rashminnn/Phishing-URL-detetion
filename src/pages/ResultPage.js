import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import AnalysisResult from '../components/AnalysisResult';
import SecurityTips from '../components/SecurityTips';
import LoadingSpinner from '../components/LoadingSpinner';

const ResultPage = () => {
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Get result from sessionStorage
    const storedResult = sessionStorage.getItem('analysisResult');
    
    if (!storedResult) {
      // If no result is found, redirect to home page
      navigate('/');
      return;
    }
    
    try {
      const parsedResult = JSON.parse(storedResult);
      setResult(parsedResult);
    } catch (error) {
      console.error('Error parsing result:', error);
      navigate('/');
    } finally {
      setIsLoading(false);
    }
  }, [navigate]);

  if (isLoading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '50vh' }}>
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div>
      <div className="header-section">
        <div className="container text-center">
          <h1 className="fw-bold">PhishGuard</h1>
          <p className="lead mb-0">URL Analysis Results</p>
        </div>
      </div>

      <div className="result-container container">
        {result && <AnalysisResult result={result} />}
        <SecurityTips />
      </div>
    </div>
  );
};

export default ResultPage;