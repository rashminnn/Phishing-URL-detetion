import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import LoadingSpinner from './LoadingSpinner';
import { analyzeUrl } from '../services/api';

const UrlScanner = () => {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    
    try {
      const sanitizedUrl = url.trim();
      if (!sanitizedUrl) {
        throw new Error('Please enter a URL');
      }
      
      console.log('Scanning URL:', sanitizedUrl);
      const result = await analyzeUrl(sanitizedUrl);
      console.log('Scan result:', result);
      
      // Store result in sessionStorage for access on result page
      sessionStorage.setItem('analysisResult', JSON.stringify(result));
      navigate('/result');
    } catch (err) {
      console.error('Error in handleSubmit:', err);
      setError(err.message || 'An error occurred while analyzing the URL');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="scanner-card">
      <h2 className="mb-4 text-center">Analyze URL Security</h2>
      
      <form onSubmit={handleSubmit}>
        <div className="mb-4 url-input-group">
          <div className="input-group">
            <span className="input-group-text border-0 bg-transparent">
              <i className="fas fa-link text-secondary"></i>
            </span>
            <input 
              type="url" 
              className="form-control url-input" 
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter a URL (e.g., https://example.com)" 
              required
            />
          </div>
        </div>
        
        {error && <div className="alert alert-danger mb-3">{error}</div>}
        
        <div className="d-grid">
          <button 
            type="submit" 
            className="btn scan-btn btn-primary"
            disabled={isLoading}
          >
            {isLoading ? (
              <><LoadingSpinner size="sm" /> Analyzing...</>
            ) : (
              <><i className="fas fa-shield-alt me-2"></i>Scan URL</>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default UrlScanner;