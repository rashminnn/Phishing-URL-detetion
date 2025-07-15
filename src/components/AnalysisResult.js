import React from 'react';
import { Link } from 'react-router-dom';

const AnalysisResult = ({ result }) => {
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(
      () => alert('URL copied to clipboard!'),
      () => alert('Failed to copy URL')
    );
  };

  const reportAnalysis = (url) => {
    alert('Thank you for your feedback! This URL has been reported for review.');
  };

  return (
    <div className="result-card">
      <div className="url-display">
        <div className="d-flex justify-content-between align-items-start">
          <div>
            <span className="d-block text-secondary mb-1">Analyzed URL:</span>
            <span className="fw-medium">{result.url}</span>
          </div>
          <button
            className="btn btn-sm btn-outline-secondary"
            onClick={() => copyToClipboard(result.url)}
            title="Copy URL"
          >
            <i className="far fa-copy"></i>
          </button>
        </div>
      </div>

      {result.is_phishing ? (
        <div className="verdict-box verdict-phishing">
          <div className="verdict-icon">
            <i className="fas fa-exclamation-triangle"></i>
          </div>
          <h3 className="mb-2">High Risk Detected</h3>
          <p className="mb-0">
            This URL exhibits multiple characteristics commonly associated with phishing attempts.
          </p>
        </div>
      ) : (
        <div className="verdict-box verdict-safe">
          <div className="verdict-icon">
            <i className="fas fa-shield-alt"></i>
          </div>
          <h3 className="mb-2">URL Appears Safe</h3>
          <p className="mb-0">
            Our security check did not identify significant phishing indicators in this URL.
          </p>
        </div>
      )}

      <div className="row align-items-center mb-4">
        <div className="col-md-4 text-center mb-3 mb-md-0">
          <p
            className={`risk-percentage ${
              result.confidence > 0.5 ? 'text-danger' : 'text-success'
            }`}
          >
            {(result.confidence * 100).toFixed(1)}%
          </p>
          <p className="risk-text">Risk Score</p>
        </div>
        <div className="col-md-8">
          <div className="risk-gauge-container">
            <div className="risk-gauge"></div>
            <div
              className="risk-indicator"
              style={{ left: `${result.confidence * 100}%` }}
            ></div>
          </div>
          <div className="risk-labels">
            <div>Low Risk</div>
            <div>Medium Risk</div>
            <div>High Risk</div>
          </div>
        </div>
      </div>

      <div className="metric-row mb-4">
        <div className="metric-box">
          <div className="small text-secondary mb-1">Risk Level</div>
          <div className="fw-bold">{result.risk_level}</div>
        </div>

        <div className="metric-box">
          <div className="small text-secondary mb-1">Safety Status</div>
          <div className={`fw-bold ${result.is_phishing ? 'text-danger' : 'text-success'}`}>
            {result.is_phishing ? 'Not Recommended' : 'Safe to Visit'}
          </div>
        </div>

        {result.analysis_method && (
          <div className="metric-box">
            <div className="small text-secondary mb-1">Analysis Method</div>
            <div className="fw-bold">{result.analysis_method}</div>
          </div>
        )}
      </div>

      {result.is_phishing ? (
        <div className="detail-section">
          <h5 className="mb-3">Security Concerns</h5>

          <div className="detail-item">
            <div className="detail-icon">
              <i className="fas fa-exclamation-triangle"></i>
            </div>
            <div>
              <h6 className="mb-1">Suspicious Domain Structure</h6>
              <p className="text-secondary small mb-0">
                This URL may use techniques to mimic legitimate websites.
              </p>
            </div>
          </div>

          {result.confidence > 0.8 && (
            <div className="detail-item">
              <div className="detail-icon">
                <i className="fas fa-fingerprint"></i>
              </div>
              <div>
                <h6 className="mb-1">Identity Theft Risk</h6>
                <p className="text-secondary small mb-0">
                  High probability of attempting to collect sensitive personal information.
                </p>
              </div>
            </div>
          )}

          <div className="detail-item">
            <div className="detail-icon">
              <i className="fas fa-shield-alt"></i>
            </div>
            <div>
              <h6 className="mb-1">Security Recommendation</h6>
              <p className="text-secondary small mb-0">
                We strongly advise against visiting this URL or providing any information.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="detail-section">
          <h5 className="mb-3">Security Assessment</h5>

          <div className="detail-item">
            <div className="detail-icon">
              <i className="fas fa-check-circle"></i>
            </div>
            <div>
              <h6 className="mb-1">Domain Analysis</h6>
              <p className="text-secondary small mb-0">
                This URL has a normal structure consistent with legitimate websites.
              </p>
            </div>
          </div>

          <div className="detail-item">
            <div className="detail-icon">
              <i className="fas fa-shield-alt"></i>
            </div>
            <div>
              <h6 className="mb-1">Safety Assessment</h6>
              <p className="text-secondary small mb-0">
                Our analysis indicates this is likely a legitimate website.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="d-flex justify-content-between mt-4">
        <Link to="/" className="btn action-secondary">
          <i className="fas fa-arrow-left me-2"></i>New Scan
        </Link>

        <button onClick={() => reportAnalysis(result.url)} className="btn action-primary">
          <i className="fas fa-flag me-2"></i>Report URL
        </button>
      </div>
    </div>
  );
};

export default AnalysisResult;