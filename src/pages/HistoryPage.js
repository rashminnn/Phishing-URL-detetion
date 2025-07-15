import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { getScanHistory } from '../services/api';
import LoadingSpinner from '../components/LoadingSpinner';

const HistoryPage = () => {
  const [history, setHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        // Try to get history from local storage first
        const localHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
        
        if (localHistory.length > 0) {
          setHistory(localHistory);
          setIsLoading(false);
          return;
        }
        
        // If no local history, try to fetch from API
        const apiHistory = await getScanHistory();
        setHistory(apiHistory);
        
        // Save to local storage
        localStorage.setItem('scanHistory', JSON.stringify(apiHistory));
      } catch (err) {
        console.error('Error fetching history:', err);
        setError('Failed to load scan history. Please try again later.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
  }, []);

  const formatDate = (dateString) => {
    try {
      const date = new Date(dateString);
      return date.toLocaleString();
    } catch (e) {
      return dateString;
    }
  };

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
          <h1 className="fw-bold">Scan History</h1>
          <p className="lead mb-0">Your recent URL security checks</p>
        </div>
      </div>

      <div className="container py-4">
        <div className="history-card">
          <h3 className="mb-4"><i className="fas fa-history me-2"></i>Recent Scans</h3>
          
          {error && (
            <div className="alert alert-danger">{error}</div>
          )}
          
          {history.length > 0 ? (
            <div className="list-group">
              {history.map((item, index) => (
                <div className="history-item" key={index}>
                  <div className="d-flex justify-content-between align-items-start">
                    <div>
                      <h6 className="mb-1 text-break">{item.url}</h6>
                      <p className="mb-0 text-muted small">
                        <i className="far fa-clock me-1"></i>{formatDate(item.timestamp)}
                        <span className="ms-3">
                          <i className={`fas fa-circle ${item.is_phishing ? 'text-danger' : 'text-success'} me-1`} style={{fontSize: '0.6rem'}}></i>
                          {item.is_phishing ? 'Phishing Detected' : 'Safe'}
                        </span>
                      </p>
                    </div>
                    <Link 
                      to="/"
                      className="btn btn-sm btn-outline-primary"
                      onClick={() => {
                        sessionStorage.setItem('prefillUrl', item.url);
                      }}
                    >
                      <i className="fas fa-sync-alt me-1"></i>Rescan
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="history-empty">
              <i className="fas fa-search fa-3x mb-3 text-muted"></i>
              <h5>No scan history yet</h5>
              <p>Your recent URL scans will appear here.</p>
            </div>
          )}
          
          <div className="text-center mt-4">
            <Link to="/" className="btn action-primary">
              <i className="fas fa-shield-alt me-2"></i>Scan a New URL
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HistoryPage;