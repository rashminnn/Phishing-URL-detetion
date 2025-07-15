import React from 'react';
import { Link } from 'react-router-dom';

const ErrorPage = () => {
  return (
    <div className="d-flex align-items-center justify-content-center" style={{ minHeight: '70vh' }}>
      <div className="text-center error-container">
        <div className="error-icon">
          <i className="fas fa-exclamation-circle"></i>
        </div>
        <h1 className="display-1 fw-bold">404</h1>
        <h2 className="mb-4">Page Not Found</h2>
        <p className="lead mb-4">The page you're looking for doesn't exist or has been moved.</p>
        <Link to="/" className="btn action-primary btn-lg">
          <i className="fas fa-home me-2"></i>
          Return Home
        </Link>
      </div>
    </div>
  );
};

export default ErrorPage;