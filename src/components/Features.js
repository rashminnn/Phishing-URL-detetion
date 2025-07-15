import React from 'react';

const Features = () => {
  return (
    <div className="row row-cols-1 row-cols-md-3 g-4 mb-4">
      <div className="col">
        <div className="card h-100 border-0 shadow-sm p-3">
          <div className="feature-icon">
            <i className="fas fa-robot"></i>
          </div>
          <div className="card-body px-0 pt-0">
            <h5>ML Powered</h5>
            <p className="text-muted">Using advanced machine learning algorithms to detect even sophisticated phishing attempts.</p>
          </div>
        </div>
      </div>
      <div className="col">
        <div className="card h-100 border-0 shadow-sm p-3">
          <div className="feature-icon">
            <i className="fas fa-bolt"></i>
          </div>
          <div className="card-body px-0 pt-0">
            <h5>Instant Analysis</h5>
            <p className="text-muted">Get immediate results about the safety of any web address before you visit.</p>
          </div>
        </div>
      </div>
      <div className="col">
        <div className="card h-100 border-0 shadow-sm p-3">
          <div className="feature-icon">
            <i className="fas fa-shield-alt"></i>
          </div>
          <div className="card-body px-0 pt-0">
            <h5>Stay Protected</h5>
            <p className="text-muted">Guard against identity theft, data breaches, and financial fraud attempts.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Features;