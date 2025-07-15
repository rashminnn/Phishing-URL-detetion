import React from 'react';

const SecurityTips = () => {
  return (
    <div className="card border-0 shadow-sm">
      <div className="card-body p-4">
        <h5 className="mb-3">Stay Protected Online</h5>
        
        <div className="mb-3">
          <span className="security-badge badge-success">Tip</span>
          <span>Always check URLs before clicking on links in emails or messages.</span>
        </div>
        
        <div className="mb-3">
          <span className="security-badge badge-warning">Warning</span>
          <span>Be cautious of URLs with misspelled domain names of popular websites.</span>
        </div>
        
        <div className="mb-3">
          <span className="security-badge badge-danger">Danger</span>
          <span>Never provide passwords or personal information on suspicious websites.</span>
        </div>
      </div>
    </div>
  );
};

export default SecurityTips;