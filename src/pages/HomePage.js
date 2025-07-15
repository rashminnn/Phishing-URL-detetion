import React from 'react';
import UrlScanner from '../components/UrlScanner';
import Features from '../components/Features';

const HomePage = () => {
  return (
    <div className="home-page">
      <div className="hero-section">
        <div className="container text-center">
          <h1 className="display-4 fw-bold mb-2">PhishGuard</h1>
          <p className="lead mb-0">Advanced URL Security Scanner </p>
        </div>
      </div>
      
      <div className="container py-4">
        <UrlScanner />
        <Features />
      </div>
    </div>
  );
};

export default HomePage;