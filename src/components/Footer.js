import React from 'react';

const Footer = () => {
  return (
    <footer className="footer mt-auto py-3">
      <div className="container text-center">
        <p className="mb-0">
          © {new Date().getFullYear()} PhishGuard | Developed by{' '}
          <a 
            href="https://github.com/rashminnn" 
            target="_blank" 
            rel="noopener noreferrer"
            className="footer-link"
          >
            rashminnn
          </a>
        </p>
        <p className="small text-muted mt-1">
          Protecting you from phishing attacks
        </p>
      </div>
    </footer>
  );
};

export default Footer;