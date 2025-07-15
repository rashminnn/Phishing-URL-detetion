import React from 'react';

const LoadingSpinner = ({ size = 'md', color = 'primary' }) => {
  // Size class mapping
  const sizeClass = {
    sm: 'spinner-border-sm',
    md: '',
    lg: 'spinner-border-lg'
  }[size];

  return (
    <div className={`spinner-border text-${color} ${sizeClass}`} role="status">
      <span className="visually-hidden">Loading...</span>
    </div>
  );
};

export default LoadingSpinner;