import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ApiTest = () => {
  const [status, setStatus] = useState('Testing API connection...');
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const testApi = async () => {
      try {
        const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:5000';
        console.log('Testing connection to:', apiUrl);
        
        const response = await axios.get(`${apiUrl}/test`);
        setStatus(`API connection successful! Response: ${JSON.stringify(response.data)}`);
      } catch (err) {
        console.error('API test failed:', err);
        setError(`API connection failed: ${err.message}`);
      }
    };
    
    testApi();
  }, []);
  
  return (
    <div className="mt-3 p-3 border rounded">
      <h5>API Connection Test</h5>
      {error ? (
        <div className="text-danger">{error}</div>
      ) : (
        <div className="text-success">{status}</div>
      )}
    </div>
  );
};

export default ApiTest;