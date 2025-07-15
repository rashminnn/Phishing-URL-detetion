import axios from 'axios';

// Update this to your Firebase Functions URL
// The environment variable approach is good for different environments
const API_URL = process.env.REACT_APP_API_URL || 'https://us-central1-idptest-b4e6d.cloudfunctions.net/api';
console.log('Using API URL:', API_URL);

// Create an axios instance
const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: false, // This is fine for Firebase Functions
});

// Your existing functions remain the same
export const analyzeUrl = async (url) => {
  try {
    console.log(`Sending request to ${API_URL}/predict with URL: ${url}`);
    
    const response = await apiClient.post('/predict', { url });
    console.log('Received response:', response.data);
    
    // Store in local history
    const historyItem = {
      url: response.data.url,
      is_phishing: response.data.is_phishing,
      confidence: response.data.confidence,
      risk_level: response.data.risk_level,
      timestamp: new Date().toISOString()
    };
    
    const existingHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
    const updatedHistory = [historyItem, ...existingHistory.slice(0, 9)];
    localStorage.setItem('scanHistory', JSON.stringify(updatedHistory));
    
    return response.data;
  } catch (error) {
    console.error('Error analyzing URL:', error);
    
    if (error.response) {
      console.error('Server response data:', error.response.data);
      console.error('Server response status:', error.response.status);
    } else if (error.request) {
      console.error('No response received. Is the backend running?');
    } else {
      console.error('Request setup error:', error.message);
    }
    
    throw new Error(
      error.response?.data?.error || 
      'Failed to analyze URL. Please try again.'
    );
  }
};

// Function to get scan history
export const getScanHistory = () => {
  return JSON.parse(localStorage.getItem('scanHistory') || '[]');
};

// Function to submit feedback
export const submitFeedback = async (data) => {
  try {
    console.log(`Sending feedback to ${API_URL}/feedback`);
    const response = await apiClient.post('/feedback', data);
    return response.data;
  } catch (error) {
    console.error('Error submitting feedback:', error);
    throw new Error(
      error.response?.data?.error || 
      'Failed to submit feedback.'
    );
  }
};

export default apiClient;