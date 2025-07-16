import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlparse, unquote
import re
import os
import time
import logging
import hashlib
from datetime import datetime, timedelta
from functools import lru_cache
import uuid
from flask_cors import CORS
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import gc
import psutil

app = Flask(__name__, static_folder='build', static_url_path='')
CORS(app)

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  # 2KB max request size

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Only log to console to save memory
    ]
)
logger = logging.getLogger('phishing_detector')

# Global model variable
model = None

def load_model():
    """Load model with memory optimization"""
    global model
    if model is not None:
        return model
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MODEL_PATH = os.environ.get('MODEL_PATH', os.path.join(BASE_DIR, 'phishing_model_xgboost.pkl'))
    
    try:
        # Log memory before loading
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"Memory before model loading: {memory_before:.2f} MB")
        
        model = joblib.load(MODEL_PATH)
        
        # Log memory after loading
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"Memory after model loading: {memory_after:.2f} MB")
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
        
        # Force garbage collection
        gc.collect()
        
        return model
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None

# Load model at startup
model = load_model()

# ---- Cache Configuration ----
URL_CACHE = {}
CACHE_TTL = 3600
MAX_CACHE_SIZE = 100  # Reduced cache size to save memory

# ---- Allowlist (reduced to save memory) ----
REPUTABLE_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
    'paypal.com', 'netflix.com', 'spotify.com', 'yahoo.com', 'reddit.com',
    'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai'
}

# ---- Precompiled Regex Patterns ----
SUSPICIOUS_PATTERNS = re.compile(
    r'|'.join([
        r'(?<!\.)paypal(?!\.com)',
        r'(?<!\.)apple(?!\.com)',
        r'(?<!\.)amazon(?!\.com)',
        r'\d{10,}',
        r'[a-zA-Z0-9]{30,}',
        r'(?<!\.)bank(?!\.[a-z]{2,3})'
    ])
)
SUSPICIOUS_TLD_PATTERN = re.compile(r'\.(?:tk|ml|ga|cf|bit|pw|top|click|download|work|gq|xyz)(?:/|$)', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_ENCODING_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')
HIGH_RISK_KEYWORDS_PATTERN = re.compile(
    r'\b(?:' + '|'.join([
        'login', 'signin', 'account', 'verification', 'verify', 'secure', 'security',
        'update', 'urgent', 'suspended', 'limited', 'expired', 'confirm', 'activate',
        'password', 'credential', 'authenticate', 'wallet', 'recover', 'unlock'
    ]) + r')\b', re.IGNORECASE
)
UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
SUSPICIOUS_TITLE_PATTERN = re.compile(
    r'\b(?:login|signin|verify|account|suspended|urgent|password|credential)\b', re.IGNORECASE
)

async def fetch_website_content(url):
    """Fetch website HTML content with memory optimization"""
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, allow_redirects=True) as response:
                if response.status == 200:
                    # Limit content size to prevent memory issues
                    content = await response.text()
                    content = content[:5000]  # Reduced from 10KB to 5KB
                    logger.info(f"Successfully fetched content for {url} ({len(content)} bytes)")
                    return content
                else:
                    logger.warning(f"Failed to fetch {url}: Status {response.status}")
                    return None
    except Exception as e:
        logger.error(f"Error fetching content for {url}: {str(e)}")
        return None

def extract_content_features(html_content):
    """Extract features from HTML content with memory optimization"""
    if not html_content:
        return {
            'has_suspicious_title': 0,
            'has_login_form': 0,
            'external_script_count': 0
        }
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract title
        title = soup.title.string if soup.title else ""
        has_suspicious_title = int(bool(SUSPICIOUS_TITLE_PATTERN.search(title)))
        
        # Check for login forms
        forms = soup.find_all('form')
        has_login_form = int(any(
            input_tag.get('type') in ['password', 'email'] or
            input_tag.get('name', '').lower() in ['username', 'password', 'email', 'login']
            for form in forms
            for input_tag in form.find_all('input')
        ))
        
        # Count external scripts
        scripts = soup.find_all('script', src=True)
        external_script_count = sum(1 for script in scripts if re.match(r'^https?://', script['src']))
        
        # Clean up
        soup.decompose()
        
        return {
            'has_suspicious_title': has_suspicious_title,
            'has_login_form': has_login_form,
            'external_script_count': min(external_script_count, 10)
        }
    except Exception as e:
        logger.error(f"Error parsing HTML content: {str(e)}")
        return {
            'has_suspicious_title': 0,
            'has_login_form': 0,
            'external_script_count': 0
        }

def sanitize_url(url):
    if not isinstance(url, str) or not url.strip():
        return ""
    url = url.strip().lower()[:2000]
    if not url.startswith(('http://', 'https://')):
        http_match = re.search(r'https?://[^\s]+', url)
        url = http_match.group(0) if http_match else 'http://' + url
    try:
        url = unquote(url)
    except Exception:
        pass
    if not re.match(r'^https?://[\w\-\.]+\.[a-zA-Z]{2,}(/.*)?$', url):
        return ""
    return url

def get_url_hash(url):
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def cache_result(url, result):
    if len(URL_CACHE) >= MAX_CACHE_SIZE:
        # Remove oldest entries
        oldest_urls = sorted(URL_CACHE.items(), key=lambda x: x[1]['timestamp'])[:20]
        for url_hash, _ in oldest_urls:
            URL_CACHE.pop(url_hash, None)
    url_hash = get_url_hash(url)
    URL_CACHE[url_hash] = {
        'result': result,
        'timestamp': time.time()
    }

def get_cached_result(url):
    url_hash = get_url_hash(url)
    cached = URL_CACHE.get(url_hash)
    if cached and time.time() - cached['timestamp'] < CACHE_TTL:
        return cached['result']
    URL_CACHE.pop(url_hash, None)
    return None

@lru_cache(maxsize=512)  # Reduced cache size
def extract_domain_parts(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return "", ""
        parts = domain.split('.')
        if len(parts) <= 2:
            registered_domain = domain
            subdomain = ""
        else:
            registered_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
        return subdomain, registered_domain
    except Exception:
        return "", ""

@lru_cache(maxsize=512)  # Reduced cache size
def is_legitimate_domain(url):
    try:
        subdomain, registered_domain = extract_domain_parts(url)
        if not registered_domain:
            return False
        return registered_domain in REPUTABLE_DOMAINS
    except Exception:
        return False

def extract_url_features(url, parsed=None, html_content=None):
    if parsed is None:
        parsed = urlparse(url) if url else urlparse('')
    domain = parsed.netloc.lower()
    subdomain, registered_domain = extract_domain_parts(url)
    
    url_length = len(url)
    domain_length = len(domain)
    url_length_norm = np.log1p(url_length)
    
    def calculate_entropy(s):
        if not s:
            return 0
        prob = np.array([s.count(c) / len(s) for c in set(s)])
        return -np.sum(prob * np.log2(prob + 1e-10))

    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)
    
    num_subdomains = max(1, subdomain.count('.') + 1) if subdomain else 0
    subdomain_ratio = num_subdomains / (domain_length + 1) if domain_length > 0 else 0
    
    has_ip = int(bool(IP_PATTERN.search(url)))
    has_suspicious_tld = int(bool(SUSPICIOUS_TLD_PATTERN.search(url)))
    has_at_symbol = int('@' in url)
    has_url_encoding = int(bool(URL_ENCODING_PATTERN.search(url)))
    has_uuid = int(bool(UUID_PATTERN.search(url)))
    has_https = int(parsed.scheme == 'https')
    has_high_risk_keywords = int(bool(HIGH_RISK_KEYWORDS_PATTERN.search(url)))
    
    path_depth = parsed.path.count('/')
    
    # Extract content-based features
    content_features = extract_content_features(html_content)
    
    total_risk_count = (
        has_ip + has_suspicious_tld + has_at_symbol + has_url_encoding +
        has_high_risk_keywords + content_features['has_suspicious_title'] +
        content_features['has_login_form']
    )
    
    return {
        'url_entropy': url_entropy,
        'domain_entropy': domain_entropy,
        'has_ip': has_ip,
        'has_suspicious_tld': has_suspicious_tld,
        'has_high_risk_keywords': has_high_risk_keywords,
        'total_risk_count': total_risk_count,
        'url_length_norm': url_length_norm,
        'subdomain_ratio': subdomain_ratio,
        'has_at_symbol': has_at_symbol,
        'has_brand_keywords': 0,  # Simplified
        'path_depth': path_depth,
        'has_url_encoding': has_url_encoding,
        'has_uuid': has_uuid,
        'has_https': has_https,
        'has_suspicious_title': content_features['has_suspicious_title'],
        'has_login_form': content_features['has_login_form'],
        'external_script_count': content_features['external_script_count']
    }

async def analyze_url_async(url):
    """Analyze URL with memory optimization"""
    if not url:
        return {
            'url': url,
            'analysis_id': str(uuid.uuid4())[:8],
            'timestamp': datetime.now().isoformat(),
            'processing_time': 0,
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Invalid URL',
            'details': {'errors': ['Invalid or empty URL'], 'content_fetched': False}
        }

    cached_result = get_cached_result(url)
    if cached_result:
        return cached_result

    start_time = time.time()
    analysis_id = str(uuid.uuid4())[:8]
    
    result = {
        'url': url,
        'analysis_id': analysis_id,
        'timestamp': datetime.now().isoformat(),
        'processing_time': 0,
        'is_phishing': False,
        'confidence': 0.0,
        'risk_level': 'Unknown',
        'analysis_method': 'Unknown',
        'details': {'content_fetched': False, 'errors': []}
    }

    try:
        # Check if legitimate domain first
        if is_legitimate_domain(url):
            result.update({
                'is_phishing': False,
                'confidence': 0.05,
                'risk_level': 'Low',
                'analysis_method': 'Verified Domain Check'
            })
            result['processing_time'] = time.time() - start_time
            cache_result(url, result)
            return result

        # Fetch content and analyze
        parsed = urlparse(url)
        html_content = await fetch_website_content(url)
        result['details']['content_fetched'] = html_content is not None
        
        features = extract_url_features(url, parsed, html_content)
        
        # Ensure model is loaded
        if model is None:
            raise ValueError("Model not loaded")
        
        # Prepare features for prediction
        feature_names = [
            'url_entropy', 'domain_entropy', 'has_ip', 'has_suspicious_tld',
            'has_high_risk_keywords', 'total_risk_count', 'url_length_norm',
            'subdomain_ratio', 'has_at_symbol', 'has_brand_keywords',
            'path_depth', 'has_url_encoding', 'has_uuid', 'has_https',
            'has_suspicious_title', 'has_login_form', 'external_script_count'
        ]
        
        df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        
        prediction = model.predict(df)[0]
        prediction_proba = model.predict_proba(df)[0][1]
        
        result.update({
            'is_phishing': bool(prediction),
            'confidence': float(prediction_proba),
            'risk_level': 'High' if prediction_proba > 0.8 else 'Medium' if prediction_proba > 0.5 else 'Low',
            'analysis_method': 'Machine Learning Analysis'
        })
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        result['details']['errors'].append(f"Analysis error: {str(e)}")
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback'
        })

    result['processing_time'] = time.time() - start_time
    cache_result(url, result)
    
    # Force garbage collection after analysis
    gc.collect()
    
    return result

# ---- Flask Routes ----
@app.route('/api/test', methods=['GET'])
def test_api():
    return jsonify({
        'status': 'success',
        'message': 'PhishGuard API is working!',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        url = request.json.get('url', '')
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        
        # Run async function in event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(analyze_url_async(url))
            return jsonify(result)
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"Request error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/feedback', methods=['POST'])
def feedback():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        data = request.json
        analysis_id = data.get('analysis_id')
        url = data.get('url')
        feedback_type = data.get('feedback_type')
        if not all([analysis_id, url, feedback_type]):
            return jsonify({'error': 'Missing required feedback data'}), 400
        if feedback_type not in ['false_positive', 'false_negative']:
            return jsonify({'error': 'Invalid feedback type'}), 400
        logger.info(f"Feedback: {feedback_type} for {analysis_id}")
        return jsonify({'success': True, 'message': 'Thank you for your feedback!'})
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'error': 'Failed to process feedback'}), 500

@app.route('/api/check', methods=['POST'])
def api_check():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        data = request.json
        url = data.get('url', '')
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        
        # Run async function in event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(analyze_url_async(url))
            api_response = {
                'url': result['url'],
                'is_phishing': result['is_phishing'],
                'confidence': result['confidence'],
                'risk_level': result['risk_level'],
                'analysis_id': result['analysis_id'],
                'timestamp': result['timestamp']
            }
            return jsonify(api_response)
        finally:
            loop.close()
            
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({'error': 'An error occurred during analysis'}), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    if path != '' and not path.startswith('api/'):
        return send_from_directory(app.static_folder, path)
    if not path.startswith('api/'):
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({'error': 'API route not found'}), 404

@app.errorhandler(404)
def page_not_found(e):
    if not request.path.startswith('/api/'):
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({'error': 'API endpoint not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    if model is None:
        logger.critical("Cannot start - model failed to load")
        exit(1)
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=False, host='0.0.0.0', port=port)