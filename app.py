import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, jsonify
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
import warnings
from collections import Counter

# Suppress XGBoost FutureWarning specifically
warnings.filterwarnings('ignore', category=FutureWarning, module='xgboost')
warnings.filterwarnings('ignore', message='Index.format is deprecated')

# Flask app - NO static folder for backend-only deployment
app = Flask(__name__)
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
        logging.StreamHandler()
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
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"Memory before model loading: {memory_before:.2f} MB")
        
        # Suppress warnings during model loading
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = joblib.load(MODEL_PATH)
        
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        logger.info(f"Memory after model loading: {memory_after:.2f} MB")
        logger.info(f"Model loaded successfully from {MODEL_PATH}")
        
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
MAX_CACHE_SIZE = 100

# ---- Allowlist ----
REPUTABLE_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
    'paypal.com', 'netflix.com', 'spotify.com', 'yahoo.com', 'reddit.com',
    'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'grok.com',
    'huggingface.co'  # Added huggingface
}

# ---- Self-reference protection ----
def is_self_reference(url):
    """Check if URL is pointing to this application itself"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return any([
            'huggingface.co' in domain,
            'hf.space' in domain,
            domain == 'localhost',
            domain.startswith('127.'),
            domain.startswith('0.0.0.0')
        ])
    except Exception:
        return False

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

# Brand keywords for detection
BRAND_KEYWORDS = {
    'paypal', 'apple', 'amazon', 'microsoft', 'google', 'facebook', 'twitter',
    'instagram', 'linkedin', 'netflix', 'spotify', 'ebay', 'alibaba', 'whatsapp',
    'telegram', 'signal', 'dropbox', 'adobe', 'oracle', 'salesforce', 'zoom',
    'slack', 'discord', 'github', 'gitlab', 'bitbucket', 'stackoverflow',
    'banking', 'bank', 'visa', 'mastercard', 'amex', 'discover', 'chase',
    'wells', 'fargo', 'citibank', 'bofa', 'hsbc', 'barclays', 'santander'
}

async def fetch_website_content(url):
    """Fetch website HTML content with retry logic and proper session cleanup"""
    if is_self_reference(url):
        logger.warning(f"Skipping self-reference URL: {url}")
        return None
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    
    timeout = aiohttp.ClientTimeout(total=8, connect=3)
    
    for attempt, user_agent in enumerate(user_agents, 1):
        headers = {'User-Agent': user_agent}
        session = None
        try:
            session = aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=10, ttl_dns_cache=300, use_dns_cache=True)
            )
            
            async with session.get(url, allow_redirects=True, headers=headers) as response:
                if response.status == 200:
                    content = await response.text()
                    content = content[:10000]
                    logger.info(f"Successfully fetched content for {url} ({len(content)} bytes) on attempt {attempt}")
                    return content
                else:
                    logger.warning(f"Attempt {attempt} failed for {url}: Status {response.status}")
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout on attempt {attempt} for {url}")
        except Exception as e:
            logger.error(f"Attempt {attempt} error fetching content for {url}: {str(e)}")
        finally:
            if session:
                try:
                    await session.close()
                except Exception as e:
                    logger.warning(f"Error closing session: {e}")
        
        if attempt < len(user_agents):
            logger.info(f"Retrying {url} with different User-Agent")
            await asyncio.sleep(0.5)
            
    logger.error(f"All attempts to fetch {url} failed")
    return None

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

@lru_cache(maxsize=512)
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

@lru_cache(maxsize=512)
def is_legitimate_domain(url):
    try:
        subdomain, registered_domain = extract_domain_parts(url)
        if not registered_domain:
            return False
        return registered_domain in REPUTABLE_DOMAINS
    except Exception:
        return False

def extract_url_features(url, parsed=None, html_content=None):
    """Extract features that match the trained model exactly"""
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
        char_counts = Counter(s)
        total_chars = len(s)
        entropy = -sum((count/total_chars) * np.log2(count/total_chars) for count in char_counts.values())
        return entropy

    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)
    
    num_subdomains = max(1, subdomain.count('.') + 1) if subdomain else 0
    subdomain_ratio = num_subdomains / (domain_length + 1) if domain_length > 0 else 0
    
    has_ip = int(bool(IP_PATTERN.search(url)))
    has_suspicious_tld = int(bool(SUSPICIOUS_TLD_PATTERN.search(url)))
    has_at_symbol = int('@' in url)
    has_url_encoding = int(bool(URL_ENCODING_PATTERN.search(url)))
    has_high_risk_keywords = int(bool(HIGH_RISK_KEYWORDS_PATTERN.search(url)))
    
    has_brand_keywords = 0
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand in BRAND_KEYWORDS:
        if brand in url_lower:
            if not (domain_lower.endswith(f"{brand}.com") or domain_lower == f"{brand}.com"):
                has_brand_keywords = 1
                break
    
    path_depth = parsed.path.count('/')
    
    total_risk_count = (
        has_ip + has_suspicious_tld + has_at_symbol + has_url_encoding +
        has_high_risk_keywords + has_brand_keywords
    )
    
    logger.info(f"Extracted features for {url}: "
                f"entropy={url_entropy:.2f}, "
                f"domain_entropy={domain_entropy:.2f}, "
                f"has_ip={has_ip}, "
                f"suspicious_tld={has_suspicious_tld}, "
                f"brand_keywords={has_brand_keywords}, "
                f"risk_count={total_risk_count}")
    
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
        'has_brand_keywords': has_brand_keywords,
        'path_depth': path_depth,
        'has_url_encoding': has_url_encoding
    }

async def analyze_url_async(url):
    """Analyze URL with actual website content fetching"""
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

    if is_self_reference(url):
        return {
            'url': url,
            'analysis_id': str(uuid.uuid4())[:8],
            'timestamp': datetime.now().isoformat(),
            'processing_time': 0.001,
            'is_phishing': False,
            'confidence': 0.05,
            'risk_level': 'Low',
            'analysis_method': 'Self-Reference Protection',
            'details': {
                'errors': [],
                'content_fetched': False,
                'self_reference': True,
                'note': 'Cannot analyze own application domain'
            }
        }

    cached_result = get_cached_result(url)
    if cached_result:
        logger.info(f"Cache hit for URL: {url}")
        return cached_result

    start_time = time.time()
    analysis_id = str(uuid.uuid4())[:8]
    logger.info(f"Analysis [{analysis_id}] started for URL: {url}")
    
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
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        subdomain, registered_domain = extract_domain_parts(url)
        result['details']['domain'] = {
            'full': domain,
            'registered_domain': registered_domain,
            'subdomain': subdomain,
            'path': parsed.path,
            'query': parsed.query,
            'scheme': parsed.scheme
        }
        
        if is_legitimate_domain(url):
            result.update({
                'is_phishing': False,
                'confidence': 0.05,
                'risk_level': 'Low',
                'analysis_method': 'Verified Domain Check',
                'details': {
                    **result['details'],
                    'verification': {
                        'method': 'Allowlist Match',
                        'matched': True,
                        'notes': 'Domain is on the verified legitimate domains list.'
                    }
                }
            })
            result['processing_time'] = time.time() - start_time
            cache_result(url, result)
            logger.info(f"Analysis [{analysis_id}] completed: LEGITIMATE (Verified Domain)")
            return result

        logger.info(f"Fetching content for URL: {url}")
        try:
            html_content = await asyncio.wait_for(fetch_website_content(url), timeout=15)
            result['details']['content_fetched'] = html_content is not None
            if html_content:
                result['details']['content_size'] = len(html_content)
                logger.info(f"Content fetched successfully: {len(html_content)} bytes")
            else:
                result['details']['errors'].append("Failed to fetch website content")
                logger.warning(f"Failed to fetch content for {url}")
        except asyncio.TimeoutError:
            logger.warning(f"Content fetch timeout for {url}")
            html_content = None
            result['details']['content_fetched'] = False
            result['details']['errors'].append("Content fetch timeout")
        
        features = extract_url_features(url, parsed, html_content)
        result['details']['extracted_features'] = features
        
        if model is None:
            raise ValueError("Model not loaded")
        
        feature_names = [
            'url_entropy', 'domain_entropy', 'has_ip', 'has_suspicious_tld',
            'has_high_risk_keywords', 'total_risk_count', 'url_length_norm',
            'subdomain_ratio', 'has_at_symbol', 'has_brand_keywords',
            'path_depth', 'has_url_encoding'
        ]
        
        df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        
        logger.info(f"Features prepared for model: {dict(zip(feature_names, df.iloc[0].values))}")
        
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                prediction = model.predict(df)[0]
                prediction_proba = model.predict_proba(df)[0][1]
            logger.info(f"Model prediction for {url}: raw_prediction={prediction}, confidence={prediction_proba:.3f}")
        except Exception as e:
            logger.error(f"Model prediction failed: {str(e)}")
            raise ValueError(f"Model prediction error: {str(e)}")
        
        result['details']['ml_prediction'] = {
            'raw_prediction': int(prediction),
            'raw_confidence': float(prediction_proba)
        }

        calibrated_confidence = prediction_proba
        calibration_factors = []
        
        if not result['details']['content_fetched']:
            calibrated_confidence *= 1.1
            calibration_factors.append(('content_fetch_failed', 1.1))
        
        if features['has_brand_keywords'] and features['has_suspicious_tld']:
            calibrated_confidence *= 1.2
            calibration_factors.append(('brand_keywords_suspicious_tld', 1.2))
        
        if features['has_ip']:
            calibrated_confidence *= 1.15
            calibration_factors.append(('ip_address', 1.15))
        
        calibrated_confidence = min(calibrated_confidence, 0.99)
        
        calibrated_prediction = int(calibrated_confidence > 0.5)
        result['details']['calibration'] = {
            'factors': calibration_factors,
            'original_confidence': float(prediction_proba),
            'calibrated_confidence': float(calibrated_confidence)
        }
        
        result.update({
            'is_phishing': bool(calibrated_prediction),
            'confidence': float(calibrated_confidence),
            'risk_level': 'High' if calibrated_confidence > 0.8 else 'Medium' if calibrated_confidence > 0.5 else 'Low',
            'analysis_method': 'ML Analysis with Website Content'
        })
        
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] failed: {str(e)}")
        result['details']['errors'].append(f"Analysis error: {str(e)}")
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback'
        })

    result['processing_time'] = time.time() - start_time
    cache_result(url, result)
    logger.info(f"Analysis [{analysis_id}] completed in {result['processing_time']:.3f}s: "
                f"{'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} "
                f"(confidence: {result['confidence']:.3f})")
    
    gc.collect()
    
    return result

# ---- Flask Routes ----
@app.route('/')
def home():
    """API home route"""
    return jsonify({
        'message': 'PhishGuard API - Phishing URL Detection',
        'status': 'online',
        'version': '1.0',
        'endpoints': {
            '/': 'GET - API information',
            '/api/test': 'GET - Test API status',
            '/predict': 'POST - Analyze URL (full details)',
            '/api/check': 'POST - Check URL (simplified)',
            '/feedback': 'POST - Submit feedback'
        },
        'timestamp': datetime.now().isoformat()
    })

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
        
        if is_self_reference(url):
            return jsonify({
                'error': 'Cannot analyze own application domain',
                'is_phishing': False,
                'confidence': 0.05
            }), 400
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
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
        logger.info(f"Feedback: {feedback_type} for {analysis_id} - URL: {url}")
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
        
        if is_self_reference(url):
            return jsonify({
                'error': 'Cannot analyze own application domain',
                'is_phishing': False,
                'confidence': 0.05
            }), 400
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
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

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    if model is None:
        logger.critical("Cannot start - model failed to load")
        exit(1)
    port = int(os.environ.get('PORT', 7860))
    app.run(debug=False, host='0.0.0.0', port=port)