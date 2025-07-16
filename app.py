import numpy as np
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
from collections import OrderedDict
import aiohttp
import asyncio
from bs4 import BeautifulSoup

app = Flask(__name__, static_folder='build', static_url_path='')
CORS(app)

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  # 2KB max request size

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('phishing_detector')

# ---- MODEL PATH ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.environ.get('MODEL_PATH', os.path.join(BASE_DIR, 'phishing_model_xgboost.pkl'))

try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None

# ---- Cache Configuration ----
URL_CACHE = OrderedDict()
CONTENT_CACHE = OrderedDict()
CACHE_TTL = 3600
MAX_CACHE_SIZE = 1000

# ---- Precompiled Regex Patterns ----
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
SUBDOMAIN_PATTERN = re.compile(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', re.IGNORECASE)
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

async def fetch_web_content(url):
    """Fetch web content asynchronously with error handling."""
    cache_key = hashlib.md5(url.encode('utf-8')).hexdigest()
    if cache_key in CONTENT_CACHE and time.time() - CONTENT_CACHE[cache_key]['timestamp'] < CACHE_TTL:
        return CONTENT_CACHE[cache_key]['content']
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(url, allow_redirects=True) as response:
                content = {
                    'status_code': response.status,
                    'html': await response.text() if response.status == 200 else '',
                    'headers': dict(response.headers),
                    'redirects': [r.url for r in response.history]
                }
                CONTENT_CACHE[cache_key] = {'content': content, 'timestamp': time.time()}
                if len(CONTENT_CACHE) > MAX_CACHE_SIZE:
                    CONTENT_CACHE.popitem(last=False)
                return content
    except Exception as e:
        logger.warning(f"Failed to fetch content for {url}: {str(e)}")
        return {'status_code': 0, 'html': '', 'headers': {}, 'redirects': []}

def extract_web_features(content):
    """Extract features from web content for ML model."""
    html = content['html']
    status_code = content['status_code']
    headers = content['headers']
    redirects = content['redirects']
    
    # Parse HTML with BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser') if html else None
    
    # Feature: Presence of login form
    has_login_form = int(bool(soup and soup.find('form') and any(
        input_tag.get('type') in ['password', 'email'] for input_tag in soup.find_all('input')
    )))
    
    # Feature: Number of external scripts/links
    external_resources = 0
    if soup:
        scripts = soup.find_all('script', src=True)
        links = soup.find_all('a', href=True)
        external_resources = len([s for s in scripts if s['src'].startswith('http')]) + \
                            len([l for l in links if l['href'].startswith('http')])
    
    # Feature: Presence of meta verification tags (e.g., Google, Facebook)
    has_meta_verification = int(bool(soup and soup.find('meta', attrs={
        'name': re.compile(r'google-site-verification|facebook-domain-verification', re.I)
    })))
    
    # Feature: Redirect count
    redirect_count = len(redirects)
    
    # Feature: Suspicious redirect (to different domain)
    suspicious_redirect = 0
    if redirects:
        parsed_url = urlparse(content['url'])
        for redirect_url in redirects:
            redirect_domain = urlparse(str(redirect_url)).netloc.lower()
            if redirect_domain and redirect_domain != parsed_url.netloc.lower():
                suspicious_redirect = 1
                break
    
    # Feature: Content length
    content_length = len(html) if html else 0
    content_length_norm = np.log1p(content_length)
    
    return {
        'has_login_form': has_login_form,
        'external_resources': external_resources,
        'has_meta_verification': has_meta_verification,
        'redirect_count': redirect_count,
        'suspicious_redirect': suspicious_redirect,
        'content_length_norm': content_length_norm,
        'status_code': status_code / 1000.0  # Normalize status code
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
    url_hash = get_url_hash(url)
    URL_CACHE[url_hash] = {'result': result, 'timestamp': time.time()}
    if len(URL_CACHE) > MAX_CACHE_SIZE:
        URL_CACHE.popitem(last=False)

def get_cached_result(url):
    url_hash = get_url_hash(url)
    cached = URL_CACHE.get(url_hash)
    if cached and time.time() - cached['timestamp'] < CACHE_TTL:
        return cached['result']
    URL_CACHE.pop(url_hash, None)
    return None

@lru_cache(maxsize=1024)
def extract_domain_parts(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return "", ""
        parts = domain.split('.')
        special_tlds = {'co.uk', 'com.au', 'co.jp', 'co.nz', 'org.uk', 'gov.uk', 'ac.uk'}
        if len(parts) >= 3 and '.'.join(parts[-2:]) in special_tlds:
            registered_domain = '.'.join(parts[-3:])
            subdomain = '.'.join(parts[:-3]) if len(parts) > 3 else ""
        elif len(parts) <= 2:
            registered_domain = domain
            subdomain = ""
        else:
            registered_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
        return subdomain, registered_domain
    except Exception:
        return "", ""

@lru_cache(maxsize=1024)
def is_gov_edu_domain(url):
    """Minimal rule-based check for clearly legitimate TLDs."""
    try:
        _, registered_domain = extract_domain_parts(url)
        return any(registered_domain.endswith(tld) for tld in ['.edu', '.gov', '.mil'])
    except Exception as e:
        logger.warning(f"Error checking TLD for {url}: {str(e)}")
        return False

def extract_url_features(url, parsed=None):
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
    
    has_common_subdomain = int(bool(subdomain and SUBDOMAIN_PATTERN.match(subdomain.lower())))
    has_ip = int(bool(IP_PATTERN.search(url)))
    has_suspicious_tld = int(bool(SUSPICIOUS_TLD_PATTERN.search(url)))
    has_at_symbol = int('@' in url)
    has_url_encoding = int(bool(URL_ENCODING_PATTERN.search(url)))
    has_uuid = int(bool(UUID_PATTERN.search(url)))
    has_https = int(parsed.scheme == 'https')
    
    brand_keywords = {'banking', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
                      'whatsapp', 'netflix', 'instagram', 'twitter', 'linkedin', 'coinbase',
                      'blockchain', 'bank', 'chase', 'wellsfargo', 'citi', 'hsbc', 'barclays'}
    brand_in_domain = any(brand in registered_domain.lower() for brand in brand_keywords)
    brand_only_in_path = (not brand_in_domain) and any(brand in url.lower() for brand in brand_keywords)
    
    has_high_risk_keywords = int(bool(HIGH_RISK_KEYWORDS_PATTERN.search(url)))
    has_brand_keywords = int(brand_only_in_path)
    
    path_depth = parsed.path.count('/')
    total_risk_count = (
        has_ip + has_suspicious_tld + has_at_symbol + has_url_encoding +
        (has_high_risk_keywords if not brand_in_domain else 0) +
        (has_brand_keywords if not brand_in_domain else 0)
    )
    if has_common_subdomain and registered_domain:
        total_risk_count = max(0, total_risk_count - 1)
    if has_uuid:
        total_risk_count = max(0, total_risk_count - 1)
    if has_https:
        total_risk_count = max(0, total_risk_count - 1)
    
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
        'has_url_encoding': has_url_encoding,
        'has_uuid': has_uuid,
        'has_https': has_https
    }

async def analyze_url(url):
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
        'details': {}
    }

    if not url:
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Invalid URL',
            'details': {'errors': ['Invalid or empty URL']}
        })
        result['processing_time'] = time.time() - start_time
        cache_result(url, result)
        return result

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
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] domain extraction error: {str(e)}")
        result['details']['errors'] = [f"Domain extraction error: {str(e)}"]
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback'
        })
        result['processing_time'] = time.time() - start_time
        cache_result(url, result)
        return result

    if is_gov_edu_domain(url):
        result.update({
            'is_phishing': False,
            'confidence': 0.05,
            'risk_level': 'Low',
            'analysis_method': 'TLD Check',
            'details': {
                **result['details'],
                'verification': {
                    'method': 'TLD Match',
                    'matched': True,
                    'notes': 'Domain has a trusted TLD (.edu, .gov, .mil).'
                }
            }
        })
        result['processing_time'] = time.time() - start_time
        cache_result(url, result)
        logger.info(f"Analysis [{analysis_id}] completed: LEGITIMATE (Trusted TLD)")
        return result

    try:
        # Fetch web content
        web_content = await fetch_web_content(url)
        web_features = extract_web_features({'url': url, **web_content})
        result['details']['web_features'] = web_features
        
        # Extract URL features
        url_features = extract_url_features(url, parsed)
        result['details']['url_features'] = url_features
        
        # Combine features
        feature_names = [
            'url_entropy', 'domain_entropy', 'has_ip', 'has_suspicious_tld',
            'has_high_risk_keywords', 'total_risk_count', 'url_length_norm',
            'subdomain_ratio', 'has_at_symbol', 'has_brand_keywords',
            'path_depth', 'has_url_encoding', 'has_uuid', 'has_https',
            'has_login_form', 'external_resources', 'has_meta_verification',
            'redirect_count', 'suspicious_redirect', 'content_length_norm',
            'status_code'
        ]
        features = {**url_features, **web_features}
        feature_array = np.array([[features.get(name, 0) for name in feature_names]], dtype=np.float32)
        
        if model is None:
            raise ValueError("Model not loaded")
        prediction = model.predict(feature_array)[0]
        prediction_proba = model.predict_proba(feature_array)[0][1]
        
        result['details']['ml_prediction'] = {
            'raw_prediction': int(prediction),
            'raw_confidence': float(prediction_proba)
        }

        # Calibrate confidence
        calibrated_confidence = prediction_proba
        calibration_factors = []
        
        if SUBDOMAIN_PATTERN.match(subdomain.lower()):
            calibrated_confidence *= 0.8
            calibration_factors.append(('valid_subdomain_format', 0.8))
        if parsed.scheme == 'https':
            calibrated_confidence *= 0.7
            calibration_factors.append(('has_https', 0.7))
        if UUID_PATTERN.search(url):
            calibrated_confidence *= 0.6
            calibration_factors.append(('uuid_in_path', 0.6))
        if web_features['has_meta_verification']:
            calibrated_confidence *= 0.6
            calibration_factors.append(('has_meta_verification', 0.6))
        if web_features['status_code'] == 0.2:  # 200 status
            calibrated_confidence *= 0.8
            calibration_factors.append(('successful_response', 0.8))
        if web_features['redirect_count'] == 0:
            calibrated_confidence *= 0.9
            calibration_factors.append(('no_redirects', 0.9))
        
        calibrated_prediction = int(calibrated_confidence > 0.5)
        result['details']['calibration'] = {
            'factors': calibration_factors,
            'original_confidence': float(prediction_proba),
            'calibrated_confidence': float(calibrated_confidence)
        }
        
        result.update({
            'is_phishing': bool(calibrated_prediction),
            'confidence': float(calibrated_confidence),
            'risk_level': 'High' if calibrated_confidence > 0.8 else 'Medium' if calibrated_confidence > 0.6 else 'Low',
            'analysis_method': 'Machine Learning Analysis'
        })
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] failed: {str(e)}")
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback',
            'details': {
                **result['details'],
                'errors': [f"Analysis error: {str(e)}"]
            }
        })

    result['processing_time'] = time.time() - start_time
    cache_result(url, result)
    logger.info(f"Analysis [{analysis_id}] completed in {result['processing_time']:.3f}s: " +
                f"{'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} " +
                f"(confidence: {result['confidence']:.2f})")
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
async def predict():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        url = request.json.get('url', '')
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        result = await analyze_url(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Request error: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred while processing your request'}), 500

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
        logger.info(f"User feedback received: {feedback_type} for analysis {analysis_id} - URL: {url}")
        return jsonify({'success': True, 'message': 'Thank you for your feedback!'})
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'error': 'Failed to process feedback'}), 500

@app.route('/api/check', methods=['POST'])
async def api_check():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        data = request.json
        url = data.get('url', '')
        api_key = data.get('api_key', '')
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        result = await analyze_url(url)
        api_response = {
            'url': result['url'],
            'is_phishing': result['is_phishing'],
            'confidence': result['confidence'],
            'risk_level': result['risk_level'],
            'analysis_id': result['analysis_id'],
            'timestamp': result['timestamp']
        }
        return jsonify(api_response)
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({'error': 'An error occurred during URL analysis'}), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react_app(path):
    if path != '' and not path.startswith('api/'):
        logger.info(f"Serving static file or fallback: /{path}")
        return send_from_directory(app.static_folder, path)
    if not path.startswith('api/'):
        logger.info(f"Serving index.html from: {os.path.join(app.static_folder, 'index.html')}")
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({'error': 'API route not found'}), 404

@app.errorhandler(404)
def page_not_found(e):
    if not request.path.startswith('/api/'):
        logger.info(f"404: Serving index.html from {os.path.join(app.static_folder, 'index.html')}")
        return send_from_directory(app.static_folder, 'index.html')
    return jsonify({'error': 'API endpoint not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'An internal server error occurred. Our team has been notified.'}), 500

if __name__ == '__main__':
    if model is None:
        logger.critical("Cannot start application - model failed to load")
        print("ERROR: Model failed to load. Check the logs for details.")
        exit(1)
    port = int(os.environ.get('PORT', 8080))
    app.run(debug=True, host='0.0.0.0', port=port)