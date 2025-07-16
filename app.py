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

app = Flask(__name__)
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

# ---- MODEL PATH (use relative path for portability) ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.environ.get('MODEL_PATH', os.path.join(BASE_DIR, 'phishing_model_xgboost.pkl'))

try:
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None

URL_CACHE = {}
CACHE_TTL = 3600
MAX_CACHE_SIZE = 1000

REPUTABLE_DOMAINS = {
    'google.com', 'youtube.com', 'gmail.com', 'apple.com', 'icloud.com', 'microsoft.com', 
    'live.com', 'office.com', 'outlook.com', 'amazon.com', 'facebook.com', 'instagram.com',
    'whatsapp.com', 'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'adobe.com',
    'dropbox.com', 'netflix.com', 'spotify.com', 'yahoo.com', 'bing.com', 'twitch.tv',
    'reddit.com', 'ebay.com', 'paypal.com', 'zoom.us', 'teams.microsoft.com',
    'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'bard.google.com',
    'copilot.microsoft.com', 'huggingface.co', 'stability.ai', 'midjourney.com',
    'aws.amazon.com', 'azure.com', 'gcp.com', 'cloud.google.com', 'heroku.com',
    'digitalocean.com', 'cloudflare.com', 'akamai.com', 'fastly.com',
    'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com',
    'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
    'wordpress.com', 'shopify.com', 'salesforce.com', 'slack.com', 'canva.com',
    'notion.so', 'figma.com', 'airtable.com', 'zendesk.com', 'atlassian.com',
    'edu', 'gov', 'mil', 'ac.uk', 'gov.uk', 'edu.au', 'gov.au'
}
SECURITY_WEBSITES = {
    'phishtank.org', 'virustotal.com', 'haveibeenpwned.com', 'malwarebytes.com',
    'kaspersky.com', 'norton.com', 'mcafee.com', 'symantec.com', 'trendmicro.com',
    'f-secure.com', 'avast.com', 'avg.com', 'bitdefender.com', 'sophos.com',
    'checkpoint.com', 'fortinet.com', 'paloaltonetworks.com', 'fireeye.com',
    'shodan.io', 'censys.io', 'cvedetails.com', 'mitre.org', 'cisa.gov',
    'cert.org', 'sans.org', 'owasp.org', 'securityfocus.com', 'exploit-db.com',
    'kali.org', 'metasploit.com', 'wireshark.org', 'snort.org', 'hackthebox.eu',
    'tryhackme.com', 'threatpost.com', 'bleepingcomputer.com', 'krebsonsecurity.com',
    'securityweek.com', 'darkreading.com', 'schneier.com', 'hackread.com',
    'thehackernews.com', 'cyberscoop.com', 'cybersecurityventures.com'
}
REPUTABLE_DOMAINS.update(SECURITY_WEBSITES)

def sanitize_url(url):
    if not isinstance(url, str):
        return ""
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        http_match = re.search(r'https?://[^\s]+', url)
        if http_match:
            url = http_match.group(0)
        else:
            url = 'http://' + url
    merged_url_match = re.search(r'(https?://[^\s]+)', url)
    if merged_url_match and merged_url_match.group(0) != url:
        url = merged_url_match.group(0)
    try:
        url = unquote(url)
    except Exception:
        pass
    if not re.match(r'^https?://[\w\-\.]+\.[a-zA-Z]{2,}(/.*)?$', url):
        return ""
    if len(url) > 2000:
        return url[:2000]
    return url

def get_url_hash(url):
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def cache_result(url, result):
    if len(URL_CACHE) >= MAX_CACHE_SIZE:
        oldest_urls = sorted(URL_CACHE.items(), key=lambda x: x[1]['timestamp'])[:100]
        for url_hash, _ in oldest_urls:
            URL_CACHE.pop(url_hash, None)
    url_hash = get_url_hash(url)
    URL_CACHE[url_hash] = {
        'result': result,
        'timestamp': time.time()
    }

def get_cached_result(url):
    url_hash = get_url_hash(url)
    if url_hash in URL_CACHE:
        cached_item = URL_CACHE[url_hash]
        if time.time() - cached_item['timestamp'] < CACHE_TTL:
            return cached_item['result']
        URL_CACHE.pop(url_hash, None)
    return None

def extract_domain_parts(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if not domain:
        return "", ""
    parts = domain.split('.')
    special_tlds = {'co.uk', 'com.au', 'co.jp', 'co.nz', 'org.uk', 'gov.uk', 'ac.uk', 'edu.au'}
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

def has_suspicious_pattern(url):
    suspicious_patterns = [
        r'(?<!\.)paypal(?!\.com)',
        r'(?<!\.)apple(?!\.com)',
        r'(?<!\.)amazon(?!\.com)',
        r'\d{10,}',
        r'[a-zA-Z0-9]{30,}',
        r'(?<!\.)bank(?!\.[a-z]{2,3})'
    ]
    return any(re.search(pattern, url) for pattern in suspicious_patterns)

@lru_cache(maxsize=1024)
def is_legitimate_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return False
        subdomain, registered_domain = extract_domain_parts(url)
        if registered_domain in REPUTABLE_DOMAINS:
            return True
        for safe_tld in ['.edu', '.gov', '.mil']:
            if registered_domain.endswith(safe_tld):
                return True
        for reputable in REPUTABLE_DOMAINS:
            if registered_domain.endswith(f".{reputable}"):
                return True
        return False
    except Exception as e:
        logger.warning(f"Error checking domain legitimacy for {url}: {str(e)}")
        return False

@lru_cache(maxsize=1024)
def is_security_website(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    subdomain, registered_domain = extract_domain_parts(url)
    if registered_domain in SECURITY_WEBSITES:
        return True
    security_keywords = ['security', 'secure', 'antivirus', 'anti-virus', 'protection', 
                        'firewall', 'scan', 'threat', 'defense', 'cyber', 'phish']
    for keyword in security_keywords:
        if keyword in registered_domain and not has_suspicious_pattern(url):
            return True
    return False

def extract_url_features(url):
    def calculate_entropy(s):
        if not s or len(s) == 0:
            return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * np.log2(p) for p in prob if p > 0])
    def safe_urlparse(url):
        try:
            return urlparse(url)
        except:
            return urlparse('')
    parsed = safe_urlparse(url)
    domain = parsed.netloc
    subdomain, registered_domain = extract_domain_parts(url)
    url_length = len(url)
    domain_length = len(domain)
    url_length_norm = np.log1p(url_length)
    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)
    if subdomain:
        num_subdomains = max(1, subdomain.count('.') + 1)
    else:
        num_subdomains = 0
    subdomain_ratio = num_subdomains / (domain_length + 1) if domain_length > 0 else 0
    common_subdomains = {
        'www', 'mail', 'web', 'app', 'login', 'accounts', 'api', 'secure', 
        'dashboard', 'portal', 'admin', 'blog', 'shop', 'store', 'support',
        'm', 'mobile', 'help', 'docs', 'developer', 'developers', 'community'
    }
    has_common_subdomain = int(subdomain.lower() in common_subdomains)
    has_ip = int(bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url)))
    has_suspicious_tld = int(bool(re.search(r'\.(?:tk|ml|ga|cf|bit|pw|top|click|download|work|gq|xyz)(?:/|$)', url, re.IGNORECASE)))
    has_at_symbol = int('@' in url)
    has_url_encoding = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    high_risk_keywords = [
        'login', 'signin', 'account', 'verification', 'verify', 'secure', 'security',
        'update', 'urgent', 'suspended', 'limited', 'expired', 'confirm', 'activate',
        'password', 'credential', 'authenticate', 'wallet', 'recover', 'unlock'
    ]
    brand_keywords = [
        'banking', 'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 
        'whatsapp', 'netflix', 'instagram', 'twitter', 'linkedin', 'coinbase', 
        'blockchain', 'bank', 'chase', 'wellsfargo', 'citi', 'hsbc', 'barclays'
    ]
    brand_in_domain = any(brand.lower() in registered_domain.lower() for brand in brand_keywords)
    brand_only_in_path = (not brand_in_domain) and any(brand.lower() in url.lower() for brand in brand_keywords)
    has_high_risk_keywords = int(bool(re.search(r'\b(?:' + '|'.join(high_risk_keywords) + r')\b', url, re.IGNORECASE)))
    has_brand_keywords = int(brand_only_in_path)
    path = parsed.path
    path_depth = path.count('/')
    total_risk_count = (
        has_ip + has_suspicious_tld + has_at_symbol + has_url_encoding + 
        (has_high_risk_keywords if not brand_in_domain else 0) + 
        (has_brand_keywords if not brand_in_domain else 0)
    )
    if has_common_subdomain and registered_domain:
        total_risk_count = max(0, total_risk_count - 1)
    if is_security_website(url):
        total_risk_count = max(0, total_risk_count - 2)
    features = {
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
    return features

def analyze_url(url):
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
        'details': {},
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
            'scheme': parsed.scheme,
        }
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] domain extraction error: {str(e)}")
        result['details']['errors'] = [f"Domain extraction error: {str(e)}"]
    if is_legitimate_domain(url):
        result.update({
            'is_phishing': False,
            'confidence': 0.05,
            'risk_level': 'Low',
            'analysis_method': 'Verified Domain Check',
            'details': {
                **result.get('details', {}),
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
    if is_security_website(url):
        result.update({
            'is_phishing': False,
            'confidence': 0.05,
            'risk_level': 'Low',
            'analysis_method': 'Security Website Recognition',
            'details': {
                **result.get('details', {}),
                'verification': {
                    'method': 'Security Website Recognition',
                    'matched': True,
                    'notes': 'URL belongs to a known security or antivirus website.'
                }
            }
        })
        result['processing_time'] = time.time() - start_time
        cache_result(url, result)
        logger.info(f"Analysis [{analysis_id}] completed: LEGITIMATE (Security Website)")
        return result
    try:
        features = extract_url_features(url)
        result['details']['extracted_features'] = features
        feature_names = [
            'url_entropy', 'domain_entropy', 'has_ip', 'has_suspicious_tld',
            'has_high_risk_keywords', 'total_risk_count', 'url_length_norm',
            'subdomain_ratio', 'has_at_symbol', 'has_brand_keywords',
            'path_depth', 'has_url_encoding'
        ]
        df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        prediction = model.predict(df)[0]
        prediction_proba = model.predict_proba(df)[0][1]
        result['details']['ml_prediction'] = {
            'raw_prediction': int(prediction),
            'raw_confidence': float(prediction_proba),
        }
        calibrated_confidence = prediction_proba
        calibration_factors = []
        common_subdomains = {'www', 'web', 'app', 'mail', 'login', 'accounts'}
        subdomain = result['details']['domain']['subdomain']
        registered_domain = result['details']['domain']['registered_domain']
        if subdomain.lower() in common_subdomains:
            calibrated_confidence *= 0.7
            calibration_factors.append(('common_subdomain', 0.7))
        common_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co'}
        if any(registered_domain.endswith(tld) for tld in common_tlds):
            calibrated_confidence *= 0.9
            calibration_factors.append(('common_tld', 0.9))
        if features['total_risk_count'] <= 1:
            calibrated_confidence *= 0.8
            calibration_factors.append(('low_risk_count', 0.8))
        security_keywords = ['security', 'secure', 'antivirus', 'protection', 'cyber', 'phish']
        if any(keyword in registered_domain for keyword in security_keywords):
            calibrated_confidence *= 0.7
            calibration_factors.append(('security_keyword', 0.7))
        calibrated_prediction = int(calibrated_confidence > 0.5)
        result['details']['calibration'] = {
            'factors': calibration_factors,
            'original_confidence': float(prediction_proba),
            'calibrated_confidence': float(calibrated_confidence),
        }
        result.update({
            'is_phishing': bool(calibrated_prediction),
            'confidence': float(calibrated_confidence),
            'risk_level': 'High' if calibrated_confidence > 0.8 else 'Medium' if calibrated_confidence > 0.6 else 'Low',
            'analysis_method': 'Machine Learning Analysis',
        })
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] failed: {str(e)}")
        result.update({
            'is_phishing': True,
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback',
            'details': {
                **result.get('details', {}),
                'errors': [f"Analysis error: {str(e)}"]
            }
        })
    result['processing_time'] = time.time() - start_time
    cache_result(url, result)
    logger.info(f"Analysis [{analysis_id}] completed in {result['processing_time']:.3f}s: " + 
               f"{'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} " +
               f"(confidence: {result['confidence']:.2f})")
    return result

@app.route('/')
def home():
    return jsonify({'message': 'PhishGuard API is running.'})

@app.route('/test', methods=['GET'])
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
        result = analyze_url(url)
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
def api_check():
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    try:
        data = request.json
        url = data.get('url', '')
        api_key = data.get('api_key', '')
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        result = analyze_url(url)
        api_response = {
            'url': result['url'],
            'is_phishing': result['is_phishing'],
            'confidence': result['confidence'],
            'risk_level': result['risk_level'],
            'analysis_id': result['analysis_id'],
            'timestamp': result['timestamp'],
        }
        return jsonify(api_response)
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({'error': 'An error occurred during URL analysis'}), 500

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'error': 'An internal server error occurred. Our team has been notified.'}), 500

if __name__ == '__main__':
    if model is None:
        logger.critical("Cannot start application - model failed to load")
        print("ERROR: Model failed to load. Check the logs for details.")
        exit(1)
    app.run(debug=True, host='0.0.0.0', port=5000)