import numpy as np
import pandas as pd
import joblib
from flask import Flask, request, render_template, jsonify, session
from urllib.parse import urlparse, unquote
import re
import os
import time
import logging
import hashlib
from datetime import datetime, timedelta
from functools import lru_cache
import uuid
from flask_cors import CORS  # Added import for CORS

# ===================== APPLICATION SETUP =====================
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes to work with React frontend

app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
# Modified for development - change back to True in production
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024  # 2KB max request size

# ===================== LOGGING CONFIGURATION =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('phishing_detector')

# ===================== MODEL LOADING =====================
try:
    MODEL_PATH = os.environ.get('MODEL_PATH', 'C:/Users/user/Desktop/ML/phishing test/phishing_model_xgboost.pkl')
    model = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded successfully from {MODEL_PATH}")
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    model = None

# ===================== RESULT CACHING =====================
# Cache for storing recent URL analysis results (URL hash -> result)
URL_CACHE = {}
CACHE_TTL = 3600  # Cache time-to-live in seconds (1 hour)
MAX_CACHE_SIZE = 1000  # Maximum number of cached results

# ===================== DOMAIN VERIFICATION SYSTEM =====================
# Top-level tech & service domains that should never be flagged as phishing
REPUTABLE_DOMAINS = {
    # Major tech companies
    'google.com', 'youtube.com', 'gmail.com', 'apple.com', 'icloud.com', 'microsoft.com', 
    'live.com', 'office.com', 'outlook.com', 'amazon.com', 'facebook.com', 'instagram.com',
    'whatsapp.com', 'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'adobe.com',
    'dropbox.com', 'netflix.com', 'spotify.com', 'yahoo.com', 'bing.com', 'twitch.tv',
    'reddit.com', 'ebay.com', 'paypal.com', 'zoom.us', 'teams.microsoft.com',
    
    # AI platforms
    'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'bard.google.com',
    'copilot.microsoft.com', 'huggingface.co', 'stability.ai', 'midjourney.com',
    
    # Major cloud providers
    'aws.amazon.com', 'azure.com', 'gcp.com', 'cloud.google.com', 'heroku.com',
    'digitalocean.com', 'cloudflare.com', 'akamai.com', 'fastly.com',
    
    # Payment services
    'visa.com', 'mastercard.com', 'americanexpress.com', 'discover.com',
    'stripe.com', 'square.com', 'venmo.com', 'cashapp.com',
    
    # Other major services
    'wordpress.com', 'shopify.com', 'salesforce.com', 'slack.com', 'canva.com',
    'notion.so', 'figma.com', 'airtable.com', 'zendesk.com', 'atlassian.com',
    
    # Add education and government domains generically
    'edu', 'gov', 'mil', 'ac.uk', 'gov.uk', 'edu.au', 'gov.au'
}

# Security and cybersecurity websites
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

# Add security websites to reputable domains
REPUTABLE_DOMAINS.update(SECURITY_WEBSITES)

# ===================== UTILITY FUNCTIONS =====================
def sanitize_url(url):
    """Sanitize and normalize the URL input with enhanced error handling"""
    # Ensure URL is a string
    if not isinstance(url, str):
        return ""
    
    # Trim whitespace and normalize
    url = url.strip().lower()
    
    # Fix common URL formatting errors
    
    # Case 1: No protocol, domain starts immediately (example.com)
    if not url.startswith(('http://', 'https://')):
        # Check if there's text before a valid http/https URL
        http_match = re.search(r'https?://[^\s]+', url)
        if http_match:
            url = http_match.group(0)  # Extract the URL part
        else:
            url = 'http://' + url  # Add protocol
    
    # Case 2: Text merged with URL (usernamehttp://example.com)
    merged_url_match = re.search(r'(https?://[^\s]+)', url)
    if merged_url_match and merged_url_match.group(0) != url:
        url = merged_url_match.group(0)  # Extract just the URL part
    
    # Decode percent-encoded characters
    try:
        url = unquote(url)
    except Exception:
        pass
    
    # Basic validation check
    if not re.match(r'^https?://[\w\-\.]+\.[a-zA-Z]{2,}(/.*)?$', url):
        return ""
    
    # Size limit for extremely long URLs
    if len(url) > 2000:
        return url[:2000]
    
    return url

def get_url_hash(url):
    """Create a hash for the URL for caching purposes"""
    return hashlib.md5(url.encode('utf-8')).hexdigest()

def cache_result(url, result):
    """Store URL analysis result in cache with timestamp"""
    # Clean cache if it's getting too large
    if len(URL_CACHE) >= MAX_CACHE_SIZE:
        # Remove oldest entries
        oldest_urls = sorted(URL_CACHE.items(), key=lambda x: x[1]['timestamp'])[:100]
        for url_hash, _ in oldest_urls:
            URL_CACHE.pop(url_hash, None)
    
    url_hash = get_url_hash(url)
    URL_CACHE[url_hash] = {
        'result': result,
        'timestamp': time.time()
    }

def get_cached_result(url):
    """Get cached result if available and not expired"""
    url_hash = get_url_hash(url)
    if url_hash in URL_CACHE:
        cached_item = URL_CACHE[url_hash]
        
        # Check if cache is still valid
        if time.time() - cached_item['timestamp'] < CACHE_TTL:
            return cached_item['result']
        
        # Remove expired item
        URL_CACHE.pop(url_hash, None)
    
    return None

def extract_domain_parts(url):
    """Extract domain parts with enhanced TLD handling"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    if not domain:
        return "", ""
    
    # Try to identify the registered domain and subdomain
    parts = domain.split('.')
    
    # Handle special cases like co.uk, com.au
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
    """Check for typical phishing patterns"""
    suspicious_patterns = [
        r'(?<!\.)paypal(?!\.com)',  # paypal not followed by .com
        r'(?<!\.)apple(?!\.com)',    # apple not followed by .com
        r'(?<!\.)amazon(?!\.com)',   # amazon not followed by .com
        r'\d{10,}',                  # very long number sequences
        r'[a-zA-Z0-9]{30,}',         # very long alphanumeric sequences
        r'(?<!\.)bank(?!\.[a-z]{2,3})'  # bank not followed by proper TLD
    ]
    
    return any(re.search(pattern, url) for pattern in suspicious_patterns)

@lru_cache(maxsize=1024)
def is_legitimate_domain(url):
    """Enhanced check for legitimate domains with caching"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if not domain:
            return False
        
        # Extract the base domain
        subdomain, registered_domain = extract_domain_parts(url)
        
        # Direct match in reputable domains
        if registered_domain in REPUTABLE_DOMAINS:
            return True
            
        # Check for educational and government domains by TLD
        for safe_tld in ['.edu', '.gov', '.mil']:
            if registered_domain.endswith(safe_tld):
                return True
        
        # Enhanced checks for subdomains of reputable domains
        for reputable in REPUTABLE_DOMAINS:
            if registered_domain.endswith(f".{reputable}"):
                return True
        
        return False
    except Exception as e:
        logger.warning(f"Error checking domain legitimacy for {url}: {str(e)}")
        return False

@lru_cache(maxsize=1024)
def is_security_website(url):
    """Check if the URL belongs to a known security/antivirus website"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # Extract base domain
    subdomain, registered_domain = extract_domain_parts(url)
    
    # Check against our security website list
    if registered_domain in SECURITY_WEBSITES:
        return True
    
    # Check for security-related TLDs and keywords
    security_keywords = ['security', 'secure', 'antivirus', 'anti-virus', 'protection', 
                        'firewall', 'scan', 'threat', 'defense', 'cyber', 'phish']
                        
    # Lower the risk for domains with security-related terms when they're legitimate looking
    for keyword in security_keywords:
        if keyword in registered_domain and not has_suspicious_pattern(url):
            return True
    
    return False

def extract_url_features(url):
    """Extract features from a single URL string with improved heuristics"""
    
    def calculate_entropy(s):
        """Calculate Shannon entropy of a string"""
        if not s or len(s) == 0:
            return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum([p * np.log2(p) for p in prob if p > 0])
    
    def safe_urlparse(url):
        """Safely parse URL without raising exceptions"""
        try:
            return urlparse(url)
        except:
            return urlparse('')
    
    # Parse URL
    parsed = safe_urlparse(url)
    domain = parsed.netloc
    
    # Extract domain parts
    subdomain, registered_domain = extract_domain_parts(url)
    
    # Key length features
    url_length = len(url)
    domain_length = len(domain)
    url_length_norm = np.log1p(url_length)
    
    # Entropy features
    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(domain)
    
    # Domain structure analysis
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_digits = sum(c.isdigit() for c in url)
    
    # Subdomains - improved calculation
    if subdomain:
        num_subdomains = max(1, subdomain.count('.') + 1)
    else:
        num_subdomains = 0
    subdomain_ratio = num_subdomains / (domain_length + 1) if domain_length > 0 else 0
    
    # Check for common legitimate subdomain patterns
    common_subdomains = {
        'www', 'mail', 'web', 'app', 'login', 'accounts', 'api', 'secure', 
        'dashboard', 'portal', 'admin', 'blog', 'shop', 'store', 'support',
        'm', 'mobile', 'help', 'docs', 'developer', 'developers', 'community'
    }
    has_common_subdomain = int(subdomain.lower() in common_subdomains)
    
    # Security indicators
    has_ip = int(bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url)))
    has_suspicious_tld = int(bool(re.search(r'\.(?:tk|ml|ga|cf|bit|pw|top|click|download|work|gq|xyz)(?:/|$)', url, re.IGNORECASE)))
    has_at_symbol = int('@' in url)
    has_url_encoding = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    
    # Keywords analysis with context
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
    
    # Check if brand name is in domain (legitimate) vs just in path (suspicious)
    brand_in_domain = any(brand.lower() in registered_domain.lower() for brand in brand_keywords)
    brand_only_in_path = (not brand_in_domain) and any(brand.lower() in url.lower() for brand in brand_keywords)
    
    # Original feature calculation
    has_high_risk_keywords = int(bool(re.search(r'\b(?:' + '|'.join(high_risk_keywords) + r')\b', url, re.IGNORECASE)))
    
    # Brand keyword detection with context
    has_brand_keywords = int(brand_only_in_path)  # Only count as suspicious if brand appears outside domain
    
    # Path analysis
    path = parsed.path
    path_depth = path.count('/')
    
    # Security risk calculation with context
    total_risk_count = (
        has_ip + has_suspicious_tld + has_at_symbol + has_url_encoding + 
        (has_high_risk_keywords if not brand_in_domain else 0) +  # Don't count keywords against legitimate domains
        (has_brand_keywords if not brand_in_domain else 0)  # Same for brand keywords
    )
    
    # Adjust risk for common subdomain patterns
    if has_common_subdomain and registered_domain:
        # Reduce risk score for common legitimate subdomains
        total_risk_count = max(0, total_risk_count - 1)
        
    # Reduce risk for known security websites
    if is_security_website(url):
        total_risk_count = max(0, total_risk_count - 2)
    
    # Create a dictionary with the 12 specific features in the expected order
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
    """Complete URL analysis with cached results and detailed reporting"""
    # Check cache first
    cached_result = get_cached_result(url)
    if cached_result:
        logger.info(f"Cache hit for URL: {url}")
        return cached_result
    
    # Start timing the analysis
    start_time = time.time()
    
    # Generate a unique analysis ID
    analysis_id = str(uuid.uuid4())[:8]
    logger.info(f"Analysis [{analysis_id}] started for URL: {url}")
    
    # Enhanced result dictionary
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
    
    # Extract domain information
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
    
    # STEP 1: First check if this is a known legitimate domain
    if is_legitimate_domain(url):
        result.update({
            'is_phishing': False,
            'confidence': 0.05,  # Very low phishing probability
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
        
        # Record processing time
        result['processing_time'] = time.time() - start_time
        
        # Cache the result
        cache_result(url, result)
        
        logger.info(f"Analysis [{analysis_id}] completed: LEGITIMATE (Verified Domain)")
        return result
        
    # STEP 1.5: Check if it's a security website
    if is_security_website(url):
        result.update({
            'is_phishing': False,
            'confidence': 0.05,  # Very low phishing probability
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
        
        # Record processing time
        result['processing_time'] = time.time() - start_time
        
        # Cache the result
        cache_result(url, result)
        
        logger.info(f"Analysis [{analysis_id}] completed: LEGITIMATE (Security Website)")
        return result
    
    # STEP 2: For other domains, use the ML model with enhanced feature extraction
    try:
        # Extract features
        features = extract_url_features(url)
        
        # Store extracted features in result
        result['details']['extracted_features'] = features
        
        # Convert to DataFrame with feature order matching training data
        feature_names = [
            'url_entropy', 'domain_entropy', 'has_ip', 'has_suspicious_tld',
            'has_high_risk_keywords', 'total_risk_count', 'url_length_norm',
            'subdomain_ratio', 'has_at_symbol', 'has_brand_keywords',
            'path_depth', 'has_url_encoding'
        ]
        
        df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        
        # STEP 3: Get raw prediction
        prediction = model.predict(df)[0]
        prediction_proba = model.predict_proba(df)[0][1]
        
        # Store raw model prediction
        result['details']['ml_prediction'] = {
            'raw_prediction': int(prediction),
            'raw_confidence': float(prediction_proba),
        }
        
        # STEP 4: Enhanced post-prediction calibration
        calibrated_confidence = prediction_proba
        calibration_factors = []
        
        # Lower confidence for domains with common subdomains
        common_subdomains = {'www', 'web', 'app', 'mail', 'login', 'accounts'}
        if subdomain.lower() in common_subdomains:
            calibrated_confidence *= 0.7
            calibration_factors.append(('common_subdomain', 0.7))
                
        # Lower confidence for long-established TLDs
        common_tlds = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co'}
        if any(registered_domain.endswith(tld) for tld in common_tlds):
            calibrated_confidence *= 0.9
            calibration_factors.append(('common_tld', 0.9))
        
        # Lower confidence for URLs with minimal risk factors
        if features['total_risk_count'] <= 1:
            calibrated_confidence *= 0.8
            calibration_factors.append(('low_risk_count', 0.8))
            
        # Lower confidence for security-related websites
        security_keywords = ['security', 'secure', 'antivirus', 'protection', 'cyber', 'phish']
        if any(keyword in registered_domain for keyword in security_keywords):
            calibrated_confidence *= 0.7
            calibration_factors.append(('security_keyword', 0.7))
            
        # Recalculate binary prediction based on adjusted probability
        calibrated_prediction = int(calibrated_confidence > 0.5)
        
        # Store calibration details
        result['details']['calibration'] = {
            'factors': calibration_factors,
            'original_confidence': float(prediction_proba),
            'calibrated_confidence': float(calibrated_confidence),
        }
        
        # Update result with final assessment
        result.update({
            'is_phishing': bool(calibrated_prediction),
            'confidence': float(calibrated_confidence),
            'risk_level': 'High' if calibrated_confidence > 0.8 else 'Medium' if calibrated_confidence > 0.6 else 'Low',
            'analysis_method': 'Machine Learning Analysis',
        })
        
    except Exception as e:
        logger.error(f"Analysis [{analysis_id}] failed: {str(e)}")
        result.update({
            'is_phishing': True,  # Default to cautious approach on error
            'confidence': 0.7,
            'risk_level': 'Medium',
            'analysis_method': 'Error Fallback',
            'details': {
                **result.get('details', {}),
                'errors': [f"Analysis error: {str(e)}"]
            }
        })
    
    # Record processing time
    result['processing_time'] = time.time() - start_time
    
    # Cache the result
    cache_result(url, result)
    
    logger.info(f"Analysis [{analysis_id}] completed in {result['processing_time']:.3f}s: " + 
               f"{'PHISHING' if result['is_phishing'] else 'LEGITIMATE'} " +
               f"(confidence: {result['confidence']:.2f})")
    
    return result

# ===================== FLASK ROUTES =====================
# Added test endpoint for React connectivity testing
@app.route('/test', methods=['GET'])
def test_api():
    """Simple endpoint to test if the API is working"""
    return jsonify({
        'status': 'success',
        'message': 'PhishGuard API is working!',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/')
def home():
    """Render the home page"""
    # Generate a unique session ID if not present
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
        session['history'] = []
    
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Process a URL and return phishing analysis results"""
    if request.method == 'POST':
        try:
            # Get URL from request
            if request.is_json:
                url = request.json.get('url', '')
            else:
                url = request.form.get('url', '')
            
            # Validate and sanitize URL
            url = sanitize_url(url)
            if not url:
                return jsonify({'error': 'Invalid or empty URL provided'}), 400
            
            # Track analysis in session history (up to 10 entries)
            if 'history' in session:
                history = session['history']
                # Check if URL is already in history
                if url not in [entry['url'] for entry in history]:
                    # Add to history, limited to 10 entries
                    history.insert(0, {'url': url, 'timestamp': datetime.now().isoformat()})
                    if len(history) > 10:
                        history.pop()
                    session['history'] = history
            
            # Perform the analysis
            result = analyze_url(url)
            
            # Return result based on request type
            if request.is_json:
                return jsonify(result)
            else:
                # Add analysis ID to session for potential feedback
                session['last_analysis_id'] = result['analysis_id']
                return render_template('result.html', result=result)
                
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            if request.is_json:
                return jsonify({'error': 'An unexpected error occurred while processing your request'}), 500
            else:
                return render_template('error.html', error='An unexpected error occurred while processing your request')

@app.route('/feedback', methods=['POST'])
def feedback():
    """Handle user feedback for false positives or false negatives"""
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    
    try:
        data = request.json
        analysis_id = data.get('analysis_id')
        url = data.get('url')
        feedback_type = data.get('feedback_type')  # 'false_positive' or 'false_negative'
        
        if not all([analysis_id, url, feedback_type]):
            return jsonify({'error': 'Missing required feedback data'}), 400
        
        if feedback_type not in ['false_positive', 'false_negative']:
            return jsonify({'error': 'Invalid feedback type'}), 400
        
        # Log the feedback for future model improvement
        logger.info(f"User feedback received: {feedback_type} for analysis {analysis_id} - URL: {url}")
        
        # Could store feedback in a database here for future model retraining
        
        return jsonify({'success': True, 'message': 'Thank you for your feedback!'})
    
    except Exception as e:
        logger.error(f"Feedback error: {str(e)}")
        return jsonify({'error': 'Failed to process feedback'}), 500

@app.route('/api/check', methods=['POST'])
def api_check():
    """API endpoint for programmatic URL checking"""
    if not request.is_json:
        return jsonify({'error': 'JSON request required'}), 400
    
    try:
        data = request.json
        url = data.get('url', '')
        api_key = data.get('api_key', '')
        
        # Validate API key (implement your own validation logic)
        # if not validate_api_key(api_key):
        #     return jsonify({'error': 'Invalid or missing API key'}), 401
        
        # Sanitize and validate URL
        url = sanitize_url(url)
        if not url:
            return jsonify({'error': 'Invalid or empty URL provided'}), 400
        
        # Perform the analysis
        result = analyze_url(url)
        
        # Return a simplified API response
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

@app.route('/history')
def history():
    """Display the user's URL checking history"""
    history = session.get('history', [])
    return render_template('history.html', history=history)

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle internal server errors"""
    return render_template('error.html', 
                          error='An internal server error occurred. Our team has been notified.'), 500

# ===================== APPLICATION STARTUP =====================
if __name__ == '__main__':
    # Check if model is loaded correctly
    if model is None:
        logger.critical("Cannot start application - model failed to load")
        print("ERROR: Model failed to load. Check the logs for details.")
        exit(1)
    
    # Development server configuration
    app.run(debug=True, host='0.0.0.0', port=5000)