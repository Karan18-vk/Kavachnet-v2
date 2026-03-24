import re
from urllib.parse import urlparse

class URLFeatureExtractor:
    """
    Expert-level URL Feature Extractor for Cybersecurity Phishing Detection.
    Extracts 10+ structural and semantic features from a raw URL.
    """
    
    @staticmethod
    def extract(url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except:
            domain = ""
            path = ""

        features = {}
        
        # 1. Length-based features
        features['url_length'] = len(url)
        features['hostname_length'] = len(domain)
        
        # 2. Count-based structural features
        features['count_dots'] = url.count('.')
        features['count_hyphens'] = url.count('-')
        features['count_at'] = url.count('@')
        features['count_question'] = url.count('?')
        features['count_equal'] = url.count('=')
        features['count_slash'] = url.count('/')
        features['count_digits'] = sum(c.isdigit() for c in url)
        
        # 3. Security-based features
        features['is_https'] = 1 if url.startswith('https') else 0
        
        # 4. Keyword-based features (Cybersecurity Indicators)
        suspicious_keywords = ['login', 'verify', 'bank', 'update', 'secure', 'account', 'banking', 'paypal', 'signin']
        features['count_keywords'] = sum(1 for kw in suspicious_keywords if kw in url.lower())
        
        # 5. Domain features
        # Check if domain is an IP address
        features['is_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
        
        return features

    @staticmethod
    def get_feature_names():
        return [
            'url_length', 'hostname_length', 'count_dots', 'count_hyphens', 
            'count_at', 'count_question', 'count_equal', 'count_slash', 
            'count_digits', 'is_https', 'count_keywords', 'is_ip'
        ]
