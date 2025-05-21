import requests
import re
from urllib.parse import urlparse

class SensitiveDataScanner:
    def __init__(self):
        # Patterns for sensitive data
        self.patterns = {
            'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
            'Social Security Number': r'\b\d{3}-\d{2}-\d{4}\b',
            'Email Address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'API Key': r'\b[A-Za-z0-9]{32,45}\b',
            'AWS Access Key': r'\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
            'AWS Secret Key': r'\b[A-Za-z0-9/+]{40}\b',
            'Google API Key': r'\bAIza[0-9A-Za-z-_]{35}\b',
            'Private Key': r'-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----',
            'Password in URL': r'(?:pass|pwd|passwd|password)=([^&]+)',
            'Internal IP Address': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b'
        }
        
    def scan(self, url):
        """Scan a URL for sensitive data exposure"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Check for HTTPS
            if url.startswith('http://'):
                vulnerabilities.append({
                    'type': 'Insecure Communication',
                    'url': url,
                    'evidence': 'Page served over HTTP',
                    'severity': 'High',
                    'description': 'The page is served over HTTP, which can lead to sensitive data being intercepted.',
                    'remediation': 'Serve all pages over HTTPS and implement HSTS.'
                })
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'Referrer-Policy': 'Referrer-Policy'
            }
            
            missing_headers = []
            for header, name in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(name)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'url': url,
                    'evidence': f"Missing headers: {', '.join(missing_headers)}",
                    'severity': 'Medium',
                    'description': 'The application is missing important security headers that help protect sensitive data.',
                    'remediation': 'Implement the missing security headers to enhance the security of the application.'
                })
            
            # Check for sensitive data in the response
            for data_type, pattern in self.patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    # Limit the number of matches to show
                    evidence = matches[:3]
                    vulnerabilities.append({
                        'type': 'Sensitive Data Exposure',
                        'url': url,
                        'data_type': data_type,
                        'evidence': f"Found {len(matches)} instances of {data_type}",
                        'examples': evidence,
                        'severity': 'High',
                        'description': f'The application exposes sensitive {data_type} data in the response.',
                        'remediation': 'Ensure sensitive data is properly masked or not included in responses. Use HTTPS for all communications.'
                    })
            
            # Check for caching directives
            if 'Cache-Control' not in response.headers and 'Pragma' not in response.headers:
                vulnerabilities.append({
                    'type': 'Missing Cache Control',
                    'url': url,
                    'evidence': 'No Cache-Control or Pragma headers',
                    'severity': 'Medium',
                    'description': 'The application does not set cache control headers, which could lead to sensitive data being cached.',
                    'remediation': 'Set appropriate Cache-Control and Pragma headers to prevent caching of sensitive data.'
                })
            
            # Check for cookies without secure flag
            for cookie in response.cookies:
                if not cookie.secure:
                    vulnerabilities.append({
                        'type': 'Insecure Cookie',
                        'url': url,
                        'evidence': f"Cookie '{cookie.name}' without Secure flag",
                        'severity': 'Medium',
                        'description': 'The application sets cookies without the Secure flag, which could lead to cookies being sent over HTTP.',
                        'remediation': 'Set the Secure flag on all cookies to ensure they are only sent over HTTPS.'
                    })
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    vulnerabilities.append({
                        'type': 'Insecure Cookie',
                        'url': url,
                        'evidence': f"Cookie '{cookie.name}' without HttpOnly flag",
                        'severity': 'Medium',
                        'description': 'The application sets cookies without the HttpOnly flag, which could lead to cookies being accessed by JavaScript.',
                        'remediation': 'Set the HttpOnly flag on all cookies that do not need to be accessed by JavaScript.'
                    })
        
        except Exception as e:
            print(f"Error scanning {url} for sensitive data: {str(e)}")
        
        return vulnerabilities