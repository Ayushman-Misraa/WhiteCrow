import requests
from bs4 import BeautifulSoup
import re

class BrokenAuthScanner:
    def __init__(self):
        self.common_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "administrator", "password": "administrator"},
            {"username": "root", "password": "root"},
            {"username": "user", "password": "user"},
            {"username": "guest", "password": "guest"}
        ]
        
    def scan(self, url):
        """Scan a URL for broken authentication vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Extract forms from the page
            forms = self._extract_forms(response.text)
            
            # Look for login forms
            login_forms = []
            for form in forms:
                if self._is_login_form(form):
                    login_forms.append(form)
            
            if not login_forms:
                return vulnerabilities
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header'
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(message)
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'url': url,
                    'evidence': ', '.join(missing_headers),
                    'severity': 'Medium',
                    'description': 'The application is missing important security headers that help protect against various attacks.',
                    'remediation': 'Implement the missing security headers to enhance the security of the application.'
                })
            
            # Check for insecure communication
            if url.startswith('http://'):
                vulnerabilities.append({
                    'type': 'Insecure Communication',
                    'url': url,
                    'evidence': 'Login form submitted over HTTP',
                    'severity': 'High',
                    'description': 'The login form is served over HTTP, which can lead to credentials being intercepted.',
                    'remediation': 'Serve the login form over HTTPS and implement HSTS.'
                })
            
            # Check for weak password policies
            # This is a basic check and might need to be enhanced
            password_fields = []
            for form in login_forms:
                for input_field in form['inputs']:
                    if input_field['type'] == 'password':
                        password_fields.append(input_field)
            
            if password_fields:
                # Check if there's any client-side password validation
                if not self._has_password_validation(response.text):
                    vulnerabilities.append({
                        'type': 'Weak Password Policy',
                        'url': url,
                        'evidence': 'No client-side password validation found',
                        'severity': 'Medium',
                        'description': 'The application does not appear to enforce a strong password policy.',
                        'remediation': 'Implement a strong password policy that requires a minimum length, complexity, and prevents the use of common passwords.'
                    })
            
            # Check for account enumeration
            # This would require actual testing with different usernames
            # For now, we'll just check if the login form has a clear error message
            
            # Check for brute force protection
            # This would require multiple login attempts
            # For now, we'll just check if there's any indication of rate limiting or CAPTCHA
            if not self._has_brute_force_protection(response.text):
                vulnerabilities.append({
                    'type': 'Lack of Brute Force Protection',
                    'url': url,
                    'evidence': 'No CAPTCHA or rate limiting detected',
                    'severity': 'Medium',
                    'description': 'The application does not appear to have protection against brute force attacks.',
                    'remediation': 'Implement rate limiting, account lockout, or CAPTCHA to prevent brute force attacks.'
                })
        
        except Exception as e:
            print(f"Error scanning {url} for broken authentication: {str(e)}")
        
        return vulnerabilities
    
    def _extract_forms(self, html):
        """Extract forms from HTML content"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {}
            form_details['action'] = form.get('action', '')
            form_details['method'] = form.get('method', 'get').lower()
            form_details['inputs'] = []
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')
                
                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            forms.append(form_details)
        
        return forms
    
    def _is_login_form(self, form):
        """Check if a form is a login form"""
        # Check if the form has a password field
        has_password = False
        for input_field in form['inputs']:
            if input_field['type'] == 'password':
                has_password = True
                break
        
        if not has_password:
            return False
        
        # Check if the form has a username/email field
        has_username = False
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'email'] and any(name in input_field['name'].lower() for name in ['user', 'email', 'login', 'name']):
                has_username = True
                break
        
        return has_username and has_password
    
    def _has_password_validation(self, html):
        """Check if there's any client-side password validation"""
        # Look for common password validation patterns in JavaScript
        patterns = [
            r'password.{1,50}length',
            r'validatePassword',
            r'checkPassword',
            r'password.{1,50}strength',
            r'password.{1,50}match',
            r'password.{1,50}regex'
        ]
        
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
    
    def _has_brute_force_protection(self, html):
        """Check if there's any indication of brute force protection"""
        # Look for CAPTCHA
        captcha_patterns = [
            r'captcha',
            r'recaptcha',
            r'g-recaptcha',
            r'hcaptcha'
        ]
        
        for pattern in captcha_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        # Look for rate limiting or account lockout mentions
        rate_limit_patterns = [
            r'too many attempts',
            r'account locked',
            r'try again later',
            r'rate limit',
            r'wait before trying'
        ]
        
        for pattern in rate_limit_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False