import requests
from bs4 import BeautifulSoup
import re

class CSRFScanner:
    def __init__(self):
        self.csrf_token_names = [
            'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
            'csrf_token', 'xsrf_token', 'security_token', 'anti_csrf_token',
            'csrfmiddlewaretoken', 'csrftoken', '__RequestVerificationToken'
        ]
        
    def scan(self, url):
        """Scan a URL for CSRF vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Extract forms from the page
            forms = self._extract_forms(response.text)
            
            for form in forms:
                # Skip GET forms as they are not typically vulnerable to CSRF
                if form['method'] == 'get':
                    continue
                
                # Check if the form has a CSRF token
                has_csrf_token = False
                
                # Check for CSRF token in hidden inputs
                for input_field in form['inputs']:
                    if input_field['type'] == 'hidden' and any(token_name in input_field['name'].lower() for token_name in self.csrf_token_names):
                        has_csrf_token = True
                        break
                
                # Check for CSRF token in cookies
                if not has_csrf_token:
                    for cookie_name in response.cookies.keys():
                        if any(token_name in cookie_name.lower() for token_name in self.csrf_token_names):
                            # Check if the token is also in the form
                            for input_field in form['inputs']:
                                if input_field['value'] == response.cookies[cookie_name]:
                                    has_csrf_token = True
                                    break
                
                # Check for CSRF token in headers
                if not has_csrf_token:
                    for header_name, header_value in response.headers.items():
                        if any(token_name in header_name.lower() for token_name in self.csrf_token_names):
                            has_csrf_token = True
                            break
                
                # If no CSRF token is found, the form might be vulnerable
                if not has_csrf_token:
                    # Determine the form submission URL
                    action = form['action']
                    if not action:
                        action = url
                    elif not action.startswith(('http://', 'https://')):
                        # Relative URL
                        if action.startswith('/'):
                            base_url = '/'.join(url.split('/')[:3])  # http(s)://domain.com
                            action = base_url + action
                        else:
                            action = url.rsplit('/', 1)[0] + '/' + action
                    
                    vulnerabilities.append({
                        'type': 'CSRF',
                        'url': url,
                        'form_action': action,
                        'form_method': form['method'],
                        'evidence': 'No CSRF token found in form',
                        'severity': 'Medium',
                        'description': 'Cross-Site Request Forgery (CSRF) vulnerability detected. The application does not implement proper CSRF protection for this form.',
                        'remediation': 'Implement CSRF tokens for all state-changing operations. Use the SameSite cookie attribute and consider implementing additional protections like checking the Referer header.'
                    })
        
        except Exception as e:
            print(f"Error scanning {url} for CSRF: {str(e)}")
        
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