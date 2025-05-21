import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import re
import base64
import json

class InsecureDeserializationScanner:
    def __init__(self):
        self.serialization_patterns = {
            'PHP': [
                r'O:[0-9]+:"[^"]+":[0-9]+:{',  # PHP serialized object
                r'a:[0-9]+:{',  # PHP serialized array
                r's:[0-9]+:"',  # PHP serialized string
            ],
            'Java': [
                r'rO0AB',  # Base64 encoded Java serialized object
                r'H4sIAAAA',  # Base64 encoded Java serialized object (GZIP)
                r'AC\+ED',  # Base64 encoded Java serialized object
            ],
            'Python': [
                r'gAJ',  # Base64 encoded Python pickle
                r'gAR',  # Base64 encoded Python pickle
                r'KlQ',  # Base64 encoded Python pickle
                r'gASV',  # Base64 encoded Python pickle
            ],
            'Ruby': [
                r'BAh',  # Base64 encoded Ruby Marshal
                r'BAt',  # Base64 encoded Ruby Marshal
                r'BAM',  # Base64 encoded Ruby Marshal
            ],
            '.NET': [
                r'AAEAAAD',  # Base64 encoded .NET serialized object
                r'AQQAAA',  # Base64 encoded .NET serialized object
            ]
        }
        
        self.payloads = {
            'PHP': [
                'O:8:"stdClass":0:{}',  # Harmless PHP object
                'a:1:{i:0;s:4:"test";}',  # Harmless PHP array
            ],
            'Java': [
                base64.b64encode(b'test').decode('utf-8'),  # Not a real payload, just for testing
            ],
            'Python': [
                base64.b64encode(b'test').decode('utf-8'),  # Not a real payload, just for testing
            ],
            'Ruby': [
                base64.b64encode(b'test').decode('utf-8'),  # Not a real payload, just for testing
            ],
            '.NET': [
                base64.b64encode(b'test').decode('utf-8'),  # Not a real payload, just for testing
            ]
        }
        
    def scan(self, url):
        """Scan a URL for insecure deserialization vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Check cookies for serialized data
            for cookie_name, cookie_value in response.cookies.items():
                for language, patterns in self.serialization_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, cookie_value):
                            vulnerabilities.append({
                                'type': 'Potential Insecure Deserialization',
                                'url': url,
                                'location': f'Cookie: {cookie_name}',
                                'evidence': f'Serialized {language} data detected in cookie',
                                'severity': 'High',
                                'description': f'The application appears to be using serialized {language} objects in cookies, which could be vulnerable to insecure deserialization attacks.',
                                'remediation': 'Avoid using serialized objects in cookies. If necessary, implement integrity checks and use a secure serialization format like JSON with a digital signature.'
                            })
            
            # Check for serialized data in the response
            for language, patterns in self.serialization_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.text):
                        vulnerabilities.append({
                            'type': 'Potential Insecure Deserialization',
                            'url': url,
                            'location': 'Response body',
                            'evidence': f'Serialized {language} data detected in response',
                            'severity': 'Medium',
                            'description': f'The application appears to be using serialized {language} objects in the response, which could indicate the use of serialization for data storage or transfer.',
                            'remediation': 'Avoid using serialized objects for data storage or transfer. Use a secure data format like JSON with proper validation.'
                        })
            
            # Check URL parameters for serialized data
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            for param, values in params.items():
                for value in values:
                    for language, patterns in self.serialization_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, value):
                                vulnerabilities.append({
                                    'type': 'Potential Insecure Deserialization',
                                    'url': url,
                                    'location': f'URL parameter: {param}',
                                    'evidence': f'Serialized {language} data detected in URL parameter',
                                    'severity': 'High',
                                    'description': f'The application appears to be using serialized {language} objects in URL parameters, which could be vulnerable to insecure deserialization attacks.',
                                    'remediation': 'Avoid using serialized objects in URL parameters. If necessary, implement integrity checks and use a secure serialization format like JSON with a digital signature.'
                                })
            
            # Test for insecure deserialization by sending serialized data
            for param, values in params.items():
                for language, payloads in self.payloads.items():
                    for payload in payloads:
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
                        
                        try:
                            # Send the request
                            payload_response = requests.get(new_url, timeout=10)
                            
                            # Check for error messages that might indicate deserialization
                            error_patterns = [
                                r'unserialize\(',
                                r'deserialize',
                                r'Serializ',
                                r'Marshal\.load',
                                r'pickle\.load',
                                r'ObjectInputStream',
                                r'readObject',
                                r'JsonConvert\.DeserializeObject',
                                r'BinaryFormatter',
                                r'SoapFormatter',
                                r'TypeNameHandling',
                                r'JavaScriptSerializer',
                                r'YAML\.load',
                                r'unsafe_load'
                            ]
                            
                            for error_pattern in error_patterns:
                                if re.search(error_pattern, payload_response.text, re.IGNORECASE):
                                    vulnerabilities.append({
                                        'type': 'Potential Insecure Deserialization',
                                        'url': url,
                                        'location': f'URL parameter: {param}',
                                        'evidence': f'Error message containing "{error_pattern}" detected',
                                        'severity': 'High',
                                        'description': f'The application appears to be deserializing user input, which could be vulnerable to insecure deserialization attacks.',
                                        'remediation': 'Avoid deserializing user input. If necessary, implement integrity checks and use a secure deserialization mechanism with proper validation.'
                                    })
                                    break
                        
                        except Exception as e:
                            print(f"Error testing {new_url} for insecure deserialization: {str(e)}")
            
            # Check for JSON-based deserialization vulnerabilities
            content_type = response.headers.get('Content-Type', '')
            if 'json' in content_type.lower():
                # Look for JSON endpoints
                json_endpoints = []
                
                # Check if the current URL is a JSON endpoint
                if 'application/json' in content_type.lower():
                    json_endpoints.append(url)
                
                # Look for links to JSON endpoints in the response
                json_link_patterns = [
                    r'href=[\'"]([^\'"]+\.json)[\'"]',
                    r'src=[\'"]([^\'"]+\.json)[\'"]',
                    r'url:[\'"]([^\'"]+\.json)[\'"]',
                    r'endpoint:[\'"]([^\'"]+\.json)[\'"]',
                    r'api:[\'"]([^\'"]+)[\'"]'
                ]
                
                for pattern in json_link_patterns:
                    matches = re.findall(pattern, response.text)
                    for match in matches:
                        if not match.startswith(('http://', 'https://')):
                            # Relative URL
                            match = urljoin(url, match)
                        json_endpoints.append(match)
                
                # Test JSON endpoints for type confusion vulnerabilities
                for endpoint in json_endpoints:
                    try:
                        # Get the JSON data
                        json_response = requests.get(endpoint, timeout=10)
                        
                        if 'application/json' in json_response.headers.get('Content-Type', '').lower():
                            try:
                                json_data = json_response.json()
                                
                                # Look for fields that might be used for type information
                                type_fields = ['type', 'class', 'classname', 'class_name', '$type', '@type', 'Type']
                                
                                for field in type_fields:
                                    if self._find_field_in_json(json_data, field):
                                        vulnerabilities.append({
                                            'type': 'Potential JSON Deserialization Vulnerability',
                                            'url': endpoint,
                                            'location': f'JSON field: {field}',
                                            'evidence': f'JSON data contains type information field: {field}',
                                            'severity': 'Medium',
                                            'description': 'The application appears to be using type information in JSON data, which could be vulnerable to JSON deserialization attacks if not properly validated.',
                                            'remediation': 'Avoid using type information in JSON data. If necessary, implement a whitelist of allowed types and proper validation.'
                                        })
                            except json.JSONDecodeError:
                                pass
                    
                    except Exception as e:
                        print(f"Error testing {endpoint} for JSON deserialization vulnerabilities: {str(e)}")
        
        except Exception as e:
            print(f"Error scanning {url} for insecure deserialization: {str(e)}")
        
        return vulnerabilities
    
    def _find_field_in_json(self, json_data, field_name):
        """Recursively search for a field in JSON data"""
        if isinstance(json_data, dict):
            if field_name in json_data:
                return True
            
            for value in json_data.values():
                if self._find_field_in_json(value, field_name):
                    return True
        
        elif isinstance(json_data, list):
            for item in json_data:
                if self._find_field_in_json(item, field_name):
                    return True
        
        return False