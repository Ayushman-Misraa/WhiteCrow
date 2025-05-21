import requests
import re
from bs4 import BeautifulSoup
import json

class ComponentsVulnerabilityScanner:
    def __init__(self):
        # Common JavaScript libraries and their version patterns
        self.js_libraries = {
            'jQuery': {
                'pattern': r'jquery[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<1.9.0': 'XSS vulnerability in jQuery.html()',
                    '<3.0.0': 'XSS vulnerability in jQuery.parseHTML()',
                    '<3.4.0': 'Prototype pollution vulnerability'
                }
            },
            'Angular': {
                'pattern': r'angular[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<1.6.0': 'XSS vulnerability in $sanitize service',
                    '<1.6.9': 'XSS vulnerability in ngSanitize',
                    '<1.7.0': 'XSS vulnerability in $sce service'
                }
            },
            'React': {
                'pattern': r'react[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<16.0.0': 'XSS vulnerability in React DOM',
                    '<16.3.0': 'Vulnerability in React.createElement()',
                    '<16.9.0': 'Vulnerability in server-side rendering'
                }
            },
            'Vue': {
                'pattern': r'vue[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<2.6.0': 'XSS vulnerability in v-bind directive',
                    '<2.5.17': 'XSS vulnerability in SSR',
                    '<2.4.2': 'XSS vulnerability in $el.innerHTML'
                }
            },
            'Bootstrap': {
                'pattern': r'bootstrap[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<3.4.0': 'XSS vulnerability in data-target attribute',
                    '<4.3.1': 'XSS vulnerability in tooltip component',
                    '<4.1.2': 'XSS vulnerability in carousel component'
                }
            },
            'Lodash': {
                'pattern': r'lodash[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<4.17.11': 'Prototype pollution vulnerability',
                    '<4.17.12': 'Prototype pollution in defaultsDeep',
                    '<4.17.15': 'Prototype pollution in zipObjectDeep'
                }
            },
            'Moment.js': {
                'pattern': r'moment[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<2.19.3': 'Regular expression DoS vulnerability',
                    '<2.24.0': 'Regular expression DoS vulnerability'
                }
            }
        }
        
        # Common server-side frameworks and their version patterns
        self.server_frameworks = {
            'Express': {
                'pattern': r'express/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<4.16.0': 'Path traversal vulnerability',
                    '<4.15.5': 'ReDos vulnerability in mime dependency',
                    '<4.15.2': 'ReDos vulnerability in qs dependency'
                }
            },
            'Django': {
                'pattern': r'Django/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<2.2.9': 'SQL injection vulnerability',
                    '<2.2.8': 'DoS vulnerability in JSONField',
                    '<2.2.4': 'XSS vulnerability in admin interface'
                }
            },
            'Ruby on Rails': {
                'pattern': r'Rails/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<5.2.4.3': 'XSS vulnerability in ActionView',
                    '<5.2.4.2': 'CSRF vulnerability in ActionController',
                    '<5.2.2.1': 'DoS vulnerability in ActiveStorage'
                }
            },
            'Spring': {
                'pattern': r'Spring/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<5.2.0': 'RCE vulnerability in Spring Core',
                    '<5.1.5': 'DoS vulnerability in Spring MVC',
                    '<5.0.5': 'RCE vulnerability in Spring Data'
                }
            },
            'Laravel': {
                'pattern': r'Laravel/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<6.18.35': 'XSS vulnerability in Blade templates',
                    '<6.0.0': 'SQL injection vulnerability in Eloquent',
                    '<5.8.30': 'RCE vulnerability in unserialize'
                }
            }
        }
        
        # Common CMS and their version patterns
        self.cms_systems = {
            'WordPress': {
                'pattern': r'WordPress/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<5.4.2': 'XSS vulnerability in block editor',
                    '<5.3.3': 'XSS vulnerability in comments',
                    '<5.2.5': 'SQL injection vulnerability'
                }
            },
            'Drupal': {
                'pattern': r'Drupal/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<8.8.8': 'RCE vulnerability in AJAX API',
                    '<8.7.14': 'XSS vulnerability in Media module',
                    '<8.6.15': 'CSRF vulnerability in Form API'
                }
            },
            'Joomla': {
                'pattern': r'Joomla/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<3.9.19': 'XSS vulnerability in com_fields',
                    '<3.9.16': 'CSRF vulnerability in com_config',
                    '<3.9.12': 'SQL injection vulnerability in com_contact'
                }
            },
            'Magento': {
                'pattern': r'Magento/(\d+\.\d+\.\d+)',
                'vulnerable_versions': {
                    '<2.3.5': 'RCE vulnerability in admin panel',
                    '<2.3.3': 'SQL injection vulnerability in catalog',
                    '<2.3.1': 'XSS vulnerability in checkout'
                }
            }
        }
        
    def scan(self, url):
        """Scan a URL for vulnerable components"""
        vulnerabilities = []
        
        try:
            # Get the page
            response = requests.get(url, timeout=10)
            
            # Check for JavaScript libraries
            js_vulnerabilities = self._check_js_libraries(response)
            vulnerabilities.extend(js_vulnerabilities)
            
            # Check for server-side frameworks
            server_vulnerabilities = self._check_server_frameworks(response)
            vulnerabilities.extend(server_vulnerabilities)
            
            # Check for CMS systems
            cms_vulnerabilities = self._check_cms_systems(response)
            vulnerabilities.extend(cms_vulnerabilities)
            
            # Check for other components
            other_vulnerabilities = self._check_other_components(response)
            vulnerabilities.extend(other_vulnerabilities)
        
        except Exception as e:
            print(f"Error scanning {url} for component vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _check_js_libraries(self, response):
        """Check for vulnerable JavaScript libraries"""
        vulnerabilities = []
        
        # Extract all script tags
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        
        # Check each script tag for library references
        for script in scripts:
            src = script.get('src', '')
            
            if src:
                # Check for library names in the src attribute
                for library, info in self.js_libraries.items():
                    if library.lower() in src.lower():
                        # Try to extract the version
                        version_match = re.search(info['pattern'], src, re.IGNORECASE)
                        
                        if version_match:
                            version = version_match.group(1)
                            
                            # Check if the version is vulnerable
                            for vuln_version, description in info['vulnerable_versions'].items():
                                if self._is_version_vulnerable(version, vuln_version):
                                    vulnerabilities.append({
                                        'type': 'Vulnerable Component',
                                        'component_type': 'JavaScript Library',
                                        'component': library,
                                        'version': version,
                                        'url': response.url,
                                        'evidence': src,
                                        'vulnerability': description,
                                        'severity': 'Medium',
                                        'description': f'The application is using a vulnerable version of {library} ({version}). {description}',
                                        'remediation': f'Update {library} to the latest version.'
                                    })
            
            # Check for inline scripts that might contain library versions
            if script.string:
                for library, info in self.js_libraries.items():
                    version_match = re.search(info['pattern'], script.string, re.IGNORECASE)
                    
                    if version_match:
                        version = version_match.group(1)
                        
                        # Check if the version is vulnerable
                        for vuln_version, description in info['vulnerable_versions'].items():
                            if self._is_version_vulnerable(version, vuln_version):
                                vulnerabilities.append({
                                    'type': 'Vulnerable Component',
                                    'component_type': 'JavaScript Library',
                                    'component': library,
                                    'version': version,
                                    'url': response.url,
                                    'evidence': f'Inline script containing {library} {version}',
                                    'vulnerability': description,
                                    'severity': 'Medium',
                                    'description': f'The application is using a vulnerable version of {library} ({version}). {description}',
                                    'remediation': f'Update {library} to the latest version.'
                                })
        
        return vulnerabilities
    
    def _check_server_frameworks(self, response):
        """Check for vulnerable server-side frameworks"""
        vulnerabilities = []
        
        # Check headers for framework information
        headers = response.headers
        
        for framework, info in self.server_frameworks.items():
            # Check for framework in headers
            for header_name, header_value in headers.items():
                if framework.lower() in header_value.lower():
                    version_match = re.search(info['pattern'], header_value, re.IGNORECASE)
                    
                    if version_match:
                        version = version_match.group(1)
                        
                        # Check if the version is vulnerable
                        for vuln_version, description in info['vulnerable_versions'].items():
                            if self._is_version_vulnerable(version, vuln_version):
                                vulnerabilities.append({
                                    'type': 'Vulnerable Component',
                                    'component_type': 'Server Framework',
                                    'component': framework,
                                    'version': version,
                                    'url': response.url,
                                    'evidence': f'{header_name}: {header_value}',
                                    'vulnerability': description,
                                    'severity': 'High',
                                    'description': f'The application is using a vulnerable version of {framework} ({version}). {description}',
                                    'remediation': f'Update {framework} to the latest version.'
                                })
        
        # Check for framework-specific patterns in the response body
        for framework, info in self.server_frameworks.items():
            version_match = re.search(info['pattern'], response.text, re.IGNORECASE)
            
            if version_match:
                version = version_match.group(1)
                
                # Check if the version is vulnerable
                for vuln_version, description in info['vulnerable_versions'].items():
                    if self._is_version_vulnerable(version, vuln_version):
                        vulnerabilities.append({
                            'type': 'Vulnerable Component',
                            'component_type': 'Server Framework',
                            'component': framework,
                            'version': version,
                            'url': response.url,
                            'evidence': f'Response body contains {framework} {version}',
                            'vulnerability': description,
                            'severity': 'High',
                            'description': f'The application is using a vulnerable version of {framework} ({version}). {description}',
                            'remediation': f'Update {framework} to the latest version.'
                        })
        
        return vulnerabilities
    
    def _check_cms_systems(self, response):
        """Check for vulnerable CMS systems"""
        vulnerabilities = []
        
        # Check for CMS-specific patterns in the response
        for cms, info in self.cms_systems.items():
            # Check meta tags for CMS information
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = soup.find_all('meta')
            
            for meta in meta_tags:
                if meta.get('name') == 'generator' and cms.lower() in meta.get('content', '').lower():
                    version_match = re.search(info['pattern'], meta.get('content', ''), re.IGNORECASE)
                    
                    if version_match:
                        version = version_match.group(1)
                        
                        # Check if the version is vulnerable
                        for vuln_version, description in info['vulnerable_versions'].items():
                            if self._is_version_vulnerable(version, vuln_version):
                                vulnerabilities.append({
                                    'type': 'Vulnerable Component',
                                    'component_type': 'CMS',
                                    'component': cms,
                                    'version': version,
                                    'url': response.url,
                                    'evidence': f'Meta generator tag: {meta.get("content")}',
                                    'vulnerability': description,
                                    'severity': 'High',
                                    'description': f'The application is using a vulnerable version of {cms} ({version}). {description}',
                                    'remediation': f'Update {cms} to the latest version.'
                                })
            
            # Check for CMS-specific patterns in the response body
            version_match = re.search(info['pattern'], response.text, re.IGNORECASE)
            
            if version_match:
                version = version_match.group(1)
                
                # Check if the version is vulnerable
                for vuln_version, description in info['vulnerable_versions'].items():
                    if self._is_version_vulnerable(version, vuln_version):
                        vulnerabilities.append({
                            'type': 'Vulnerable Component',
                            'component_type': 'CMS',
                            'component': cms,
                            'version': version,
                            'url': response.url,
                            'evidence': f'Response body contains {cms} {version}',
                            'vulnerability': description,
                            'severity': 'High',
                            'description': f'The application is using a vulnerable version of {cms} ({version}). {description}',
                            'remediation': f'Update {cms} to the latest version.'
                        })
        
        return vulnerabilities
    
    def _check_other_components(self, response):
        """Check for other vulnerable components"""
        vulnerabilities = []
        
        # Check for package.json or similar files that might contain dependency information
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        
        package_files = ['package.json', 'composer.json', 'requirements.txt', 'Gemfile', 'pom.xml']
        
        for link in links:
            href = link.get('href', '')
            
            for package_file in package_files:
                if package_file in href:
                    try:
                        package_response = requests.get(response.url.rstrip('/') + '/' + href.lstrip('/'), timeout=5)
                        
                        if package_response.status_code == 200:
                            # Try to parse as JSON
                            try:
                                package_data = json.loads(package_response.text)
                                
                                # Check dependencies
                                if 'dependencies' in package_data:
                                    for dep, ver in package_data['dependencies'].items():
                                        # Here we would check against a database of known vulnerable packages
                                        # For now, we'll just report the dependency
                                        vulnerabilities.append({
                                            'type': 'Exposed Dependency Information',
                                            'component_type': 'Dependency',
                                            'component': dep,
                                            'version': ver,
                                            'url': package_response.url,
                                            'evidence': f'Dependency information exposed in {package_file}',
                                            'severity': 'Medium',
                                            'description': f'The application exposes dependency information, which could help attackers identify vulnerable components.',
                                            'remediation': f'Restrict access to {package_file} and similar files that expose dependency information.'
                                        })
                            except json.JSONDecodeError:
                                # Not a JSON file, might be another format
                                pass
                    
                    except Exception:
                        pass
        
        return vulnerabilities
    
    def _is_version_vulnerable(self, current_version, vulnerable_version):
        """Check if the current version is vulnerable based on the vulnerable version specification"""
        # Parse the versions
        current_parts = list(map(int, current_version.split('.')))
        
        # Handle version ranges
        if vulnerable_version.startswith('<'):
            # Less than a specific version
            vuln_version = vulnerable_version[1:]
            vuln_parts = list(map(int, vuln_version.split('.')))
            
            # Compare versions
            for i in range(max(len(current_parts), len(vuln_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                vuln_part = vuln_parts[i] if i < len(vuln_parts) else 0
                
                if current_part < vuln_part:
                    return True
                elif current_part > vuln_part:
                    return False
            
            # Versions are equal
            return False
        
        elif vulnerable_version.startswith('<='):
            # Less than or equal to a specific version
            vuln_version = vulnerable_version[2:]
            vuln_parts = list(map(int, vuln_version.split('.')))
            
            # Compare versions
            for i in range(max(len(current_parts), len(vuln_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                vuln_part = vuln_parts[i] if i < len(vuln_parts) else 0
                
                if current_part < vuln_part:
                    return True
                elif current_part > vuln_part:
                    return False
            
            # Versions are equal
            return True
        
        elif vulnerable_version.startswith('>'):
            # Greater than a specific version
            vuln_version = vulnerable_version[1:]
            vuln_parts = list(map(int, vuln_version.split('.')))
            
            # Compare versions
            for i in range(max(len(current_parts), len(vuln_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                vuln_part = vuln_parts[i] if i < len(vuln_parts) else 0
                
                if current_part > vuln_part:
                    return True
                elif current_part < vuln_part:
                    return False
            
            # Versions are equal
            return False
        
        elif vulnerable_version.startswith('>='):
            # Greater than or equal to a specific version
            vuln_version = vulnerable_version[2:]
            vuln_parts = list(map(int, vuln_version.split('.')))
            
            # Compare versions
            for i in range(max(len(current_parts), len(vuln_parts))):
                current_part = current_parts[i] if i < len(current_parts) else 0
                vuln_part = vuln_parts[i] if i < len(vuln_parts) else 0
                
                if current_part > vuln_part:
                    return True
                elif current_part < vuln_part:
                    return False
            
            # Versions are equal
            return True
        
        else:
            # Exact version match
            vuln_parts = list(map(int, vulnerable_version.split('.')))
            
            # Compare versions
            if len(current_parts) != len(vuln_parts):
                return False
            
            for i in range(len(current_parts)):
                if current_parts[i] != vuln_parts[i]:
                    return False
            
            # Versions are equal
            return True