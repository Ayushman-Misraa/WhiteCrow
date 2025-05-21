import requests
from urllib.parse import urlparse, urljoin
import re

class SecurityMisconfigScanner:
    def __init__(self):
        self.common_paths = [
            '/.git/',
            '/.svn/',
            '/.env',
            '/.htaccess',
            '/config.php',
            '/config.js',
            '/config.json',
            '/settings.php',
            '/settings.js',
            '/settings.json',
            '/backup/',
            '/backup.zip',
            '/backup.tar.gz',
            '/backup.sql',
            '/phpinfo.php',
            '/info.php',
            '/server-status',
            '/server-info',
            '/wp-config.php',
            '/wp-admin/',
            '/admin/',
            '/administrator/',
            '/manager/',
            '/console/',
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/swagger/',
            '/swagger-ui.html',
            '/api-docs/',
            '/actuator/',
            '/actuator/health',
            '/actuator/info',
            '/actuator/env',
            '/debug/',
            '/debug/pprof/',
            '/status',
            '/metrics',
            '/logs/',
            '/log/',
            '/tmp/',
            '/temp/',
            '/test/',
            '/dev/',
            '/development/',
            '/staging/'
        ]
        
        self.security_headers = {
            'X-Frame-Options': 'Protects against clickjacking',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'Content-Security-Policy': 'Restricts resource loading',
            'X-XSS-Protection': 'Provides XSS protection',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Referrer-Policy': 'Controls referrer information',
            'Feature-Policy': 'Restricts browser features',
            'Permissions-Policy': 'Restricts browser features (newer version)'
        }
        
    def scan(self, url):
        """Scan a URL for security misconfigurations"""
        vulnerabilities = []
        
        try:
            # Get the base URL
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Check for missing security headers
            response = requests.get(url, timeout=10)
            missing_headers = []
            
            for header, description in self.security_headers.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                vulnerabilities.append({
                    'type': 'Missing Security Headers',
                    'url': url,
                    'evidence': f"Missing headers: {', '.join(missing_headers)}",
                    'severity': 'Medium',
                    'description': 'The application is missing important security headers that help protect against various attacks.',
                    'remediation': 'Implement the missing security headers to enhance the security of the application.'
                })
            
            # Check for directory listing
            directory_paths = ['/images/', '/css/', '/js/', '/uploads/', '/includes/', '/assets/']
            for path in directory_paths:
                dir_url = urljoin(base_url, path)
                try:
                    dir_response = requests.get(dir_url, timeout=5)
                    
                    # Check for directory listing
                    if dir_response.status_code == 200 and 'Index of' in dir_response.text:
                        vulnerabilities.append({
                            'type': 'Directory Listing',
                            'url': dir_url,
                            'evidence': 'Directory listing enabled',
                            'severity': 'Medium',
                            'description': 'Directory listing is enabled, which can expose sensitive files and information.',
                            'remediation': 'Disable directory listing in the web server configuration.'
                        })
                except Exception:
                    pass
            
            # Check for sensitive files and directories
            for path in self.common_paths:
                sensitive_url = urljoin(base_url, path)
                try:
                    sensitive_response = requests.get(sensitive_url, timeout=5)
                    
                    # Check if the file/directory exists
                    if sensitive_response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'Sensitive File/Directory',
                            'url': sensitive_url,
                            'evidence': f'Status code: {sensitive_response.status_code}',
                            'severity': 'High',
                            'description': 'A sensitive file or directory was found that could expose confidential information or provide access to administrative functions.',
                            'remediation': 'Remove or restrict access to sensitive files and directories.'
                        })
                except Exception:
                    pass
            
            # Check for error disclosure
            error_test_url = urljoin(url, '/nonexistent_page_12345')
            try:
                error_response = requests.get(error_test_url, timeout=5)
                
                # Check for detailed error messages
                error_patterns = [
                    r'SQL syntax.*?MySQL',
                    r'Warning.*?\\Wmysqli?_',
                    r'ORA-[0-9][0-9][0-9][0-9]',
                    r'Microsoft OLE DB Provider for SQL Server',
                    r'Unclosed quotation mark after the character string',
                    r'PostgreSQL.*?ERROR',
                    r'System\.Data\.SQLite\.SQLiteException',
                    r'Exception.*?Stack trace',
                    r'<b>Warning</b>:.*?on line',
                    r'<b>Fatal error</b>:.*?on line'
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, error_response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Error Disclosure',
                            'url': error_test_url,
                            'evidence': f'Error pattern matched: {pattern}',
                            'severity': 'Medium',
                            'description': 'The application reveals detailed error messages that could disclose sensitive information about the system.',
                            'remediation': 'Configure the application to display generic error messages in production and log detailed errors server-side.'
                        })
                        break
            except Exception:
                pass
            
            # Check for HTTP methods
            try:
                options_response = requests.options(url, timeout=5)
                
                if 'Allow' in options_response.headers:
                    allowed_methods = options_response.headers['Allow']
                    dangerous_methods = []
                    
                    if 'PUT' in allowed_methods:
                        dangerous_methods.append('PUT')
                    if 'DELETE' in allowed_methods:
                        dangerous_methods.append('DELETE')
                    if 'TRACE' in allowed_methods:
                        dangerous_methods.append('TRACE')
                    
                    if dangerous_methods:
                        vulnerabilities.append({
                            'type': 'Dangerous HTTP Methods',
                            'url': url,
                            'evidence': f"Allowed methods: {allowed_methods}",
                            'severity': 'Medium',
                            'description': f"The server allows potentially dangerous HTTP methods: {', '.join(dangerous_methods)}",
                            'remediation': 'Disable unnecessary HTTP methods in the web server configuration.'
                        })
            except Exception:
                pass
        
        except Exception as e:
            print(f"Error scanning {url} for security misconfigurations: {str(e)}")
        
        return vulnerabilities