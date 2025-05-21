import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import time
import re
from bs4 import BeautifulSoup
import concurrent.futures
import logging
import random
import socket
from datetime import datetime
from .modules.sql_injection import SQLInjectionScanner
from .modules.xss import XSSScanner
from .modules.csrf import CSRFScanner
from .modules.ssrf import SSRFScanner
from .modules.broken_auth import BrokenAuthScanner
from .modules.sensitive_data import SensitiveDataScanner
from .modules.xxe import XXEScanner
from .modules.security_misconfig import SecurityMisconfigScanner
from .modules.insecure_deserialization import InsecureDeserializationScanner
from .modules.components_vulnerabilities import ComponentsVulnerabilityScanner

class WebVulnerabilityScanner:
    def __init__(self, target_url, options=None):
        self.target_url = target_url
        self.options = options or {}
        self.visited_urls = set()
        self.urls_to_scan = [target_url]
        self.results = {
            'target': target_url,
            'scan_time': None,
            'vulnerabilities': [],
            'statistics': {
                'urls_scanned': 0,
                'vulnerabilities_found': 0,
                'scan_duration': 0
            }
        }
        self.scanners = self._initialize_scanners()
        
    def _initialize_scanners(self):
        """Initialize all vulnerability scanners"""
        return {
            'sql_injection': SQLInjectionScanner(),
            'xss': XSSScanner(),
            'csrf': CSRFScanner(),
            'ssrf': SSRFScanner(),
            'broken_auth': BrokenAuthScanner(),
            'sensitive_data': SensitiveDataScanner(),
            'xxe': XXEScanner(),
            'security_misconfig': SecurityMisconfigScanner(),
            'insecure_deserialization': InsecureDeserializationScanner(),
            'components_vulnerabilities': ComponentsVulnerabilityScanner()
        }
    
    def start_scan(self):
        """Start the vulnerability scan"""
        start_time = time.time()
        
        # Crawl the website if enabled - with deeper crawling
        if self.options.get('crawl', True):
            self._crawl_website()
        
        # Set a lower number of concurrent threads for more thorough scanning
        # This will make each scan more focused and reduce resource contention
        max_workers = self.options.get('threads', 3)
        
        # Scan each URL for vulnerabilities with increased timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self._scan_url, url) for url in self.urls_to_scan]
            # Wait for all scans to complete, even if they take longer
            concurrent.futures.wait(futures, timeout=None)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Update results
        self.results['scan_time'] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results['statistics']['urls_scanned'] = len(self.visited_urls)
        self.results['statistics']['vulnerabilities_found'] = len(self.results['vulnerabilities'])
        self.results['statistics']['scan_duration'] = round(scan_duration, 2)
        
        # Add more detailed statistics
        self.results['statistics']['scan_depth'] = 'Thorough'
        self.results['statistics']['scan_mode'] = 'Comprehensive'
        
        return self.results
    
    def _crawl_website(self):
        """Crawl the website to find all URLs with enhanced discovery"""
        max_urls = self.options.get('max_urls', 200)  # Increased from 100 to 200
        timeout = self.options.get('timeout', 20)     # Increased timeout
        
        # Track visited URLs and their depth
        url_depths = {self.target_url: 0}
        max_depth = self.options.get('max_depth', 5)  # Crawl up to 5 levels deep
        
        while self.urls_to_scan and len(self.visited_urls) < max_urls:
            url = self.urls_to_scan.pop(0)
            current_depth = url_depths.get(url, 0)
            
            # Skip if already visited or exceeds max depth
            if url in self.visited_urls or current_depth >= max_depth:
                continue
                
            try:
                # Use a longer timeout for more reliable crawling
                response = requests.get(url, timeout=timeout, 
                                       headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
                self.visited_urls.add(url)
                
                # Parse the HTML content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links - including those in JavaScript and CSS
                self._extract_links_from_html(soup, url, current_depth, url_depths)
                
                # Look for forms that might be vulnerable
                self._extract_forms(soup, url)
                
                # Extract URLs from JavaScript
                self._extract_urls_from_javascript(soup, url, current_depth, url_depths)
                
                # Check for robots.txt and sitemap.xml if at root level
                if current_depth == 0:
                    self._check_robots_and_sitemap(url, url_depths)
            
            except Exception as e:
                print(f"Error crawling {url}: {str(e)}")
    
    def _extract_links_from_html(self, soup, base_url, current_depth, url_depths):
        """Extract links from HTML with enhanced discovery"""
        # Find all elements that might contain URLs
        for element in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame', 'area', 'base', 'form']):
            # Check different attributes that might contain URLs
            for attr in ['href', 'src', 'action', 'data-src', 'data-url']:
                if element.has_attr(attr):
                    href = element[attr]
                    self._process_url(href, base_url, current_depth + 1, url_depths)
    
    def _extract_urls_from_javascript(self, soup, base_url, current_depth, url_depths):
        """Extract URLs from JavaScript code"""
        # Find all script tags
        for script in soup.find_all('script'):
            if script.string:
                # Look for URLs in JavaScript using regex
                urls = re.findall(r'(https?://[^\s\'"]+)', script.string)
                urls += re.findall(r'[\'"](/[^\s\'"]*)[\'"]', script.string)  # Relative URLs
                
                for url in urls:
                    self._process_url(url, base_url, current_depth + 1, url_depths)
    
    def _check_robots_and_sitemap(self, base_url, url_depths):
        """Check robots.txt and sitemap.xml for additional URLs"""
        parsed_url = urlparse(base_url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check robots.txt
        try:
            robots_url = f"{base}/robots.txt"
            response = requests.get(robots_url, timeout=10)
            if response.status_code == 200:
                # Extract sitemap URLs
                sitemaps = re.findall(r'Sitemap:\s*(https?://[^\s]+)', response.text)
                for sitemap in sitemaps:
                    self._process_url(sitemap, base_url, 1, url_depths)
                
                # Extract allowed URLs
                allowed = re.findall(r'Allow:\s*([^\s]+)', response.text)
                for path in allowed:
                    url = urljoin(base, path)
                    self._process_url(url, base_url, 1, url_depths)
        except Exception as e:
            print(f"Error checking robots.txt: {str(e)}")
        
        # Check sitemap.xml
        try:
            sitemap_url = f"{base}/sitemap.xml"
            response = requests.get(sitemap_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'xml')
                locs = soup.find_all('loc')
                for loc in locs:
                    self._process_url(loc.text, base_url, 1, url_depths)
        except Exception as e:
            print(f"Error checking sitemap.xml: {str(e)}")
    
    def _extract_forms(self, soup, url):
        """Extract and analyze forms for potential vulnerabilities"""
        forms = soup.find_all('form')
        for form in forms:
            # Add the form action URL to the scan list
            action = form.get('action', '')
            if action:
                self._process_url(action, url, 1, {})
    
    def _process_url(self, href, base_url, depth, url_depths):
        """Process a URL and add it to the scan list if valid"""
        # Skip empty, anchors, javascript, and mailto links
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            return
            
        # Convert relative URL to absolute
        if not href.startswith(('http://', 'https://')):
            href = urljoin(base_url, href)
        
        # Clean the URL (remove fragments)
        parsed = urlparse(href)
        href = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
        
        # Only add URLs from the same domain
        if urlparse(href).netloc == urlparse(self.target_url).netloc:
            if href not in self.visited_urls and href not in self.urls_to_scan:
                self.urls_to_scan.append(href)
                url_depths[href] = depth
    
    def _scan_url(self, url):
        """Scan a single URL for all vulnerabilities with enhanced thoroughness"""
        # First, get baseline response for comparison
        try:
            baseline_response = requests.get(url, timeout=20, 
                                           headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
            baseline_status = baseline_response.status_code
            baseline_headers = baseline_response.headers
            baseline_content = baseline_response.text
        except Exception as e:
            print(f"Error getting baseline for {url}: {str(e)}")
            return
        
        # Run each scanner with enhanced options
        for scanner_name, scanner in self.scanners.items():
            if self.options.get(scanner_name, True):  # Check if this scanner is enabled
                try:
                    # Set enhanced options for more thorough scanning
                    scanner_options = {
                        'thorough': True,
                        'timeout': 30,  # Increased timeout
                        'baseline_response': baseline_response,
                        'baseline_status': baseline_status,
                        'baseline_headers': baseline_headers,
                        'baseline_content': baseline_content,
                        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                    
                    # Run the scan with enhanced options
                    vulnerabilities = scanner.scan(url, scanner_options)
                    
                    # Verify findings to reduce false positives
                    verified_vulnerabilities = self._verify_findings(vulnerabilities, url, scanner_name)
                    
                    if verified_vulnerabilities:
                        self.results['vulnerabilities'].extend(verified_vulnerabilities)
                        
                except Exception as e:
                    print(f"Error in {scanner_name} scanner for {url}: {str(e)}")
    
    def _verify_findings(self, vulnerabilities, url, scanner_name):
        """Verify vulnerability findings to reduce false positives"""
        verified = []
        
        for vuln in vulnerabilities:
            # Skip verification for certain high-confidence findings
            if vuln.get('confidence', 'Medium') == 'High':
                verified.append(vuln)
                continue
                
            # For others, try to verify with a second check
            try:
                # Get the payload that triggered the vulnerability
                payload = vuln.get('payload', '')
                param = vuln.get('parameter', '')
                
                if payload and param:
                    # Construct a slightly modified payload to confirm
                    if scanner_name == 'sql_injection':
                        # For SQL injection, try a different payload
                        modified_payload = payload.replace("'", "\"") if "'" in payload else payload.replace("\"", "'")
                    elif scanner_name == 'xss':
                        # For XSS, try a different tag
                        modified_payload = payload.replace("<script>", "<img src=x onerror=") if "<script>" in payload else payload.replace("<img", "<svg")
                    else:
                        # For others, just add some noise
                        modified_payload = payload + "/* verification */"
                    
                    # Re-test with the modified payload
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    
                    if params and param in params:
                        # URL parameter test
                        new_params = params.copy()
                        new_params[param] = [modified_payload]
                        query_string = urlencode(new_params, doseq=True)
                        verification_url = urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            query_string,
                            parsed_url.fragment
                        ))
                        
                        response = requests.get(verification_url, timeout=20)
                        
                        # Check if we still get the same type of vulnerability
                        if (scanner_name == 'sql_injection' and any(re.search(pattern, response.text, re.IGNORECASE) for pattern in self.scanners['sql_injection'].error_patterns)) or \
                           (scanner_name == 'xss' and modified_payload in response.text) or \
                           (scanner_name == 'csrf' and 'csrf' not in response.text.lower()):
                            # Verification successful
                            vuln['confidence'] = 'High'  # Upgrade confidence
                            verified.append(vuln)
                    else:
                        # Can't verify, but still include with original confidence
                        verified.append(vuln)
                else:
                    # No payload or parameter to verify with, include as is
                    verified.append(vuln)
            except Exception as e:
                print(f"Error verifying {scanner_name} vulnerability on {url}: {str(e)}")
                # Include the vulnerability despite verification failure
                verified.append(vuln)
                
        return verified
    
    def get_results(self):
        """Get the scan results"""
        return self.results