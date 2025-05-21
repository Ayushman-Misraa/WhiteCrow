
A comprehensive web vulnerability scanner with a sleek desktop GUI, designed for professional security testing and penetration testing. WhiteCrow helps security professionals identify and remediate web application vulnerabilities with precision and efficiency.

## 🔍 Features

- **Advanced Vulnerability Detection**: Identifies OWASP Top 10 vulnerabilities with high accuracy
- **Modern Desktop Interface**: Elegant dark-themed UI with intuitive controls and real-time feedback
- **Comprehensive Reporting**: Generate detailed reports in multiple formats (PDF, HTML, JSON, CSV)
- **Customizable Scanning Engine**: Configure scan depth, target vulnerabilities, and testing parameters
- **Multi-threaded Architecture**: Parallel scanning capabilities for improved performance
- **Real-time Progress Monitoring**: Live updates on scan progress and findings
- **Detailed Vulnerability Analysis**: In-depth information on each vulnerability with remediation guidance
- **Cross-platform Compatibility**: Works on Windows, macOS, and Linux

## 🛡️ Vulnerabilities Detected

WhiteCrow can detect a wide range of web application vulnerabilities, including:

| Vulnerability Type | Description |
|-------------------|-------------|
| SQL Injection | Detection of various SQL injection techniques including error-based, time-based, and boolean-based blind injections |
| Cross-Site Scripting (XSS) | Identification of reflected, stored, and DOM-based XSS vulnerabilities |
| Cross-Site Request Forgery (CSRF) | Detection of CSRF vulnerabilities in forms and requests |
| Server-Side Request Forgery (SSRF) | Identification of SSRF vulnerabilities that could allow server manipulation |
| Broken Authentication | Detection of weak authentication mechanisms and session management flaws |
| Sensitive Data Exposure | Identification of improperly protected sensitive information |
| XML External Entities (XXE) | Detection of XXE vulnerabilities in XML processors |
| Security Misconfigurations | Identification of insecure default configurations and incomplete setups |
| Insecure Deserialization | Detection of insecure deserialization vulnerabilities |
| Vulnerable Components | Identification of components with known vulnerabilities |

## 📋 Requirements

- Python 3.8 or higher
- PyQt5 for the GUI components
- Required Python packages (see requirements.txt)
- For PDF report generation: wkhtmltopdf (automatically installed with pdfkit)

## 🔧 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Ayushman-Misraa/WhiteCrow.git
cd whitecrow
```

### Step 2: Create a Virtual Environment (Recommended)

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Additional Components (for PDF Reports)

For PDF report generation, you need wkhtmltopdf:

- **Windows**: The installer will be downloaded automatically when needed
- **macOS**: `brew install wkhtmltopdf`
- **Linux**: `sudo apt-get install wkhtmltopdf` (Ubuntu/Debian) or equivalent for your distribution

## 🚀 Usage

### Starting the Application

```bash
python app.py
```

This will launch the WhiteCrow desktop application with its intuitive GUI interface.

### Basic Scanning Workflow

1. **Configure Target**: Enter the target URL in the main input field
2. **Select Scan Options**: Choose which vulnerabilities to scan for using the checkboxes
3. **Set Scan Parameters**: Configure scan depth, threads, and timeout settings
4. **Start Scan**: Click the "Start Scan" button to begin the vulnerability assessment
5. **Monitor Progress**: Watch real-time updates in the progress section
6. **Review Results**: Analyze the findings in the results tab once the scan completes
7. **Generate Report**: Export a comprehensive report in your preferred format

### Command Line Options

WhiteCrow also supports command-line operation for integration with other tools:

```bash
python app.py --headless --url https://example.com --output report.pdf
```

For a full list of command-line options:

```bash
python app.py --help
```

## 📊 Understanding Scan Results

WhiteCrow categorizes vulnerabilities by severity:

- **Critical**: Vulnerabilities that pose an immediate threat and should be addressed urgently
- **High**: Serious vulnerabilities that should be prioritized
- **Medium**: Moderate risk vulnerabilities that should be addressed
- **Low**: Minor issues that represent minimal risk
- **Informational**: Findings that don't represent a direct risk but could be useful for security hardening

Each vulnerability report includes:

- Detailed description of the vulnerability
- The affected URL and parameters
- Evidence of the vulnerability
- Technical details about how it was discovered
- Recommended remediation steps
- References to relevant security resources

## 🔄 Advanced Configuration

WhiteCrow can be customized through the settings panel:

- **Scan Depth**: Control how thoroughly the scanner crawls the target application
- **Request Throttling**: Adjust request timing to avoid overwhelming the target server
- **Custom Headers**: Add specific HTTP headers to requests
- **Authentication**: Configure credentials for testing authenticated sections
- **Proxy Settings**: Route requests through a proxy for additional testing capabilities
- **Custom Payloads**: Add your own test payloads for specialized testing scenarios

## 🤝 Contributing

Contributions to WhiteCrow are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the project's coding standards and includes appropriate tests.


## ⚠️ Ethical Use Warning

WhiteCrow is a powerful security testing tool designed for legitimate security assessments with proper authorization. Unauthorized scanning of systems is illegal in most jurisdictions and unethical. Always ensure you have explicit permission to scan any target system.

The developers of WhiteCrow are not responsible for any misuse of this software or for any damage that may result from its use. Use responsibly and ethically.

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Common Vulnerability Scoring System](https://www.first.org/cvss/)

## 📞 Support

For bug reports and feature requests, please use the [GitHub account](https://github.com/Ayushman-Misraa/).

For general questions and discussions, and colaboration [gmail account](ayushmanmisra036@gmail.com).

---

*WhiteCrow - Illuminate the Shadows, Secure the Web*
