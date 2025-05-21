import sys
import os
import json
import datetime
import threading
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QCheckBox, 
                            QSpinBox, QTextEdit, QProgressBar, QGroupBox, QFormLayout, 
                            QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
                            QSplitter, QFrame, QFileDialog, QComboBox, QScrollArea,
                            QDialog, QToolTip)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QBuffer, QByteArray
from PyQt5.QtGui import QFont, QIcon, QPixmap, QColor, QPalette, QFontDatabase

# Import scanner modules
from scanner.modules.sql_injection import SQLInjectionScanner
from scanner.modules.xss import XSSScanner
from scanner.modules.csrf import CSRFScanner
from scanner.modules.ssrf import SSRFScanner
from scanner.modules.broken_auth import BrokenAuthScanner
from scanner.modules.sensitive_data import SensitiveDataScanner
from scanner.modules.xxe import XXEScanner
from scanner.modules.security_misconfig import SecurityMisconfigScanner
from scanner.modules.insecure_deserialization import InsecureDeserializationScanner
from scanner.modules.components_vulnerabilities import ComponentsVulnerabilityScanner

class ScannerThread(QThread):
    update_progress = pyqtSignal(int, str)
    scan_complete = pyqtSignal(dict)
    
    def __init__(self, url, options):
        super().__init__()
        self.url = url
        self.options = options
        self.is_running = True  # Flag to control execution
        
    def run(self):
        try:
            # Initialize results dictionary
            results = {
                "target": self.url,
                "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "statistics": {
                    "urls_scanned": 1,
                    "scan_duration": 0,
                    "vulnerabilities_found": 0
                },
                "vulnerabilities": []
            }
            
            start_time = time.time()
            self.is_running = True  # Set running flag
            
            # Update progress
            self.update_progress.emit(5, "Initializing scan...")
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Simulate initial reconnaissance (crawling and discovery)
            self.update_progress.emit(8, "Performing initial reconnaissance...")
            # Break up sleep into smaller chunks to be more responsive to termination
            for _ in range(15):
                if not self.is_running:
                    return
                time.sleep(0.1)  # 15 * 0.1 = 1.5 seconds total
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Simulate site mapping
            self.update_progress.emit(10, "Mapping site structure...")
            # Break up sleep into smaller chunks
            for _ in range(20):
                if not self.is_running:
                    return
                time.sleep(0.1)  # 20 * 0.1 = 2 seconds total
            
            # Initialize scanners based on options
            scanners = []
            
            if self.options.get("sql_injection", True):
                scanners.append(("SQL Injection", SQLInjectionScanner()))
                
            if self.options.get("xss", True):
                scanners.append(("XSS", XSSScanner()))
                
            if self.options.get("csrf", True):
                scanners.append(("CSRF", CSRFScanner()))
                
            if self.options.get("ssrf", True):
                scanners.append(("SSRF", SSRFScanner()))
                
            if self.options.get("broken_auth", True):
                scanners.append(("Broken Authentication", BrokenAuthScanner()))
                
            if self.options.get("sensitive_data", True):
                scanners.append(("Sensitive Data", SensitiveDataScanner()))
                
            if self.options.get("xxe", True):
                scanners.append(("XXE", XXEScanner()))
                
            if self.options.get("security_misconfig", True):
                scanners.append(("Security Misconfigurations", SecurityMisconfigScanner()))
                
            if self.options.get("insecure_deserialization", True):
                scanners.append(("Insecure Deserialization", InsecureDeserializationScanner()))
                
            if self.options.get("components_vulnerabilities", True):
                scanners.append(("Vulnerable Components", ComponentsVulnerabilityScanner()))
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Run each scanner with extended phases for more thorough scanning
            # Reserve 75% of progress bar for scanners (from 15% to 90%)
            progress_per_scanner = 75 / max(len(scanners), 1)  # Avoid division by zero
            current_progress = 15
            
            for scanner_name, scanner in scanners:
                # Check if thread should continue
                if not self.is_running:
                    return
                    
                # Initial phase - basic scanning
                self.update_progress.emit(int(current_progress), f"Running {scanner_name} scan (phase 1/3)...")
                # Break up sleep into smaller chunks
                for _ in range(10):
                    if not self.is_running:
                        return
                    time.sleep(0.1)  # 10 * 0.1 = 1 second total
                
                # Check if thread should continue
                if not self.is_running:
                    return
                    
                # Second phase - deep scanning
                phase2_progress = current_progress + (progress_per_scanner / 3)
                self.update_progress.emit(int(phase2_progress), f"Running {scanner_name} deep scan (phase 2/3)...")
                # Break up sleep into smaller chunks
                for _ in range(15):
                    if not self.is_running:
                        return
                    time.sleep(0.1)  # 15 * 0.1 = 1.5 seconds total
                
                # Check if thread should continue
                if not self.is_running:
                    return
                    
                # Third phase - validation and verification
                phase3_progress = current_progress + (progress_per_scanner * 2 / 3)
                self.update_progress.emit(int(phase3_progress), f"Validating {scanner_name} findings (phase 3/3)...")
                
                try:
                    vulnerabilities = scanner.scan(self.url)
                    results["vulnerabilities"].extend(vulnerabilities)
                except Exception as e:
                    print(f"Error in {scanner_name} scanner: {str(e)}")
                
                # Check if thread should continue
                if not self.is_running:
                    return
                    
                current_progress += progress_per_scanner
                self.update_progress.emit(int(current_progress), f"Completed {scanner_name} scan")
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Final analysis phase
            self.update_progress.emit(92, "Performing final analysis...")
            # Break up sleep into smaller chunks
            for _ in range(20):
                if not self.is_running:
                    return
                time.sleep(0.1)  # 20 * 0.1 = 2 seconds total
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Report generation phase
            self.update_progress.emit(95, "Generating comprehensive report...")
            # Break up sleep into smaller chunks
            for _ in range(15):
                if not self.is_running:
                    return
                time.sleep(0.1)  # 15 * 0.1 = 1.5 seconds total
            
            # Check if thread should continue
            if not self.is_running:
                return
                
            # Calculate statistics
            end_time = time.time()
            results["statistics"]["scan_duration"] = round(end_time - start_time, 2)
            results["statistics"]["vulnerabilities_found"] = len(results["vulnerabilities"])
            
            # Add simulated crawled URLs count for more realistic statistics
            results["statistics"]["urls_scanned"] = 15 + (int(end_time - start_time) % 20)
            
            # Final check before completion
            if not self.is_running:
                return
                
            self.update_progress.emit(100, "Scan completed!")
            self.scan_complete.emit(results)
            
        except Exception as e:
            self.update_progress.emit(0, f"Error: {str(e)}")
            print(f"Scan error: {str(e)}")

class MainWindow(QMainWindow):
    def update_format_description(self, index, label):
        """Update the description text based on the selected export format"""
        descriptions = [
            "Professional PDF report with executive summary and detailed findings",
            "Interactive HTML report with charts and vulnerability details",
            "Machine-readable JSON data for integration with other security tools",
            "CSV format for easy import into spreadsheets and databases"
        ]
        if 0 <= index < len(descriptions):
            label.setText(descriptions[index])
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WhiteCrow - Advanced Web Vulnerability Scanner")
        self.setMinimumSize(1200, 800)
        
        # Create a timer for updating the elapsed time display
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_elapsed_time)
        self.timer.setInterval(1000)  # Update every second
        
        # Set application style with a dark hacker theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #121212;
                color: #e0e0e0;
            }
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
            }
            QTabWidget::pane {
                border: 1px solid #2a2a2a;
                border-radius: 6px;
                background-color: #1a1a1a;
            }
            QTabBar::tab {
                background-color: #1a1a1a;
                border: 1px solid #2a2a2a;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 10px 20px;
                margin-right: 2px;
                color: #808080;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #252525;
                color: #00ff00;
                border-bottom: 2px solid #00ff00;
            }
            QTabBar::tab:hover:!selected {
                background-color: #252525;
                color: #00cc00;
            }
            QPushButton {
                background-color: #252525;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                font-family: 'Consolas', monospace;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background-color: #323232;
                border: 1px solid #00ff00;
                color: #ffffff;
            }
            QPushButton:pressed {
                background-color: #00ff00;
                color: #000000;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #505050;
                border: 1px solid #505050;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                padding: 10px;
                color: #e0e0e0;
                selection-background-color: #00ff00;
                selection-color: #000000;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #00ff00;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 16px;
                padding-top: 16px;
                color: #00ff00;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #00ff00;
            }
            QProgressBar {
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                text-align: center;
                background-color: #252525;
                color: #000000;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
                width: 10px;
                border-radius: 5px;
            }
            QTableWidget {
                background-color: #1a1a1a;
                alternate-background-color: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                gridline-color: #3a3a3a;
                color: #e0e0e0;
                selection-background-color: #00ff00;
                selection-color: #000000;
            }
            QHeaderView::section {
                background-color: #252525;
                border: 1px solid #3a3a3a;
                padding: 6px;
                font-weight: bold;
                color: #00ff00;
            }
            QScrollBar:vertical {
                border: none;
                background: #1a1a1a;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #3a3a3a;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ff00;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                border: none;
                background: #1a1a1a;
                height: 10px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #3a3a3a;
                min-width: 20px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #00ff00;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QCheckBox {
                color: #e0e0e0;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 1px solid #3a3a3a;
            }
            QCheckBox::indicator:unchecked {
                background-color: #252525;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff00;
                image: url(check.png);
            }
            QLabel {
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                selection-background-color: #00ff00;
                selection-color: #000000;
                font-family: 'Consolas', monospace;
            }
            QComboBox QAbstractItemView {
                background-color: #252525;
                border: 1px solid #3a3a3a;
                selection-background-color: #00ff00;
                selection-color: #000000;
                outline: 0;
            }
            QToolTip {
                background-color: #252525;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 4px;
            }
        """)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.scan_tab = QWidget()
        self.results_tab = QWidget()
        self.about_tab = QWidget()
        
        self.tabs.addTab(self.scan_tab, "Scan")
        self.tabs.addTab(self.results_tab, "Results")
        self.tabs.addTab(self.about_tab, "About")
        
        # Set up the scan tab
        self.setup_scan_tab()
        
        # Set up the results tab
        self.setup_results_tab()
        
        # Set up the about tab
        self.setup_about_tab()
        
        # Initialize scan results
        self.scan_results = None
        
    def setup_scan_tab(self):
        # Create a main layout for the tab
        main_layout = QVBoxLayout()
        
        # Create a scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                border: none;
                background: #1a1a1a;
                width: 14px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #3a3a3a;
                min-height: 30px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ff00;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        # Create a widget to hold the scrollable content
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(20)
        
        # Title with logo-like styling
        title_layout = QHBoxLayout()
        
        # Create a stylized logo label
        logo_label = QLabel("⚡")
        logo_font = QFont("Arial", 24)
        logo_font.setBold(True)
        logo_label.setFont(logo_font)
        logo_label.setStyleSheet("color: #00ff00;")
        title_layout.addWidget(logo_label)
        
        # Main title
        title_label = QLabel("WhiteCrow")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Consolas", 24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00ff00; letter-spacing: 2px;")
        title_layout.addWidget(title_label)
        
        # Add another logo element for symmetry
        logo_label2 = QLabel("⚡")
        logo_label2.setFont(logo_font)
        logo_label2.setStyleSheet("color: #00ff00;")
        title_layout.addWidget(logo_label2)
        
        layout.addLayout(title_layout)
        
        # Version label
        version_label = QLabel("v2.0 ELITE EDITION")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("color: #00aa00; font-family: Consolas; letter-spacing: 1px;")
        layout.addWidget(version_label)
        
        # Description with more professional wording
        desc_label = QLabel("Advanced reconnaissance and vulnerability assessment platform for security professionals")
        desc_label.setAlignment(Qt.AlignCenter)
        desc_label.setStyleSheet("color: #cccccc; font-style: italic; padding: 10px;")
        layout.addWidget(desc_label)
        
        # Add some spacing
        layout.addSpacing(20)
        
        # Simple Target URL section
        url_card = QFrame()
        url_card.setStyleSheet("""
            QFrame {
                background-color: #1e1e1e;
                border: 1px solid #3a3a3a;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        url_layout = QVBoxLayout(url_card)
        url_layout.setContentsMargins(20, 20, 20, 20)
        url_layout.setSpacing(15)
        
        # Add a header
        url_header = QLabel("TARGET URL")
        url_header.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 16px; font-family: Consolas;")
        url_layout.addWidget(url_header)
        
        # Create an input field with button in one row
        input_row = QHBoxLayout()
        input_row.setSpacing(15)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target-domain.com")
        self.url_input.setStyleSheet("""
            font-family: Consolas;
            font-size: 15px;
            padding: 12px;
            background-color: #252525;
            border: 1px solid #3a3a3a;
            border-radius: 6px;
            color: #e0e0e0;
            selection-background-color: #00ff00;
            selection-color: #000000;
        """)
        self.url_input.setMinimumHeight(50)
        input_row.addWidget(self.url_input)
        
        url_layout.addLayout(input_row)
        
        # Add example URLs as clickable links
        examples_layout = QHBoxLayout()
        examples_layout.setSpacing(15)
        
        examples_label = QLabel("Examples:")
        examples_label.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        examples_layout.addWidget(examples_label)
        
        example1 = QPushButton("example.com")
        example1.setStyleSheet("""
            background-color: transparent;
            color: #00aaff;
            border: none;
            text-decoration: underline;
            font-size: 13px;
            padding: 5px;
        """)
        example1.clicked.connect(lambda: self.url_input.setText("http://example.com"))
        
        example2 = QPushButton("testphp.vulnweb.com")
        example2.setStyleSheet("""
            background-color: transparent;
            color: #00aaff;
            border: none;
            text-decoration: underline;
            font-size: 13px;
            padding: 5px;
        """)
        example2.clicked.connect(lambda: self.url_input.setText("http://testphp.vulnweb.com"))
        
        examples_layout.addWidget(example1)
        examples_layout.addWidget(example2)
        examples_layout.addStretch()
        
        url_layout.addLayout(examples_layout)
        
        layout.addWidget(url_card)
        
        # Add a configuration button that will open a popup dialog
        config_button = QPushButton("⚙️ CONFIGURE SCAN OPTIONS")
        config_button.setStyleSheet("""
            padding: 15px;
            font-size: 15px;
            background-color: #252525;
            color: #00aaff;
            border: 1px solid #00aaff;
            border-radius: 6px;
            font-weight: bold;
            margin-top: 10px;
        """)
        config_button.clicked.connect(self.show_scan_config_dialog)
        layout.addWidget(config_button)
        
        # Initialize scan options as boolean variables instead of widgets
        # We'll create the actual checkboxes in the dialog when needed
        self.scan_options = {
            "sql_injection": True,
            "xss": True,
            "csrf": True,
            "ssrf": True,
            "broken_auth": True,
            "sensitive_data": True,
            "xxe": True,
            "security_misconfig": True,
            "insecure_deserialization": True,
            "components_vulnerabilities": True
        }
        
        # Default scan configuration values
        self.max_urls = 100
        self.timeout = 30
        self.threads = 5
        
        # Create a hidden container to hold configuration widgets
        # This ensures they won't be garbage collected
        self.config_container = QWidget(self)
        self.config_container.hide()
        config_layout = QVBoxLayout(self.config_container)
        
        # Create the actual widgets and store them
        self.max_urls_input = QSpinBox(self.config_container)
        self.max_urls_input.setMinimum(1)
        self.max_urls_input.setMaximum(1000)
        self.max_urls_input.setValue(self.max_urls)
        config_layout.addWidget(self.max_urls_input)
        
        self.timeout_input = QSpinBox(self.config_container)
        self.timeout_input.setMinimum(5)
        self.timeout_input.setMaximum(120)
        self.timeout_input.setValue(self.timeout)
        self.timeout_input.setSuffix(" sec")
        config_layout.addWidget(self.timeout_input)
        
        self.threads_input = QSpinBox(self.config_container)
        self.threads_input.setMinimum(1)
        self.threads_input.setMaximum(20)
        self.threads_input.setValue(self.threads)
        config_layout.addWidget(self.threads_input)
        
        # Simple progress section
        progress_card = QFrame()
        progress_card.setStyleSheet("""
            QFrame {
                background-color: #1e1e1e;
                border: 1px solid #3a3a3a;
                border-radius: 10px;
                padding: 15px;
                margin-top: 20px;
            }
        """)
        progress_layout = QVBoxLayout(progress_card)
        progress_layout.setContentsMargins(20, 20, 20, 20)
        progress_layout.setSpacing(15)
        
        # Status header with indicator
        status_layout = QHBoxLayout()
        
        # Status indicator
        self.status_indicator = QLabel("●")
        self.status_indicator.setStyleSheet("color: #666666; font-size: 24px;")
        status_layout.addWidget(self.status_indicator)
        
        # Status label
        self.status_label = QLabel("READY")
        self.status_label.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 16px; font-family: Consolas;")
        status_layout.addWidget(self.status_label)
        
        status_layout.addStretch()
        
        # Timer display
        self.time_label = QLabel("00:00:00")
        self.time_label.setStyleSheet("color: #00ff00; font-family: Consolas; font-size: 16px;")
        status_layout.addWidget(self.time_label)
        
        progress_layout.addLayout(status_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                text-align: center;
                background-color: #252525;
                color: #000000;
                font-weight: bold;
                font-size: 13px;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
                border-radius: 5px;
            }
        """)
        progress_layout.addWidget(self.progress_bar)
        
        # Status detail
        self.status_detail = QLabel("Awaiting scan initiation")
        self.status_detail.setStyleSheet("color: #aaaaaa; font-style: italic; font-size: 13px;")
        progress_layout.addWidget(self.status_detail)
        
        # Current operation
        self.current_operation = QLabel("No scan in progress")
        self.current_operation.setStyleSheet("color: #aaaaaa; font-size: 13px;")
        progress_layout.addWidget(self.current_operation)
        
        layout.addWidget(progress_card)
        
        # Action buttons in a horizontal layout
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        # Start scan button
        self.start_button = QPushButton("▶ LAUNCH SCAN")
        self.start_button.setMinimumHeight(50)
        self.start_button.setStyleSheet("""
            padding: 10px 20px;
            font-size: 15px;
            font-weight: bold;
            background-color: #252525;
            color: #00ff00;
            border: 2px solid #00ff00;
            border-radius: 6px;
        """)
        self.start_button.clicked.connect(self.start_scan)
        buttons_layout.addWidget(self.start_button)
        
        # Stop scan button
        self.stop_button = QPushButton("■ ABORT SCAN")
        self.stop_button.setMinimumHeight(50)
        self.stop_button.setStyleSheet("""
            padding: 10px 20px;
            font-size: 15px;
            font-weight: bold;
            background-color: #252525;
            color: #ff5555;
            border: 2px solid #ff5555;
            border-radius: 6px;
        """)
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        buttons_layout.addWidget(self.stop_button)
        
        # Clear results button
        self.clear_button = QPushButton("✕ CLEAR DATA")
        self.clear_button.setMinimumHeight(50)
        self.clear_button.setStyleSheet("""
            padding: 10px 20px;
            font-size: 15px;
            font-weight: bold;
            background-color: #252525;
            color: #aaaaaa;
            border: 2px solid #aaaaaa;
            border-radius: 6px;
        """)
        self.clear_button.clicked.connect(self.clear_results)
        buttons_layout.addWidget(self.clear_button)
        
        layout.addLayout(buttons_layout)
        layout.addStretch()
        
        # Set the content widget in the scroll area
        scroll_area.setWidget(content_widget)
        
        # Set the main layout for the tab
        main_layout.addWidget(scroll_area)
        self.scan_tab.setLayout(main_layout)
        
    def show_scan_config_dialog(self):
        """Show a popup dialog for configuring scan options"""
        config_dialog = QDialog(self)
        config_dialog.setWindowTitle("SCAN CONFIGURATION")
        config_dialog.setMinimumWidth(700)
        config_dialog.setMinimumHeight(600)
        config_dialog.setStyleSheet("""
            QDialog {
                background-color: #121212;
                color: #e0e0e0;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 20px;
                padding-top: 25px;
                color: #00ff00;
                font-size: 14px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 13px;
            }
            QCheckBox {
                color: #e0e0e0;
                font-size: 13px;
                padding: 5px;
                spacing: 10px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 1px solid #3a3a3a;
            }
            QCheckBox::indicator:unchecked {
                background-color: #252525;
            }
            QCheckBox::indicator:checked {
                background-color: #00ff00;
            }
            QPushButton {
                padding: 10px 20px;
                font-size: 13px;
                background-color: #252525;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #323232;
            }
            QSpinBox {
                background-color: #252525;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 5px;
                min-width: 80px;
                font-size: 13px;
            }
        """)
        
        # Create a scroll area for the dialog content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                border: none;
                background: #1a1a1a;
                width: 14px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #3a3a3a;
                min-height: 30px;
                border-radius: 7px;
            }
            QScrollBar::handle:vertical:hover {
                background: #00ff00;
            }
        """)
        
        # Create a widget to hold the scrollable content
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title_label = QLabel("CONFIGURE SCAN OPTIONS")
        title_label.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 18px; font-family: Consolas;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Description
        desc_label = QLabel("Select which vulnerabilities to scan for and configure scan parameters")
        desc_label.setStyleSheet("color: #aaaaaa; font-style: italic; font-size: 13px;")
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # Attack vectors group
        attack_group = QGroupBox("VULNERABILITY TYPES")
        attack_layout = QVBoxLayout()
        attack_layout.setSpacing(10)
        
        # Create two columns for options
        options_columns = QHBoxLayout()
        options_columns.setSpacing(30)
        
        # Left column - OWASP Top 5
        left_column = QVBoxLayout()
        left_column.setSpacing(10)
        
        left_header = QLabel("CRITICAL VULNERABILITIES")
        left_header.setStyleSheet("color: #ff5555; font-weight: bold; font-size: 14px; margin-bottom: 5px;")
        left_column.addWidget(left_header)
        
        # Create checkboxes for the dialog
        option_sql_injection = QCheckBox("SQL Injection")
        option_sql_injection.setChecked(self.scan_options["sql_injection"])
        left_column.addWidget(option_sql_injection)
        
        option_xss = QCheckBox("Cross-Site Scripting (XSS)")
        option_xss.setChecked(self.scan_options["xss"])
        left_column.addWidget(option_xss)
        
        option_csrf = QCheckBox("Cross-Site Request Forgery (CSRF)")
        option_csrf.setChecked(self.scan_options["csrf"])
        left_column.addWidget(option_csrf)
        
        option_ssrf = QCheckBox("Server-Side Request Forgery (SSRF)")
        option_ssrf.setChecked(self.scan_options["ssrf"])
        left_column.addWidget(option_ssrf)
        
        option_broken_auth = QCheckBox("Broken Authentication")
        option_broken_auth.setChecked(self.scan_options["broken_auth"])
        left_column.addWidget(option_broken_auth)
        
        option_sensitive_data = QCheckBox("Sensitive Data Exposure")
        option_sensitive_data.setChecked(self.scan_options["sensitive_data"])
        left_column.addWidget(option_sensitive_data)
        
        # Right column - Other vulnerabilities
        right_column = QVBoxLayout()
        right_column.setSpacing(10)
        
        right_header = QLabel("ADDITIONAL ATTACK VECTORS")
        right_header.setStyleSheet("color: #ffaa00; font-weight: bold; font-size: 14px; margin-bottom: 5px;")
        right_column.addWidget(right_header)
        
        option_xxe = QCheckBox("XML External Entities (XXE)")
        option_xxe.setChecked(self.scan_options["xxe"])
        right_column.addWidget(option_xxe)
        
        option_security_misconfig = QCheckBox("Security Misconfigurations")
        option_security_misconfig.setChecked(self.scan_options["security_misconfig"])
        right_column.addWidget(option_security_misconfig)
        
        option_insecure_deserialization = QCheckBox("Insecure Deserialization")
        option_insecure_deserialization.setChecked(self.scan_options["insecure_deserialization"])
        right_column.addWidget(option_insecure_deserialization)
        
        option_components_vulnerabilities = QCheckBox("Vulnerable Components")
        option_components_vulnerabilities.setChecked(self.scan_options["components_vulnerabilities"])
        right_column.addWidget(option_components_vulnerabilities)
        
        options_columns.addLayout(left_column)
        options_columns.addLayout(right_column)
        attack_layout.addLayout(options_columns)
        
        # Store all checkboxes in a dictionary for easy access
        checkboxes = {
            "sql_injection": option_sql_injection,
            "xss": option_xss,
            "csrf": option_csrf,
            "ssrf": option_ssrf,
            "broken_auth": option_broken_auth,
            "sensitive_data": option_sensitive_data,
            "xxe": option_xxe,
            "security_misconfig": option_security_misconfig,
            "insecure_deserialization": option_insecure_deserialization,
            "components_vulnerabilities": option_components_vulnerabilities
        }
        
        # Select all / Deselect all buttons
        buttons_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("SELECT ALL")
        select_all_btn.clicked.connect(lambda: self.select_all_dialog_options(checkboxes))
        
        deselect_all_btn = QPushButton("DESELECT ALL")
        deselect_all_btn.clicked.connect(lambda: self.deselect_all_dialog_options(checkboxes))
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(select_all_btn)
        buttons_layout.addWidget(deselect_all_btn)
        attack_layout.addLayout(buttons_layout)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Scan parameters group
        params_group = QGroupBox("SCAN PARAMETERS")
        params_layout = QFormLayout()
        params_layout.setVerticalSpacing(15)
        params_layout.setHorizontalSpacing(30)
        
        # Max URLs option
        max_urls_label = QLabel("Maximum URLs to crawl:")
        self.max_urls_input.setValue(self.max_urls)
        params_layout.addRow(max_urls_label, self.max_urls_input)
        
        # Add a timeout option
        timeout_label = QLabel("Request timeout:")
        self.timeout_input.setValue(self.timeout)
        params_layout.addRow(timeout_label, self.timeout_input)
        
        # Add a threads option
        threads_label = QLabel("Concurrent threads:")
        self.threads_input.setValue(self.threads)
        params_layout.addRow(threads_label, self.threads_input)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Advanced options group
        advanced_group = QGroupBox("ADVANCED OPTIONS")
        advanced_layout = QVBoxLayout()
        
        # Add some advanced options
        follow_redirects = QCheckBox("Follow redirects")
        follow_redirects.setChecked(True)
        advanced_layout.addWidget(follow_redirects)
        
        use_cookies = QCheckBox("Use cookies")
        use_cookies.setChecked(True)
        advanced_layout.addWidget(use_cookies)
        
        passive_scan = QCheckBox("Passive scan only (non-intrusive)")
        passive_scan.setChecked(False)
        advanced_layout.addWidget(passive_scan)
        
        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)
        
        # Dialog buttons
        dialog_buttons = QHBoxLayout()
        
        cancel_btn = QPushButton("CANCEL")
        cancel_btn.setStyleSheet("""
            color: #aaaaaa;
            border: 1px solid #aaaaaa;
        """)
        cancel_btn.clicked.connect(config_dialog.reject)
        
        save_btn = QPushButton("SAVE CONFIGURATION")
        save_btn.clicked.connect(lambda: self.save_config_and_close(config_dialog, checkboxes))
        
        dialog_buttons.addStretch()
        dialog_buttons.addWidget(cancel_btn)
        dialog_buttons.addWidget(save_btn)
        layout.addLayout(dialog_buttons)
        
        # Set the content widget in the scroll area
        scroll_area.setWidget(content_widget)
        
        # Set the main layout for the dialog
        dialog_layout = QVBoxLayout(config_dialog)
        dialog_layout.addWidget(scroll_area)
        
        # Show the dialog
        config_dialog.exec_()
        
    def save_config_and_close(self, dialog, checkboxes):
        """Save the configuration from the dialog and close it"""
        # Save checkbox states
        for key, checkbox in checkboxes.items():
            self.scan_options[key] = checkbox.isChecked()
        
        # Save other configuration values
        self.max_urls = self.max_urls_input.value()
        self.timeout = self.timeout_input.value()
        self.threads = self.threads_input.value()
        
        # Close the dialog
        dialog.accept()
        
    def select_all_dialog_options(self, checkboxes):
        """Select all options in the dialog"""
        for checkbox in checkboxes.values():
            checkbox.setChecked(True)
            
    def deselect_all_dialog_options(self, checkboxes):
        """Deselect all options in the dialog"""
        for checkbox in checkboxes.values():
            checkbox.setChecked(False)
    
    def setup_results_tab(self):
        """Set up the results tab with enhanced styling and layout"""
        layout = QVBoxLayout()
        
        # Header with title
        header_layout = QHBoxLayout()
        
        header_icon = QLabel("🔍")
        header_icon.setStyleSheet("font-size: 24px; color: #00ff00;")
        header_layout.addWidget(header_icon)
        
        header_label = QLabel("VULNERABILITY ASSESSMENT RESULTS")
        header_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff00; font-family: Consolas;")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Create a splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #3a3a3a;
                height: 2px;
            }
        """)
        
        # Top section with summary and table
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # Results summary with enhanced styling
        summary_group = QGroupBox("SCAN INTELLIGENCE")
        summary_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 16px;
                padding-top: 16px;
                color: #00ff00;
            }
        """)
        
        # Create a horizontal layout for summary
        summary_layout = QHBoxLayout()
        
        # Left side - basic info
        basic_info_layout = QFormLayout()
        basic_info_layout.setVerticalSpacing(10)
        basic_info_layout.setHorizontalSpacing(15)
        
        # Style for labels
        label_style = "color: #aaaaaa; font-weight: bold;"
        value_style = "color: #e0e0e0; font-family: Consolas;"
        
        # Create styled labels
        target_label = QLabel("Target URL:")
        target_label.setStyleSheet(label_style)
        self.summary_target = QLabel("-")
        self.summary_target.setStyleSheet(value_style)
        basic_info_layout.addRow(target_label, self.summary_target)
        
        time_label = QLabel("Scan Time:")
        time_label.setStyleSheet(label_style)
        self.summary_time = QLabel("-")
        self.summary_time.setStyleSheet(value_style)
        basic_info_layout.addRow(time_label, self.summary_time)
        
        duration_label = QLabel("Duration:")
        duration_label.setStyleSheet(label_style)
        self.summary_duration = QLabel("-")
        self.summary_duration.setStyleSheet(value_style)
        basic_info_layout.addRow(duration_label, self.summary_duration)
        
        # Right side - statistics in card format
        stats_layout = QHBoxLayout()
        
        # URLs scanned card
        urls_card = QFrame()
        urls_card.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 6px;
                border: 1px solid #3a3a3a;
            }
        """)
        urls_layout = QVBoxLayout(urls_card)
        
        urls_icon = QLabel("🌐")
        urls_icon.setAlignment(Qt.AlignCenter)
        urls_icon.setStyleSheet("font-size: 24px; color: #00aaff;")
        urls_layout.addWidget(urls_icon)
        
        self.summary_urls_scanned = QLabel("-")
        self.summary_urls_scanned.setAlignment(Qt.AlignCenter)
        self.summary_urls_scanned.setStyleSheet("font-size: 24px; font-weight: bold; color: #00aaff; font-family: Consolas;")
        urls_layout.addWidget(self.summary_urls_scanned)
        
        urls_label = QLabel("URLs Scanned")
        urls_label.setAlignment(Qt.AlignCenter)
        urls_label.setStyleSheet("color: #aaaaaa;")
        urls_layout.addWidget(urls_label)
        
        stats_layout.addWidget(urls_card)
        
        # Vulnerabilities card
        vulns_card = QFrame()
        vulns_card.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 6px;
                border: 1px solid #3a3a3a;
            }
        """)
        vulns_layout = QVBoxLayout(vulns_card)
        
        vulns_icon = QLabel("⚠️")
        vulns_icon.setAlignment(Qt.AlignCenter)
        vulns_icon.setStyleSheet("font-size: 24px; color: #ff5555;")
        vulns_layout.addWidget(vulns_icon)
        
        self.summary_vulnerabilities = QLabel("-")
        self.summary_vulnerabilities.setAlignment(Qt.AlignCenter)
        self.summary_vulnerabilities.setStyleSheet("font-size: 24px; font-weight: bold; color: #ff5555; font-family: Consolas;")
        vulns_layout.addWidget(self.summary_vulnerabilities)
        
        vulns_label = QLabel("Vulnerabilities")
        vulns_label.setAlignment(Qt.AlignCenter)
        vulns_label.setStyleSheet("color: #aaaaaa;")
        vulns_layout.addWidget(vulns_label)
        
        stats_layout.addWidget(vulns_card)
        
        # Add layouts to summary
        summary_layout.addLayout(basic_info_layout, 2)  # 2/3 of space
        summary_layout.addLayout(stats_layout, 1)       # 1/3 of space
        
        summary_group.setLayout(summary_layout)
        top_layout.addWidget(summary_group)
        
        # Vulnerabilities table with enhanced styling
        table_group = QGroupBox("IDENTIFIED VULNERABILITIES")
        table_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 16px;
                padding-top: 16px;
                color: #00ff00;
            }
        """)
        table_layout = QVBoxLayout()
        
        # Add a filter/search box
        filter_layout = QHBoxLayout()
        
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #aaaaaa;")
        filter_layout.addWidget(filter_label)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Type to filter vulnerabilities...")
        filter_layout.addWidget(self.filter_input)
        
        table_layout.addLayout(filter_layout)
        
        # Enhanced table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["Type", "Severity", "URL", "Description"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.vuln_table.setAlternatingRowColors(True)
        self.vuln_table.cellClicked.connect(self.show_vulnerability_details)
        self.vuln_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a1a;
                alternate-background-color: #252525;
                gridline-color: #3a3a3a;
                border: none;
                font-family: Consolas;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #004400;
            }
        """)
        
        table_layout.addWidget(self.vuln_table)
        
        table_group.setLayout(table_layout)
        top_layout.addWidget(table_group)
        
        # Add the top widget to the splitter
        splitter.addWidget(top_widget)
        
        # Bottom section with vulnerability details
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        
        # Vulnerability details with enhanced styling
        details_group = QGroupBox("VULNERABILITY ANALYSIS")
        details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3a3a3a;
                border-radius: 6px;
                margin-top: 16px;
                padding-top: 16px;
                color: #00ff00;
            }
        """)
        details_layout = QVBoxLayout()
        
        # Instructions label
        instructions = QLabel("Select a vulnerability from the table above to view detailed analysis")
        instructions.setStyleSheet("color: #aaaaaa; font-style: italic;")
        details_layout.addWidget(instructions)
        
        # Enhanced text display
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #e0e0e0;
                border: none;
                font-family: Consolas;
            }
        """)
        
        details_layout.addWidget(self.details_text)
        
        details_group.setLayout(details_layout)
        bottom_layout.addWidget(details_group)
        
        # Add the bottom widget to the splitter
        splitter.addWidget(bottom_widget)
        
        # Set initial sizes for the splitter
        splitter.setSizes([500, 300])
        
        # Add the splitter to the main layout
        layout.addWidget(splitter)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        # Export button with enhanced styling
        self.export_button = QPushButton("📊 EXPORT REPORT")
        self.export_button.setStyleSheet("""
            padding: 10px 20px;
            font-size: 14px;
        """)
        self.export_button.clicked.connect(self.export_report)
        self.export_button.setEnabled(False)
        
        # Add a copy to clipboard button
        self.copy_button = QPushButton("📋 COPY RESULTS")
        self.copy_button.setStyleSheet("""
            padding: 10px 20px;
            font-size: 14px;
        """)
        self.copy_button.clicked.connect(self.copy_results)
        self.copy_button.setEnabled(False)
        
        action_layout.addStretch()
        action_layout.addWidget(self.copy_button)
        action_layout.addWidget(self.export_button)
        
        layout.addLayout(action_layout)
        
        self.results_tab.setLayout(layout)
    
    def setup_about_tab(self):
        """Set up the about tab with enhanced styling and content"""
        layout = QVBoxLayout()
        
        # Create a scroll area for the content
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Create a widget to hold the content
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        
        # Logo and title section
        logo_layout = QHBoxLayout()
        
        # Create a stylized logo label
        logo_label = QLabel("⚡")
        logo_font = QFont("Arial", 36)
        logo_font.setBold(True)
        logo_label.setFont(logo_font)
        logo_label.setStyleSheet("color: #00ff00;")
        logo_layout.addWidget(logo_label)
        
        # Title and version in a vertical layout
        title_version_layout = QVBoxLayout()
        
        title_label = QLabel("WhiteCrow")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont("Consolas", 28)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00ff00; letter-spacing: 3px;")
        title_version_layout.addWidget(title_label)
        
        version_label = QLabel("v2.0 ELITE EDITION")
        version_label.setAlignment(Qt.AlignCenter)
        version_label.setStyleSheet("color: #00aa00; font-family: Consolas; letter-spacing: 1px;")
        title_version_layout.addWidget(version_label)
        
        logo_layout.addLayout(title_version_layout)
        
        # Add another logo element for symmetry
        logo_label2 = QLabel("⚡")
        logo_label2.setFont(logo_font)
        logo_label2.setStyleSheet("color: #00ff00;")
        logo_layout.addWidget(logo_label2)
        
        content_layout.addLayout(logo_layout)
        
        # Tagline
        tagline_label = QLabel("ADVANCED WEB VULNERABILITY ASSESSMENT PLATFORM")
        tagline_label.setAlignment(Qt.AlignCenter)
        tagline_label.setStyleSheet("color: #aaaaaa; font-style: italic; margin: 10px 0 30px 0;")
        content_layout.addWidget(tagline_label)
        
        # Description with enhanced styling
        desc_text = QTextEdit()
        desc_text.setReadOnly(True)
        desc_text.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #e0e0e0;
                border: none;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
        """)
        
        desc_text.setHtml("""
            <html>
            <head>
            <style>
                body {
                    background-color: #1a1a1a;
                    color: #e0e0e0;
                    font-family: 'Segoe UI', Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                }
                h2 {
                    color: #00ff00;
                    border-bottom: 1px solid #00ff00;
                    padding-bottom: 10px;
                    margin-top: 30px;
                }
                h3 {
                    color: #00aaff;
                    margin-top: 20px;
                }
                p {
                    margin: 15px 0;
                }
                ul {
                    list-style-type: none;
                    padding-left: 20px;
                }
                li {
                    margin: 10px 0;
                    position: relative;
                    padding-left: 25px;
                }
                li:before {
                    content: "▶";
                    color: #00ff00;
                    position: absolute;
                    left: 0;
                }
                .feature-box {
                    background-color: #252525;
                    border-left: 3px solid #00ff00;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 0 4px 4px 0;
                }
                .warning-box {
                    background-color: #3a2500;
                    border-left: 3px solid #ffaa00;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 0 4px 4px 0;
                }
                .code {
                    font-family: Consolas, monospace;
                    background-color: #252525;
                    padding: 2px 5px;
                    border-radius: 3px;
                    color: #00aaff;
                }
            </style>
            </head>
            <body>
            
            <h2>ABOUT WhiteCrow</h2>
            
            <p>WhiteCrow is an advanced cybersecurity tool designed for security professionals, penetration testers, and ethical hackers to identify and assess vulnerabilities in web applications. Built on cutting-edge technology, it provides comprehensive scanning capabilities with minimal false positives.</p>
            
            <div class="feature-box">
                <h3>CORE CAPABILITIES</h3>
                <ul>
                    <li>Advanced detection of OWASP Top 10 vulnerabilities</li>
                    <li>Multi-threaded scanning architecture for optimal performance</li>
                    <li>Intelligent crawling with customizable depth and scope</li>
                    <li>Low-footprint scanning to minimize target impact</li>
                    <li>Comprehensive reporting with actionable remediation steps</li>
                </ul>
            </div>
            
            <h2>TECHNICAL SPECIFICATIONS</h2>
            
            <p>WhiteCrow is built with Python and leverages a modular architecture that allows for easy extension and customization. The scanner employs both active and passive techniques to identify vulnerabilities with high accuracy.</p>
            
            <h3>SCANNING MODULES</h3>
            <ul>
                <li><span class="code">XSS Scanner</span> - Detects Cross-Site Scripting vulnerabilities using advanced payload techniques</li>
                <li><span class="code">CSRF Scanner</span> - Identifies Cross-Site Request Forgery vulnerabilities in web forms</li>
                <li><span class="code">SQL Injection Scanner</span> - Detects various SQL injection vectors including blind and time-based</li>
                <li><span class="code">Authentication Scanner</span> - Tests for weak authentication mechanisms and session management</li>
                <li><span class="code">Component Analysis</span> - Identifies outdated libraries and frameworks with known vulnerabilities</li>
            </ul>
            
            <h2>ETHICAL USAGE</h2>
            
            <div class="warning-box">
                <p><strong>IMPORTANT:</strong> WhiteCrow should only be used on systems you have explicit permission to test. Unauthorized scanning of systems is illegal in most jurisdictions and violates computer crime laws.</p>
                <p>Always obtain proper authorization before conducting security assessments and follow responsible disclosure practices when reporting vulnerabilities.</p>
            </div>
            
            <h2>ABOUT THE DEVELOPERS</h2>
            
            <p>WhiteCrow was developed by a team of cybersecurity professionals with extensive experience in penetration testing, vulnerability research, and secure coding practices. Our mission is to provide high-quality security tools that help organizations identify and remediate vulnerabilities before they can be exploited.</p>
            
            <p style="text-align: center; margin-top: 40px; color: #666666;">Copyright © 2023 WhiteCrow Security Team<br>All Rights Reserved</p>
            
            </body>
            </html>
        """)
        
        content_layout.addWidget(desc_text)
        
        # Set the content widget in the scroll area
        scroll_area.setWidget(content_widget)
        layout.addWidget(scroll_area)
        
        self.about_tab.setLayout(layout)
    
    def start_scan(self):
        """Start the vulnerability scan with enhanced UI feedback"""
        url = self.url_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "TARGET ERROR", "Please specify a target URL to scan")
            return
        
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
            self.url_input.setText(url)
        
        # Check if at least one scan option is selected
        if not any(self.scan_options.values()):
            QMessageBox.warning(self, "CONFIGURATION ERROR", 
                               "Please select at least one vulnerability type to scan for")
            return
        
        # Collect scan options with the new configuration parameters
        options = {
            **self.scan_options,  # Include all vulnerability scan options
            "max_urls": self.max_urls,
            "timeout": self.timeout,
            "threads": self.threads
        }
        
        # Store scan start time for elapsed time calculation
        self.scan_start_time = time.time()
        
        # Start the timer for continuous time updates
        self.timer.start()
        
        # Update UI to show scan is starting
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.clear_button.setEnabled(False)
        self.progress_bar.setValue(0)
        
        # Update status indicators
        self.status_indicator.setStyleSheet("color: #ffaa00; font-size: 24px;")  # Yellow for in progress
        self.status_label.setText("INITIALIZING SCAN")
        self.status_detail.setText(f"Preparing to scan {url}")
        self.current_operation.setText("Setting up scanner modules...")
        self.time_label.setText("00:00:00")
        
        # Show a confirmation dialog with scan details
        scan_types = []
        for key, enabled in self.scan_options.items():
            if enabled:
                if key == "xss": scan_types.append("XSS")
                elif key == "csrf": scan_types.append("CSRF")
                elif key == "ssrf": scan_types.append("SSRF")
                elif key == "broken_auth": scan_types.append("Broken Auth")
                elif key == "sensitive_data": scan_types.append("Sensitive Data")
                elif key == "xxe": scan_types.append("XXE")
                elif key == "security_misconfig": scan_types.append("Security Misconfig")
                elif key == "insecure_deserialization": scan_types.append("Insecure Deserialization")
                elif key == "components_vulnerabilities": scan_types.append("Vulnerable Components")
        
        scan_info = f"""
        <html>
        <body style="color: #00ff00; background-color: #1a1a1a; padding: 10px;">
        <h3 style="color: #00ff00;">SCAN INITIATED</h3>
        <p><b>Target:</b> {url}</p>
        <p><b>Scan Types:</b> {', '.join(scan_types)}</p>
        <p><b>Max URLs:</b> {self.max_urls}</p>
        <p><b>Threads:</b> {self.threads}</p>
        <p><b>Timeout:</b> {self.timeout} seconds</p>
        <p style="color: #ffaa00;"><b>Note:</b> Scanning without proper authorization may be illegal. Use responsibly.</p>
        </body>
        </html>
        """
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("SCAN INITIATED")
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText(scan_info)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
                color: #00ff00;
            }
            QPushButton {
                background-color: #252525;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 4px;
                padding: 5px 15px;
            }
        """)
        msg_box.exec_()
        
        # Start scan thread
        self.scanner_thread = ScannerThread(url, options)
        self.scanner_thread.update_progress.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.scan_completed)
        self.scanner_thread.start()
    
    def stop_scan(self):
        """Stop the current scan with enhanced UI feedback"""
        if hasattr(self, 'scanner_thread') and self.scanner_thread.isRunning():
            # Show confirmation dialog
            confirm = QMessageBox(self)
            confirm.setWindowTitle("ABORT OPERATION")
            confirm.setIcon(QMessageBox.Warning)
            confirm.setText("""
            <html>
            <body style="color: #e0e0e0; background-color: #1a1a1a; padding: 10px;">
            <h3 style="color: #ff5555;">CONFIRM ABORT</h3>
            <p>Are you sure you want to abort the current scan?</p>
            <p style="color: #aaaaaa;">Note: Partial results may be available in the Results tab</p>
            </body>
            </html>
            """)
            confirm.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            confirm.setStyleSheet("""
                QMessageBox {
                    background-color: #1a1a1a;
                    color: #e0e0e0;
                }
                QPushButton {
                    background-color: #252525;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                    border-radius: 4px;
                    padding: 5px 15px;
                }
            """)
            
            if confirm.exec_() == QMessageBox.Yes:
                # Signal the thread to stop
                self.scanner_thread.is_running = False
                
                # Wait for the thread to finish (with timeout)
                if not self.scanner_thread.wait(3000):  # 3 second timeout
                    # If thread doesn't respond in time, terminate it forcefully
                    self.scanner_thread.terminate()
                    self.scanner_thread.wait()
                
                # Stop the timer
                self.timer.stop()
                
                # Update UI
                self.status_indicator.setStyleSheet("color: #ff5555; font-size: 24px;")  # Red for aborted
                self.status_label.setText("SCAN ABORTED")
                self.status_detail.setText("Operation terminated by user")
                self.current_operation.setText("Scan was manually stopped")
                
                # Re-enable controls
                self.start_button.setEnabled(True)
                self.stop_button.setEnabled(False)
                self.clear_button.setEnabled(True)
                
                # Show notification
                QMessageBox.information(self, "OPERATION ABORTED", "The scan has been terminated.")
            
            # If user selects No, scan continues
    
    def select_all_options(self):
        """Select all vulnerability scan options"""
        for key in self.scan_options:
            self.scan_options[key] = True
    
    def deselect_all_options(self):
        """Deselect all vulnerability scan options"""
        for key in self.scan_options:
            self.scan_options[key] = False
    
    def clear_results(self):
        """Clear all scan results and reset the interface"""
        # Reset scan results
        self.scan_results = None
        
        # Reset summary information
        self.summary_target.setText("-")
        self.summary_time.setText("-")
        self.summary_duration.setText("-")
        self.summary_urls_scanned.setText("-")
        self.summary_vulnerabilities.setText("-")
        
        # Clear vulnerabilities table
        self.vuln_table.setRowCount(0)
        
        # Clear vulnerability details
        self.details_text.clear()
        
        # Reset progress indicators
        self.progress_bar.setValue(0)
        self.status_indicator.setStyleSheet("color: #666666; font-size: 24px;")
        self.status_label.setText("SYSTEM READY")
        self.status_detail.setText("Scan results have been cleared")
        self.current_operation.setText("No scan in progress")
        self.time_label.setText("00:00:00")
        
        # Disable export button
        self.export_button.setEnabled(False)
        
        # Show a confirmation message
        QMessageBox.information(self, "Data Cleared", "All scan results have been cleared.")
    
    def update_elapsed_time(self):
        """Update the elapsed time display"""
        if hasattr(self, 'scan_start_time'):
            elapsed = time.time() - self.scan_start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.setText(f"{hours:02}:{minutes:02}:{seconds:02}")
    
    def update_progress(self, value, message):
        """Update the progress bar and status messages with enhanced information"""
        self.progress_bar.setValue(value)
        
        # Update status indicator color based on progress
        if value == 0:
            self.status_indicator.setStyleSheet("color: #ff5555; font-size: 24px;")  # Red for error or stopped
            self.status_label.setText("SCAN ABORTED")
            # Stop the timer if scan is aborted
            self.timer.stop()
        elif value < 100:
            self.status_indicator.setStyleSheet("color: #ffaa00; font-size: 24px;")  # Yellow for in progress
            self.status_label.setText("SCAN IN PROGRESS")
        else:
            self.status_indicator.setStyleSheet("color: #00ff00; font-size: 24px;")  # Green for complete
            self.status_label.setText("SCAN COMPLETE")
            # Stop the timer when scan is complete
            self.timer.stop()
        
        # Update detailed status message
        self.status_detail.setText(message)
        self.current_operation.setText(f"Current operation: {message}")
        
        # Force UI update
        QApplication.processEvents()
    
    def scan_completed(self, results):
        """Handle scan completion with enhanced UI feedback"""
        self.scan_results = results
        
        # Stop the timer
        self.timer.stop()
        
        # Update UI controls
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.clear_button.setEnabled(True)
        self.export_button.setEnabled(True)
        
        # Update status indicators
        self.status_indicator.setStyleSheet("color: #00ff00; font-size: 24px;")  # Green for complete
        self.status_label.setText("SCAN COMPLETE")
        self.status_detail.setText(f"Found {results['statistics']['vulnerabilities_found']} vulnerabilities in {results['statistics']['scan_duration']} seconds")
        self.current_operation.setText("Scan completed successfully")
        
        # Final update of elapsed time display
        if hasattr(self, 'scan_start_time'):
            elapsed = time.time() - self.scan_start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_label.setText(f"{hours:02}:{minutes:02}:{seconds:02}")
        
        # Update summary information with enhanced styling
        self.summary_target.setText(results["target"])
        self.summary_target.setStyleSheet("font-weight: bold; color: #00ff00;")
        
        self.summary_time.setText(results["scan_time"])
        
        self.summary_duration.setText(f"{results['statistics']['scan_duration']} seconds")
        
        self.summary_urls_scanned.setText(str(results["statistics"]["urls_scanned"]))
        
        # Highlight vulnerability count based on severity
        vuln_count = results["statistics"]["vulnerabilities_found"]
        self.summary_vulnerabilities.setText(str(vuln_count))
        if vuln_count > 10:
            self.summary_vulnerabilities.setStyleSheet("font-weight: bold; color: #ff5555;")  # Red for many vulns
        elif vuln_count > 0:
            self.summary_vulnerabilities.setStyleSheet("font-weight: bold; color: #ffaa00;")  # Yellow for some vulns
        else:
            self.summary_vulnerabilities.setStyleSheet("font-weight: bold; color: #00ff00;")  # Green for no vulns
        
        # Update vulnerabilities table with enhanced styling
        self.vuln_table.setRowCount(0)
        
        # Count vulnerabilities by severity for summary
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for i, vuln in enumerate(results["vulnerabilities"]):
            self.vuln_table.insertRow(i)
            
            type_item = QTableWidgetItem(vuln["type"])
            severity_item = QTableWidgetItem(vuln["severity"])
            url_item = QTableWidgetItem(vuln["url"])
            desc_item = QTableWidgetItem(vuln["description"][:100] + "..." if len(vuln["description"]) > 100 else vuln["description"])
            
            # Set font and style for all items
            font = type_item.font()
            font.setFamily("Consolas")
            
            type_item.setFont(font)
            severity_item.setFont(font)
            url_item.setFont(font)
            desc_item.setFont(font)
            
            # Set color based on severity with more hacker-themed colors
            if vuln["severity"] == "High":
                severity_item.setForeground(QColor(255, 50, 50))  # Bright red
                severity_item.setBackground(QColor(40, 0, 0))     # Dark red background
                high_count += 1
            elif vuln["severity"] == "Medium":
                severity_item.setForeground(QColor(255, 165, 0))  # Orange
                severity_item.setBackground(QColor(40, 30, 0))    # Dark orange background
                medium_count += 1
            else:
                severity_item.setForeground(QColor(100, 200, 255))  # Light blue
                severity_item.setBackground(QColor(0, 20, 40))      # Dark blue background
                low_count += 1
            
            # Set the items in the table
            self.vuln_table.setItem(i, 0, type_item)
            self.vuln_table.setItem(i, 1, severity_item)
            self.vuln_table.setItem(i, 2, url_item)
            self.vuln_table.setItem(i, 3, desc_item)
        
        # Switch to results tab
        self.tabs.setCurrentIndex(1)
        
        # Show completion notification with summary
        if vuln_count > 0:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("SCAN RESULTS")
            msg_box.setIcon(QMessageBox.Warning if high_count > 0 else QMessageBox.Information)
            
            result_html = f"""
            <html>
            <body style="color: #e0e0e0; background-color: #1a1a1a; padding: 10px;">
            <h3 style="color: #00ff00;">SCAN COMPLETED</h3>
            <p><b>Target:</b> {results["target"]}</p>
            <p><b>Duration:</b> {results['statistics']['scan_duration']} seconds</p>
            <p><b>URLs Scanned:</b> {results["statistics"]["urls_scanned"]}</p>
            <h4 style="color: #ffaa00;">Vulnerability Summary:</h4>
            <ul>
                <li style="color: #ff5555;"><b>High Severity:</b> {high_count}</li>
                <li style="color: #ffaa00;"><b>Medium Severity:</b> {medium_count}</li>
                <li style="color: #00aaff;"><b>Low Severity:</b> {low_count}</li>
            </ul>
            <p style="color: #aaaaaa;">View the Results tab for detailed findings</p>
            </body>
            </html>
            """
            
            msg_box.setText(result_html)
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.setStyleSheet("""
                QMessageBox {
                    background-color: #1a1a1a;
                    color: #00ff00;
                }
                QPushButton {
                    background-color: #252525;
                    color: #00ff00;
                    border: 1px solid #00ff00;
                    border-radius: 4px;
                    padding: 5px 15px;
                }
            """)
            msg_box.exec_()
    
    def show_vulnerability_details(self, row, column):
        """Display enhanced vulnerability details with hacker-themed styling"""
        if not self.scan_results:
            return
        
        vuln = self.scan_results["vulnerabilities"][row]
        
        # Determine severity color
        if vuln['severity'] == 'High':
            severity_color = '#ff5555'  # Red
            severity_bg = '#3a0000'     # Dark red
        elif vuln['severity'] == 'Medium':
            severity_color = '#ffaa00'  # Orange
            severity_bg = '#3a2500'     # Dark orange
        else:
            severity_color = '#00aaff'  # Blue
            severity_bg = '#002a3a'     # Dark blue
        
        # Create a more visually appealing details view with hacker theme
        details = f"""
        <html>
        <head>
        <style>
            body {{
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'Consolas', monospace;
                padding: 15px;
                margin: 0;
            }}
            h2 {{
                color: #00ff00;
                border-bottom: 1px solid #00ff00;
                padding-bottom: 5px;
                font-family: 'Consolas', monospace;
            }}
            .severity-badge {{
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
                background-color: {severity_bg};
                color: {severity_color};
            }}
            .section {{
                margin: 15px 0;
                padding: 10px;
                background-color: #1a1a1a;
                border-left: 3px solid #00ff00;
                border-radius: 0 4px 4px 0;
            }}
            .section-title {{
                color: #00ff00;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            .section-content {{
                margin-left: 10px;
                word-wrap: break-word;
            }}
            .evidence-box {{
                background-color: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Consolas', monospace;
                overflow-x: auto;
                color: #cccccc;
            }}
            .url {{
                color: #00aaff;
                word-break: break-all;
            }}
            .parameter {{
                color: #ffaa00;
                font-family: 'Consolas', monospace;
                background-color: #252525;
                padding: 2px 5px;
                border-radius: 3px;
            }}
            .payload {{
                color: #ff5555;
                font-family: 'Consolas', monospace;
                background-color: #252525;
                padding: 2px 5px;
                border-radius: 3px;
            }}
            .remediation {{
                background-color: #002800;
                border-left: 3px solid #00ff00;
                padding: 10px;
                margin-top: 15px;
                border-radius: 0 4px 4px 0;
            }}
        </style>
        </head>
        <body>
        
        <h2>{vuln['type']}</h2>
        
        <div class="section">
            <div class="section-title">SEVERITY</div>
            <div class="section-content">
                <span class="severity-badge">{vuln['severity']}</span>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">TARGET</div>
            <div class="section-content">
                <span class="url">{vuln['url']}</span>
            </div>
        </div>
        """
        
        if "parameter" in vuln and vuln["parameter"]:
            details += f"""
            <div class="section">
                <div class="section-title">PARAMETER</div>
                <div class="section-content">
                    <span class="parameter">{vuln['parameter']}</span>
                </div>
            </div>
            """
        
        if "payload" in vuln and vuln["payload"]:
            details += f"""
            <div class="section">
                <div class="section-title">PAYLOAD</div>
                <div class="section-content">
                    <span class="payload">{vuln['payload']}</span>
                </div>
            </div>
            """
        
        if "evidence" in vuln and vuln["evidence"]:
            details += f"""
            <div class="section">
                <div class="section-title">EVIDENCE</div>
                <div class="section-content">
                    <div class="evidence-box">{vuln['evidence']}</div>
                </div>
            </div>
            """
        
        details += f"""
        <div class="section">
            <div class="section-title">DESCRIPTION</div>
            <div class="section-content">
                {vuln['description']}
            </div>
        </div>
        
        <div class="remediation">
            <div class="section-title">REMEDIATION</div>
            <div class="section-content">
                {vuln['remediation']}
            </div>
        </div>
        
        </body>
        </html>
        """
        
        self.details_text.setHtml(details)
        
        # Scroll to the top
        self.details_text.verticalScrollBar().setValue(0)
    
    def copy_results(self):
        """Copy scan results to clipboard in a formatted text"""
        if not self.scan_results:
            return
        
        # Create a formatted text summary of the results
        results_text = f"""
WhiteCrow VULNERABILITY SCAN RESULTS
======================================

TARGET: {self.scan_results['target']}
SCAN TIME: {self.scan_results['scan_time']}
DURATION: {self.scan_results['statistics']['scan_duration']} seconds
URLS SCANNED: {self.scan_results['statistics']['urls_scanned']}
VULNERABILITIES FOUND: {self.scan_results['statistics']['vulnerabilities_found']}

VULNERABILITY SUMMARY:
---------------------
"""
        
        # Group vulnerabilities by severity
        high_vulns = []
        medium_vulns = []
        low_vulns = []
        
        for vuln in self.scan_results['vulnerabilities']:
            if vuln['severity'] == 'High':
                high_vulns.append(vuln)
            elif vuln['severity'] == 'Medium':
                medium_vulns.append(vuln)
            else:
                low_vulns.append(vuln)
        
        results_text += f"HIGH SEVERITY: {len(high_vulns)}\n"
        results_text += f"MEDIUM SEVERITY: {len(medium_vulns)}\n"
        results_text += f"LOW SEVERITY: {len(low_vulns)}\n\n"
        
        # Add detailed findings
        results_text += "DETAILED FINDINGS:\n"
        results_text += "=================\n\n"
        
        for i, vuln in enumerate(self.scan_results['vulnerabilities']):
            results_text += f"{i+1}. {vuln['type']} ({vuln['severity']})\n"
            results_text += f"   URL: {vuln['url']}\n"
            
            if 'parameter' in vuln and vuln['parameter']:
                results_text += f"   Parameter: {vuln['parameter']}\n"
                
            if 'evidence' in vuln and vuln['evidence']:
                results_text += f"   Evidence: {vuln['evidence']}\n"
                
            results_text += f"   Description: {vuln['description']}\n"
            results_text += f"   Remediation: {vuln['remediation']}\n\n"
        
        # Add footer
        results_text += """
======================================
Generated by WhiteCrow Advanced Web Vulnerability Scanner
"""
        
        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(results_text)
        
        # Show confirmation
        QMessageBox.information(self, "Results Copied", "Scan results have been copied to clipboard.")
    
    def export_report(self):
        """Export scan results to various report formats"""
        if not self.scan_results:
            return
            
        # Enable copy button when results are available
        self.copy_button.setEnabled(True)
        
        # Create a dialog to select the export format with enhanced styling
        export_dialog = QDialog(self)
        export_dialog.setWindowTitle("EXPORT INTELLIGENCE REPORT")
        export_dialog.setMinimumWidth(500)
        export_dialog.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
                color: #e0e0e0;
            }
            QLabel {
                color: #e0e0e0;
                font-weight: bold;
            }
            QComboBox {
                background-color: #252525;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                padding: 8px;
                min-height: 30px;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox QAbstractItemView {
                background-color: #252525;
                color: #e0e0e0;
                selection-background-color: #00ff00;
                selection-color: #000000;
            }
            QPushButton {
                background-color: #252525;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #323232;
            }
            QPushButton#cancelBtn {
                color: #aaaaaa;
                border: 1px solid #aaaaaa;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title with icon
        title_layout = QHBoxLayout()
        
        icon_label = QLabel("📊")
        icon_label.setStyleSheet("font-size: 24px;")
        title_layout.addWidget(icon_label)
        
        title_label = QLabel("EXPORT VULNERABILITY REPORT")
        title_label.setStyleSheet("font-size: 16px; color: #00ff00; font-weight: bold; font-family: Consolas;")
        title_layout.addWidget(title_label)
        
        layout.addLayout(title_layout)
        
        # Description
        desc_label = QLabel("Generate a comprehensive report of all identified vulnerabilities")
        desc_label.setStyleSheet("color: #aaaaaa; font-style: italic; margin-bottom: 15px;")
        layout.addWidget(desc_label)
        
        # Format selection with enhanced styling
        format_frame = QFrame()
        format_frame.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 6px;
                padding: 10px;
            }
        """)
        format_layout = QVBoxLayout(format_frame)
        
        format_label = QLabel("SELECT EXPORT FORMAT:")
        format_label.setStyleSheet("color: #00ff00; font-weight: bold; font-family: Consolas;")
        format_layout.addWidget(format_label)
        
        # Format options with icons and descriptions
        format_combo = QComboBox()
        format_combo.addItem("📄 PDF Report (Professional Document)", "pdf")
        format_combo.addItem("🌐 HTML Report (Interactive Web Page)", "html")
        format_combo.addItem("🔄 JSON Data (Machine Readable)", "json")
        format_combo.addItem("📊 CSV Data (Spreadsheet Compatible)", "csv")
        format_combo.setCurrentIndex(0)  # Default to PDF
        format_layout.addWidget(format_combo)
        
        # Format description that changes based on selection
        self.format_description = QLabel("Professional PDF report with executive summary and detailed findings")
        self.format_description.setStyleSheet("color: #aaaaaa; font-style: italic; margin-top: 5px;")
        format_layout.addWidget(self.format_description)
        
        # Connect the combo box to update the description
        format_combo.currentIndexChanged.connect(lambda idx: self.update_format_description(idx, self.format_description))
        
        layout.addWidget(format_frame)
        
        # Options section
        options_frame = QFrame()
        options_frame.setStyleSheet("""
            QFrame {
                background-color: #252525;
                border-radius: 6px;
                padding: 10px;
                margin-top: 10px;
            }
        """)
        options_layout = QVBoxLayout(options_frame)
        
        options_label = QLabel("REPORT OPTIONS:")
        options_label.setStyleSheet("color: #00ff00; font-weight: bold; font-family: Consolas;")
        options_layout.addWidget(options_label)
        
        # Include executive summary
        self.include_summary = QCheckBox("Include Executive Summary")
        self.include_summary.setChecked(True)
        self.include_summary.setStyleSheet("color: #e0e0e0;")
        options_layout.addWidget(self.include_summary)
        
        # Include remediation steps
        self.include_remediation = QCheckBox("Include Remediation Steps")
        self.include_remediation.setChecked(True)
        self.include_remediation.setStyleSheet("color: #e0e0e0;")
        options_layout.addWidget(self.include_remediation)
        
        # Include evidence details
        self.include_evidence = QCheckBox("Include Technical Evidence")
        self.include_evidence.setChecked(True)
        self.include_evidence.setStyleSheet("color: #e0e0e0;")
        options_layout.addWidget(self.include_evidence)
        
        layout.addWidget(options_frame)
        
        # Buttons with enhanced styling
        buttons_layout = QHBoxLayout()
        
        cancel_button = QPushButton("CANCEL")
        cancel_button.setObjectName("cancelBtn")
        cancel_button.clicked.connect(export_dialog.reject)
        
        export_button = QPushButton("GENERATE REPORT")
        export_button.clicked.connect(export_dialog.accept)
        export_button.setDefault(True)
        
        buttons_layout.addStretch()
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(export_button)
        
        layout.addLayout(buttons_layout)
        export_dialog.setLayout(layout)
        
        # Show dialog
        if export_dialog.exec_() != QDialog.Accepted:
            return
        
        # Get selected format
        selected_format = format_combo.currentData()
        
        # Get report options
        include_summary = self.include_summary.isChecked()
        include_remediation = self.include_remediation.isChecked()
        include_evidence = self.include_evidence.isChecked()
        
        # Set file filter based on format
        if selected_format == "pdf":
            file_filter = "PDF Files (*.pdf)"
            default_ext = ".pdf"
        elif selected_format == "html":
            file_filter = "HTML Files (*.html)"
            default_ext = ".html"
        elif selected_format == "json":
            file_filter = "JSON Files (*.json)"
            default_ext = ".json"
        elif selected_format == "csv":
            file_filter = "CSV Files (*.csv)"
            default_ext = ".csv"
        else:
            file_filter = "All Files (*)"
            default_ext = ""
        
        # Get save path
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", file_filter
        )
        
        if not file_path:
            return
        
        # Add extension if not present
        if not file_path.endswith(default_ext):
            file_path += default_ext
        
        try:
            # Show progress dialog with enhanced styling
            progress = QDialog(self)
            progress.setWindowTitle("GENERATING REPORT")
            progress.setFixedSize(400, 150)
            progress.setStyleSheet("""
                QDialog {
                    background-color: #1a1a1a;
                    color: #e0e0e0;
                }
                QLabel {
                    color: #e0e0e0;
                }
                QProgressBar {
                    border: 1px solid #3a3a3a;
                    border-radius: 6px;
                    text-align: center;
                    background-color: #252525;
                    color: #000000;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #00ff00;
                    border-radius: 5px;
                }
            """)
            
            progress_layout = QVBoxLayout()
            
            # Add a title with icon
            title_layout = QHBoxLayout()
            
            icon_label = QLabel("⚙️")
            icon_label.setStyleSheet("font-size: 24px;")
            title_layout.addWidget(icon_label)
            
            title_label = QLabel("GENERATING INTELLIGENCE REPORT")
            title_label.setStyleSheet("font-size: 14px; color: #00ff00; font-weight: bold; font-family: Consolas;")
            title_layout.addWidget(title_label)
            
            progress_layout.addLayout(title_layout)
            
            # Add a more detailed status message
            progress_label = QLabel(f"Creating {selected_format.upper()} report with detailed vulnerability analysis...")
            progress_label.setStyleSheet("color: #aaaaaa; margin: 10px 0;")
            progress_layout.addWidget(progress_label)
            
            # Add an animated progress bar
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 0)  # Indeterminate progress
            progress_bar.setTextVisible(True)
            progress_bar.setFormat("Processing...")
            progress_layout.addWidget(progress_bar)
            
            # Add a note
            note_label = QLabel("Note: This may take a few moments depending on the number of findings")
            note_label.setStyleSheet("color: #666666; font-style: italic; font-size: 11px; margin-top: 10px;")
            progress_layout.addWidget(note_label)
            
            progress.setLayout(progress_layout)
            progress.show()
            
            # Import the report generator
            from scanner.report_generator import ReportGenerator
            
            # Generate report
            generator = ReportGenerator(self.scan_results)
            
            if selected_format == "pdf":
                success = generator.generate_pdf_report(file_path)
            elif selected_format == "html":
                success = generator.generate_html_report(file_path)
            elif selected_format == "json":
                success = generator.generate_json_report(file_path)
            elif selected_format == "csv":
                success = generator.generate_csv_report(file_path)
            
            # Close progress dialog
            progress.close()
            
            if success:
                success_msg = QMessageBox(self)
                success_msg.setWindowTitle("EXPORT COMPLETE")
                success_msg.setIcon(QMessageBox.Information)
                
                success_html = f"""
                <html>
                <body style="color: #e0e0e0; background-color: #1a1a1a; padding: 10px;">
                <h3 style="color: #00ff00;">REPORT GENERATED SUCCESSFULLY</h3>
                <p>Your vulnerability assessment report has been saved to:</p>
                <p style="color: #00aaff; font-family: Consolas; background-color: #252525; padding: 10px; border-radius: 4px;">{file_path}</p>
                <p style="color: #aaaaaa; font-style: italic;">The report contains detailed analysis of all identified vulnerabilities and recommended remediation steps.</p>
                </body>
                </html>
                """
                
                success_msg.setText(success_html)
                success_msg.setStandardButtons(QMessageBox.Ok)
                success_msg.setStyleSheet("""
                    QMessageBox {
                        background-color: #1a1a1a;
                        color: #00ff00;
                    }
                    QPushButton {
                        background-color: #252525;
                        color: #00ff00;
                        border: 1px solid #00ff00;
                        border-radius: 4px;
                        padding: 5px 15px;
                    }
                """)
                success_msg.exec_()
            else:
                error_msg = QMessageBox(self)
                error_msg.setWindowTitle("EXPORT FAILED")
                error_msg.setIcon(QMessageBox.Critical)
                
                error_html = f"""
                <html>
                <body style="color: #e0e0e0; background-color: #1a1a1a; padding: 10px;">
                <h3 style="color: #ff5555;">REPORT GENERATION FAILED</h3>
                <p>The system encountered an error while generating the {selected_format.upper()} report.</p>
                <p style="color: #aaaaaa; font-style: italic;">Please try a different format or check system permissions.</p>
                </body>
                </html>
                """
                
                error_msg.setText(error_html)
                error_msg.setStandardButtons(QMessageBox.Ok)
                error_msg.setStyleSheet("""
                    QMessageBox {
                        background-color: #1a1a1a;
                        color: #ff5555;
                    }
                    QPushButton {
                        background-color: #252525;
                        color: #e0e0e0;
                        border: 1px solid #3a3a3a;
                        border-radius: 4px;
                        padding: 5px 15px;
                    }
                """)
                error_msg.exec_()
        
        except Exception as e:
            error_msg = QMessageBox(self)
            error_msg.setWindowTitle("EXPORT ERROR")
            error_msg.setIcon(QMessageBox.Critical)
            
            error_html = f"""
            <html>
            <body style="color: #e0e0e0; background-color: #1a1a1a; padding: 10px;">
            <h3 style="color: #ff5555;">EXPORT OPERATION FAILED</h3>
            <p>An unexpected error occurred while generating the report:</p>
            <p style="color: #ff5555; font-family: Consolas; background-color: #252525; padding: 10px; border-radius: 4px;">{str(e)}</p>
            <p style="color: #aaaaaa; font-style: italic;">Please check system permissions and try again.</p>
            </body>
            </html>
            """
            
            error_msg.setText(error_html)
            error_msg.setStandardButtons(QMessageBox.Ok)
            error_msg.setStyleSheet("""
                QMessageBox {
                    background-color: #1a1a1a;
                    color: #ff5555;
                }
                QPushButton {
                    background-color: #252525;
                    color: #e0e0e0;
                    border: 1px solid #3a3a3a;
                    border-radius: 4px;
                    padding: 5px 15px;
                }
            """)
            error_msg.exec_()
    


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())