import os
import json
import csv
import datetime
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import io
import base64
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtCore import QBuffer, QByteArray
from PyQt5.QtGui import QPixmap
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import tempfile

class ReportGenerator:
    def __init__(self, scan_results):
        self.scan_results = scan_results
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        
    def generate_json_report(self, file_path):
        """Generate a JSON report"""
        with open(file_path, 'w') as f:
            json.dump(self.scan_results, f, indent=4)
        return True
    
    def generate_csv_report(self, file_path):
        """Generate a CSV report"""
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Type', 'Severity', 'URL', 'Parameter', 'Evidence', 'Description', 'Remediation'])
            
            # Write vulnerabilities
            for vuln in self.scan_results['vulnerabilities']:
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('url', ''),
                    vuln.get('parameter', ''),
                    vuln.get('evidence', ''),
                    vuln.get('description', ''),
                    vuln.get('remediation', '')
                ])
        return True
    
    def generate_html_report(self, file_path):
        """Generate an HTML report with graphs"""
        # Generate graphs
        severity_chart = self._generate_severity_chart()
        vulnerability_types_chart = self._generate_vulnerability_types_chart()
        
        # Prepare template data
        template_data = {
            'results': self.scan_results,
            'severity_chart': severity_chart,
            'vulnerability_types_chart': vulnerability_types_chart,
            'current_date': datetime.datetime.now().strftime('%Y-%m-%d'),
            'report_id': datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        }
        
        # Render template
        template = self.env.get_template('pentest_report.html')
        html_content = template.render(**template_data)
        
        # Write to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True
    
    def generate_pdf_report(self, file_path):
        """Generate a PDF report"""
        try:
            # First generate HTML report
            temp_html = tempfile.NamedTemporaryFile(suffix='.html', delete=False)
            temp_html_path = temp_html.name
            temp_html.close()
            
            self.generate_html_report(temp_html_path)
            
            # Skip external PDF libraries and use reportlab directly
            success = self._generate_reportlab_pdf(file_path)
            
            # Clean up temp file
            os.unlink(temp_html_path)
            return success
        
        except Exception as e:
            print(f"Error generating PDF: {str(e)}")
            # Fallback to direct reportlab PDF generation
            return self._generate_reportlab_pdf(file_path)
    
    def _generate_reportlab_pdf(self, file_path):
        """Generate PDF using ReportLab (fallback method)"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            
            # Create document
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Create custom styles - check if they already exist first
            if 'CustomTitle' not in styles:
                styles.add(ParagraphStyle(name='CustomTitle', 
                                        fontName='Helvetica-Bold', 
                                        fontSize=18, 
                                        textColor=colors.red,
                                        spaceAfter=12))
            
            if 'CustomHeading2' not in styles:
                styles.add(ParagraphStyle(name='CustomHeading2', 
                                        fontName='Helvetica-Bold', 
                                        fontSize=14, 
                                        textColor=colors.red,
                                        spaceAfter=10,
                                        spaceBefore=10))
            
            if 'CustomHeading3' not in styles:
                styles.add(ParagraphStyle(name='CustomHeading3', 
                                        fontName='Helvetica-Bold', 
                                        fontSize=12, 
                                        textColor=colors.red,
                                        spaceAfter=8,
                                        spaceBefore=8))
            
            # Create content
            content = []
            
            # Title
            content.append(Paragraph("WhiteCrow Web Vulnerability Scan Report", styles['CustomTitle']))
            content.append(Spacer(1, 0.25*inch))
            
            # Executive Summary
            content.append(Paragraph("Executive Summary", styles['CustomHeading2']))
            summary_text = f"""
            A security assessment was conducted on {self.scan_results['target']} on {self.scan_results['scan_time']}.
            The scan identified {len(self.scan_results['vulnerabilities'])} vulnerabilities.
            Based on the findings, the overall security posture is considered to be at risk.
            """
            content.append(Paragraph(summary_text, styles['Normal']))
            content.append(Spacer(1, 0.25*inch))
            
            # Generate severity chart
            severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
            for vuln in self.scan_results['vulnerabilities']:
                severity = vuln.get('severity', 'Low')
                severity_counts[severity] += 1
            
            # Create a pie chart
            plt.figure(figsize=(6, 4))
            plt.pie(severity_counts.values(), labels=severity_counts.keys(), 
                   autopct='%1.1f%%', colors=['#ff6666', '#ffcc66', '#66b3ff'])
            plt.title('Vulnerabilities by Severity')
            
            # Save chart to buffer
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png')
            img_buffer.seek(0)
            plt.close()
            
            # Add chart to PDF
            img = Image(img_buffer)
            img.drawHeight = 3*inch
            img.drawWidth = 4*inch
            content.append(img)
            content.append(Spacer(1, 0.25*inch))
            
            # Scan Summary
            content.append(Paragraph("Scan Summary", styles['CustomHeading2']))
            
            summary_data = [
                ['Target URL', self.scan_results['target']],
                ['Scan Time', self.scan_results['scan_time']],
                ['Duration', f"{self.scan_results['statistics']['scan_duration']} seconds"],
                ['URLs Scanned', str(self.scan_results['statistics']['urls_scanned'])],
                ['Vulnerabilities Found', str(self.scan_results['statistics']['vulnerabilities_found'])]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(summary_table)
            content.append(Spacer(1, 0.25*inch))
            
            # Vulnerabilities
            content.append(Paragraph("Detailed Findings", styles['CustomHeading2']))
            
            # Group vulnerabilities by type
            vuln_by_type = {}
            for vuln in self.scan_results['vulnerabilities']:
                if vuln['type'] not in vuln_by_type:
                    vuln_by_type[vuln['type']] = []
                vuln_by_type[vuln['type']].append(vuln)
            
            # Add each vulnerability type
            for vuln_type, vulns in vuln_by_type.items():
                content.append(Paragraph(vuln_type, styles['CustomHeading3']))
                
                for i, vuln in enumerate(vulns):
                    # Vulnerability details
                    vuln_text = f"""
                    <b>Finding #{i+1}</b> (Severity: {vuln['severity']})<br/>
                    <b>URL:</b> {vuln['url']}<br/>
                    """
                    
                    if 'parameter' in vuln and vuln['parameter']:
                        vuln_text += f"<b>Parameter:</b> {vuln['parameter']}<br/>"
                    
                    if 'evidence' in vuln and vuln['evidence']:
                        vuln_text += f"<b>Evidence:</b> {vuln['evidence']}<br/>"
                    
                    vuln_text += f"""
                    <b>Description:</b> {vuln['description']}<br/>
                    <b>Remediation:</b> {vuln['remediation']}
                    """
                    
                    content.append(Paragraph(vuln_text, styles['Normal']))
                    content.append(Spacer(1, 0.15*inch))
            
            # Build PDF
            doc.build(content)
            return True
        
        except Exception as e:
            print(f"Error generating PDF with ReportLab: {str(e)}")
            return False
    
    def _generate_severity_chart(self):
        """Generate a chart showing vulnerabilities by severity"""
        # Count vulnerabilities by severity
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] += 1
        
        # Create a pie chart
        plt.figure(figsize=(8, 6))
        plt.pie(severity_counts.values(), labels=severity_counts.keys(), 
               autopct='%1.1f%%', colors=['#ff6666', '#ffcc66', '#66b3ff'])
        plt.title('Vulnerabilities by Severity')
        
        # Save chart to base64 for embedding in HTML
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    def _generate_vulnerability_types_chart(self):
        """Generate a chart showing vulnerabilities by type"""
        # Count vulnerabilities by type
        type_counts = {}
        for vuln in self.scan_results['vulnerabilities']:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in type_counts:
                type_counts[vuln_type] = 0
            type_counts[vuln_type] += 1
        
        # Create a bar chart
        plt.figure(figsize=(10, 6))
        plt.bar(type_counts.keys(), type_counts.values(), color='#4a6cf7')
        plt.title('Vulnerabilities by Type')
        plt.xlabel('Vulnerability Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save chart to base64 for embedding in HTML
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        plt.close()
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')