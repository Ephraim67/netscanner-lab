from datetime import datetime
import csv
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import os

class ReportGenerator:
    def __init__(self):
        """Initialize with template setup for HTML reports"""
        self.template_dir = Path(__file__).parent.parent / 'templates'
        self.template_dir.mkdir(exist_ok=True)
        
        # Setup template environment
        template_path = self.template_dir / 'report_template.html'
        if not template_path.exists():
            self._create_default_template(template_path)
        self.env = Environment(loader=FileSystemLoader(str(self.template_dir)))

    def _create_default_template(self, template_path):
        """Create default HTML template if missing"""
        default_template = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .high { background-color: #ffdddd; }
        .medium { background-color: #fff3cd; }
        .low { background-color: #d4edda; }
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated on: {{ timestamp }}</p>
    <p>Total vulnerabilities found: {{ total_vulns }}</p>
    
    {% for host, vulns in results.items() %}
    <h2>Host: {{ host }}</h2>
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Vulnerability</th>
                <th>Severity</th>
            </tr>
        </thead>
        <tbody>
            {% for vuln in vulns %}
            <tr class="{{ vuln.severity.lower() }}">
                <td>{{ vuln.port }}</td>
                <td>{{ vuln.service }}</td>
                <td>{{ vuln.type }}</td>
                <td>{{ vuln.severity }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endfor %}
</body>
</html>"""
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(default_template)

    def generate(self, results, output_format=None):
        """
        Generate output - terminal by default, or file if format specified
        
        Args:
            results: Scan results
            output_format: None for terminal, 'html' or 'csv' for files
            
        Returns:
            For file output: Path to generated file
            For terminal: None (prints to console)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if output_format:
            output_format = output_format.lower()
            if output_format not in ('html', 'csv'):
                raise ValueError("Supported formats: 'html' or 'csv'")
            
            filename = f"vulnerability_report_{timestamp.replace(':', '-')}.{output_format}"
            if output_format == 'html':
                self._generate_html(results, filename, timestamp)
            else:
                self._generate_csv(results, filename, timestamp)
            return str(Path(filename).resolve())
        else:
            self._display_terminal_report(results, timestamp)
            return None

    def _display_terminal_report(self, results, timestamp):
        """Display formatted results in terminal"""
        from tabulate import tabulate
        
        print(f"\n\033[1mVulnerability Scan Report\033[0m")
        print(f"Generated: {timestamp}")
        print(f"Total vulnerabilities: {sum(len(v) for v in results.values())}")
        print("-" * 80)
        
        for host, vulns in results.items():
            print(f"\n\033[1mHost:\033[0m {host}")
            table_data = []
            for vuln in vulns:
                # Color coding based on severity
                severity = vuln['severity'].lower()
                if severity == 'high':
                    severity_display = f"\033[91m{vuln['severity']}\033[0m"  # Red
                elif severity == 'medium':
                    severity_display = f"\033[93m{vuln['severity']}\033[0m"  # Yellow
                else:
                    severity_display = f"\033[92m{vuln['severity']}\033[0m"  # Green
                
                table_data.append([
                    vuln['port'],
                    vuln['service'],
                    vuln['type'],
                    severity_display
                ])
            
            print(tabulate(table_data, 
                         headers=["Port", "Service", "Vulnerability", "Severity"],
                         tablefmt="grid"))
        print("-" * 80)

    def _generate_html(self, results, filename, timestamp):
        """Generate HTML report file"""
        try:
            html = self._render_html_template(results, timestamp)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
        except Exception as e:
            raise RuntimeError(f"HTML generation failed: {str(e)}")

    def _generate_csv(self, results, filename, timestamp):
        """Generate CSV report file"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Host', 'Port', 'Service', 'Vulnerability', 'Severity', 'Timestamp'])
                for host, vulns in results.items():
                    for vuln in vulns:
                        writer.writerow([
                            host,
                            vuln['port'],
                            vuln['service'],
                            vuln['type'],
                            vuln['severity'],
                            timestamp
                        ])
        except Exception as e:
            raise RuntimeError(f"CSV generation failed: {str(e)}")

    def _render_html_template(self, results, timestamp):
        """Render HTML template with results"""
        try:
            template = self.env.get_template('report_template.html')
            return template.render(
                results=results,
                timestamp=timestamp,
                total_vulns=sum(len(v) for v in results.values())
            )
        except Exception as e:
            raise RuntimeError(f"Template rendering failed: {str(e)}")