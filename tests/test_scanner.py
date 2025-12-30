"""
test_scanner.py - Unit Tests for Vulnerability Scanner

Run with: pytest tests/test_scanner.py -v
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner import VulnerabilityScanner
from analyzer import VulnerabilityAnalyzer, Vulnerability, Severity
from remediator import Remediator, RemediationType


class TestVulnerabilityScanner:
    """Test suite for the VulnerabilityScanner class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = VulnerabilityScanner()
    
    @patch('scanner.nmap.PortScanner')
    def test_scanner_initialization(self, mock_nmap):
        """Test that scanner initializes correctly."""
        scanner = VulnerabilityScanner()
        assert scanner.last_scan_results is None
    
    @patch('scanner.nmap.PortScanner')
    def test_quick_scan_returns_dict(self, mock_nmap):
        """Test that quick_scan returns a dictionary."""
        mock_instance = MagicMock()
        mock_nmap.return_value = mock_instance
        mock_instance.all_hosts.return_value = []
        
        scanner = VulnerabilityScanner()
        result = scanner.quick_scan("127.0.0.1")
        
        assert isinstance(result, dict)
        assert "target" in result or "error" in result
    
    def test_parse_results_empty(self):
        """Test parsing empty scan results."""
        self.scanner.nm = MagicMock()
        self.scanner.nm.all_hosts.return_value = []
        
        result = self.scanner._parse_results("127.0.0.1")
        
        assert result["target"] == "127.0.0.1"
        assert result["hosts"] == []
        assert result["status"] == "completed"
    
    def test_export_without_results(self):
        """Test export fails gracefully when no results exist."""
        result = self.scanner.export_results("/tmp/test.json")
        assert result is False


class TestVulnerabilityAnalyzer:
    """Test suite for the VulnerabilityAnalyzer class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = VulnerabilityAnalyzer()
        self.mock_scan_results = {
            "target": "192.168.1.100",
            "status": "completed",
            "hosts": [{
                "ip": "192.168.1.100",
                "hostname": "testserver",
                "state": "up",
                "ports": [
                    {"port": 22, "protocol": "tcp", "state": "open",
                     "service": "ssh", "product": "OpenSSH", "version": "7.4"},
                    {"port": 23, "protocol": "tcp", "state": "open",
                     "service": "telnet", "product": "", "version": ""},
                    {"port": 80, "protocol": "tcp", "state": "open",
                     "service": "http", "product": "Apache", "version": "2.4.49"},
                ]
            }]
        }
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes with empty vulnerability list."""
        assert self.analyzer.vulnerabilities == []
        assert self.analyzer.scan_results is None
    
    def test_analyze_detects_telnet(self):
        """Test that analyzer detects open telnet as vulnerability."""
        vulns = self.analyzer.analyze(self.mock_scan_results)
        
        telnet_vulns = [v for v in vulns if v.port == 23]
        assert len(telnet_vulns) > 0
        assert telnet_vulns[0].severity == Severity.HIGH
    
    def test_analyze_detects_vulnerable_apache(self):
        """Test that analyzer detects vulnerable Apache version."""
        vulns = self.analyzer.analyze(self.mock_scan_results)
        
        apache_vulns = [v for v in vulns if "Apache" in v.description or v.port == 80]
        assert len(apache_vulns) > 0
    
    def test_analyze_with_error_results(self):
        """Test analyzer handles error results gracefully."""
        error_results = {"error": "Scan failed", "target": "192.168.1.1"}
        vulns = self.analyzer.analyze(error_results)
        
        assert vulns == []
    
    def test_get_summary(self):
        """Test summary generation."""
        self.analyzer.analyze(self.mock_scan_results)
        summary = self.analyzer.get_summary()
        
        assert "total" in summary
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary
        assert summary["total"] >= 0
    
    def test_needs_immediate_action_with_critical(self):
        """Test immediate action detection with critical vulnerability."""
        # Add a critical vulnerability
        self.analyzer.vulnerabilities = [
            Vulnerability(port=445, service="smb", 
                         description="SMBv1 vulnerable",
                         severity=Severity.CRITICAL)
        ]
        
        assert self.analyzer.needs_immediate_action() is True
    
    def test_needs_immediate_action_without_critical(self):
        """Test immediate action detection without critical vulnerability."""
        self.analyzer.vulnerabilities = [
            Vulnerability(port=22, service="ssh",
                         description="Outdated SSH",
                         severity=Severity.MEDIUM)
        ]
        
        assert self.analyzer.needs_immediate_action() is False
    
    def test_get_critical_findings(self):
        """Test filtering for critical/high findings."""
        self.analyzer.vulnerabilities = [
            Vulnerability(port=23, service="telnet", description="Telnet open",
                         severity=Severity.HIGH),
            Vulnerability(port=22, service="ssh", description="Old SSH",
                         severity=Severity.LOW),
            Vulnerability(port=445, service="smb", description="SMBv1",
                         severity=Severity.CRITICAL),
        ]
        
        critical = self.analyzer.get_critical_findings()
        
        assert len(critical) == 2
        assert all(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in critical)
    
    def test_generate_report(self):
        """Test report generation."""
        self.analyzer.analyze(self.mock_scan_results)
        report = self.analyzer.generate_report()
        
        assert "VULNERABILITY ANALYSIS REPORT" in report
        assert "Total Findings" in report


class TestRemediator:
    """Test suite for the Remediator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.remediator = Remediator(output_dir="/tmp/remediation_test")
        self.mock_vulns = [
            Vulnerability(port=23, service="telnet",
                         description="Telnet exposed",
                         severity=Severity.HIGH, remediation_available=True),
            Vulnerability(port=22, service="ssh",
                         description="Old SSH version",
                         severity=Severity.MEDIUM, remediation_available=True),
        ]
    
    def test_remediator_initialization(self):
        """Test remediator initializes correctly."""
        assert self.remediator.actions == []
        assert self.remediator.output_dir == "/tmp/remediation_test"
    
    def test_generate_remediation_for_telnet(self):
        """Test remediation generation for telnet."""
        telnet_vuln = [Vulnerability(port=23, service="telnet",
                                     description="Telnet open",
                                     severity=Severity.HIGH,
                                     remediation_available=True)]
        
        actions = self.remediator.generate_remediation(telnet_vuln)
        
        assert len(actions) == 1
        assert actions[0].action_type == RemediationType.ANSIBLE
        assert "telnet" in actions[0].script.lower()
    
    def test_generate_remediation_multiple_vulns(self):
        """Test remediation generation for multiple vulnerabilities."""
        actions = self.remediator.generate_remediation(self.mock_vulns)
        
        assert len(actions) == 2
    
    def test_get_summary(self):
        """Test summary generation."""
        self.remediator.generate_remediation(self.mock_vulns)
        summary = self.remediator.get_summary()
        
        assert "REMEDIATION SUMMARY" in summary
        assert "Total Actions" in summary


class TestIntegration:
    """Integration tests for the full pipeline."""
    
    def test_full_pipeline_mock(self):
        """Test the full scan -> analyze -> remediate pipeline with mocked data."""
        # Mock scan results
        scan_results = {
            "target": "test-server",
            "status": "completed",
            "hosts": [{
                "ip": "10.0.0.1",
                "hostname": "test-server",
                "state": "up",
                "ports": [
                    {"port": 23, "protocol": "tcp", "state": "open",
                     "service": "telnet", "product": "", "version": ""},
                ]
            }]
        }
        
        # Analyze
        analyzer = VulnerabilityAnalyzer()
        vulns = analyzer.analyze(scan_results)
        
        assert len(vulns) > 0
        
        # Generate remediation
        remediator = Remediator()
        actions = remediator.generate_remediation(vulns)
        
        assert len(actions) > 0
        
        # Verify pipeline produces actionable output
        summary = analyzer.get_summary()
        assert summary["total"] > 0


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
