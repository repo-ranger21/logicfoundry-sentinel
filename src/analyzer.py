"""
analyzer.py - Vulnerability Analysis Engine

Analyzes scan results and determines if remediation is needed.
"""

from typing import Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    port: int
    service: str
    description: str
    severity: Severity
    cve: Optional[str] = None
    remediation_available: bool = False


class VulnerabilityAnalyzer:
    """
    Analyzes scan results to identify vulnerabilities and recommend fixes.
    """
    
    # Known vulnerable services/versions (simplified database)
    KNOWN_VULNERABILITIES = {
        "ssh": {
            "OpenSSH 7.": {"severity": Severity.MEDIUM, "desc": "Outdated SSH version"},
            "OpenSSH 6.": {"severity": Severity.HIGH, "desc": "Legacy SSH with known CVEs"},
        },
        "http": {
            "Apache/2.2": {"severity": Severity.HIGH, "desc": "Apache 2.2 EOL - upgrade required"},
            "Apache/2.4.49": {"severity": Severity.CRITICAL, "desc": "Path traversal CVE-2021-41773"},
            "nginx/1.14": {"severity": Severity.MEDIUM, "desc": "Outdated nginx version"},
        },
        "ftp": {
            "vsftpd 2.3.4": {"severity": Severity.CRITICAL, "desc": "Backdoored version"},
            "ProFTPD 1.3.3": {"severity": Severity.HIGH, "desc": "Remote code execution"},
        },
        "mysql": {
            "MySQL 5.5": {"severity": Severity.HIGH, "desc": "MySQL 5.5 EOL"},
            "MySQL 5.6": {"severity": Severity.MEDIUM, "desc": "MySQL 5.6 EOL"},
        },
        "smb": {
            "Samba 3.": {"severity": Severity.CRITICAL, "desc": "Legacy Samba - EternalBlue risk"},
        }
    }
    
    # Ports that should typically be closed on public interfaces
    RISKY_PORTS = {
        21: ("ftp", Severity.MEDIUM, "FTP is unencrypted"),
        23: ("telnet", Severity.HIGH, "Telnet is unencrypted - use SSH"),
        135: ("msrpc", Severity.MEDIUM, "Windows RPC exposed"),
        139: ("netbios", Severity.MEDIUM, "NetBIOS exposed"),
        445: ("smb", Severity.HIGH, "SMB exposed - ransomware risk"),
        3389: ("rdp", Severity.HIGH, "RDP exposed - brute force risk"),
        5900: ("vnc", Severity.HIGH, "VNC exposed - often unencrypted"),
    }
    
    def __init__(self):
        self.vulnerabilities: list[Vulnerability] = []
        self.scan_results = None
    
    def analyze(self, scan_results: dict) -> list[Vulnerability]:
        """
        Analyze scan results for vulnerabilities.
        
        Args:
            scan_results: Results from VulnerabilityScanner
            
        Returns:
            list: Detected vulnerabilities
        """
        self.scan_results = scan_results
        self.vulnerabilities = []
        
        if "error" in scan_results:
            print(f"[!] Cannot analyze - scan had errors: {scan_results['error']}")
            return []
        
        for host in scan_results.get("hosts", []):
            self._analyze_host(host)
        
        return self.vulnerabilities
    
    def _analyze_host(self, host: dict) -> None:
        """Analyze a single host for vulnerabilities."""
        host_ip = host.get("ip", "unknown")
        
        for port_info in host.get("ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "").lower()
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            full_version = f"{product} {version}".strip()
            
            # Check for risky open ports
            if port in self.RISKY_PORTS:
                port_name, severity, desc = self.RISKY_PORTS[port]
                self.vulnerabilities.append(Vulnerability(
                    port=port,
                    service=service,
                    description=f"{desc} (Port {port} open on {host_ip})",
                    severity=severity,
                    remediation_available=True
                ))
            
            # Check for vulnerable service versions
            if service in self.KNOWN_VULNERABILITIES:
                for version_pattern, vuln_info in self.KNOWN_VULNERABILITIES[service].items():
                    if version_pattern in full_version:
                        self.vulnerabilities.append(Vulnerability(
                            port=port,
                            service=service,
                            description=f"{vuln_info['desc']} ({full_version} on {host_ip})",
                            severity=vuln_info["severity"],
                            remediation_available=True
                        ))
    
    def get_summary(self) -> dict:
        """
        Get a summary of the analysis.
        
        Returns:
            dict: Summary with counts by severity
        """
        summary = {
            "total": len(self.vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "remediation_available": 0
        }
        
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
            if vuln.remediation_available:
                summary["remediation_available"] += 1
        
        return summary
    
    def get_critical_findings(self) -> list[Vulnerability]:
        """Get only critical and high severity findings."""
        return [v for v in self.vulnerabilities 
                if v.severity in (Severity.CRITICAL, Severity.HIGH)]
    
    def needs_immediate_action(self) -> bool:
        """Check if any critical vulnerabilities require immediate action."""
        return any(v.severity == Severity.CRITICAL for v in self.vulnerabilities)
    
    def generate_report(self) -> str:
        """
        Generate a human-readable vulnerability report.
        
        Returns:
            str: Formatted report
        """
        report = []
        report.append("=" * 60)
        report.append("VULNERABILITY ANALYSIS REPORT")
        report.append("=" * 60)
        
        summary = self.get_summary()
        report.append(f"\nTotal Findings: {summary['total']}")
        report.append(f"  Critical: {summary['critical']}")
        report.append(f"  High:     {summary['high']}")
        report.append(f"  Medium:   {summary['medium']}")
        report.append(f"  Low:      {summary['low']}")
        report.append(f"\nAuto-fix Available: {summary['remediation_available']}")
        
        if self.vulnerabilities:
            report.append("\n" + "-" * 60)
            report.append("DETAILED FINDINGS")
            report.append("-" * 60)
            
            # Sort by severity
            sorted_vulns = sorted(self.vulnerabilities, 
                                  key=lambda v: list(Severity).index(v.severity))
            
            for vuln in sorted_vulns:
                report.append(f"\n[{vuln.severity.value.upper()}] Port {vuln.port}/{vuln.service}")
                report.append(f"  Description: {vuln.description}")
                if vuln.cve:
                    report.append(f"  CVE: {vuln.cve}")
                report.append(f"  Auto-fix: {'Yes' if vuln.remediation_available else 'No'}")
        
        return "\n".join(report)


# CLI Entry Point
if __name__ == "__main__":
    # Example usage with mock data
    mock_scan_results = {
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
                {"port": 445, "protocol": "tcp", "state": "open",
                 "service": "smb", "product": "Samba", "version": "3.6.25"},
            ]
        }]
    }
    
    analyzer = VulnerabilityAnalyzer()
    vulnerabilities = analyzer.analyze(mock_scan_results)
    
    print(analyzer.generate_report())
    
    if analyzer.needs_immediate_action():
        print("\n[!!!] CRITICAL vulnerabilities detected - immediate action required!")
