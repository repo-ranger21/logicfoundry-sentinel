"""
scanner.py - Network Vulnerability Scanner

Handles Nmap and Nikto scanning logic for automated vulnerability detection.
"""

import nmap
import subprocess
import json
from typing import Optional


class VulnerabilityScanner:
    """
    A wrapper class for network vulnerability scanning using Nmap and Nikto.
    """
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.last_scan_results = None
    
    def quick_scan(self, target: str) -> dict:
        """
        Perform a quick TCP SYN scan on common ports.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            dict: Scan results with open ports and services
        """
        print(f"[*] Starting quick scan on {target}...")
        
        try:
            self.nm.scan(hosts=target, arguments='-sV -F --open')
            self.last_scan_results = self._parse_results(target)
            return self.last_scan_results
        except nmap.PortScannerError as e:
            return {"error": f"Nmap scan failed: {str(e)}", "target": target}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}", "target": target}
    
    def full_scan(self, target: str, ports: str = "1-65535") -> dict:
        """
        Perform a comprehensive scan with service/version detection.
        
        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (default: all ports)
            
        Returns:
            dict: Detailed scan results
        """
        print(f"[*] Starting full scan on {target} (ports: {ports})...")
        print("[!] This may take several minutes...")
        
        try:
            self.nm.scan(hosts=target, ports=ports, arguments='-sV -sC -O --open')
            self.last_scan_results = self._parse_results(target)
            return self.last_scan_results
        except nmap.PortScannerError as e:
            return {"error": f"Nmap scan failed: {str(e)}", "target": target}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}", "target": target}
    
    def vulnerability_scan(self, target: str) -> dict:
        """
        Run Nmap with vulnerability detection scripts.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            dict: Vulnerability scan results
        """
        print(f"[*] Starting vulnerability scan on {target}...")
        
        try:
            self.nm.scan(hosts=target, arguments='-sV --script=vuln --open')
            self.last_scan_results = self._parse_results(target)
            return self.last_scan_results
        except nmap.PortScannerError as e:
            return {"error": f"Nmap scan failed: {str(e)}", "target": target}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}", "target": target}
    
    def _parse_results(self, target: str) -> dict:
        """
        Parse Nmap scan results into a structured format.
        
        Args:
            target: The scanned target
            
        Returns:
            dict: Parsed scan results
        """
        results = {
            "target": target,
            "status": "unknown",
            "hosts": []
        }
        
        for host in self.nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": self.nm[host].hostname(),
                "state": self.nm[host].state(),
                "ports": []
            }
            
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in sorted(ports):
                    port_info = self.nm[host][proto][port]
                    host_info["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info.get("state", "unknown"),
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", "")
                    })
            
            results["hosts"].append(host_info)
        
        results["status"] = "completed"
        return results
    
    def run_nikto(self, target: str, port: int = 80) -> dict:
        """
        Run Nikto web vulnerability scanner against a target.
        
        Args:
            target: IP address or hostname
            port: Web server port (default: 80)
            
        Returns:
            dict: Nikto scan results
        """
        print(f"[*] Running Nikto scan on {target}:{port}...")
        
        try:
            cmd = ["nikto", "-h", f"{target}:{port}", "-Format", "json", "-o", "-"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    "target": target,
                    "port": port,
                    "status": "completed",
                    "output": result.stdout
                }
            else:
                return {
                    "target": target,
                    "port": port,
                    "status": "error",
                    "error": result.stderr
                }
        except FileNotFoundError:
            return {"error": "Nikto not installed or not in PATH", "target": target}
        except subprocess.TimeoutExpired:
            return {"error": "Nikto scan timed out", "target": target}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}", "target": target}
    
    def export_results(self, filepath: str, format: str = "json") -> bool:
        """
        Export scan results to a file.
        
        Args:
            filepath: Output file path
            format: Export format ('json' or 'txt')
            
        Returns:
            bool: True if export successful
        """
        if not self.last_scan_results:
            print("[!] No scan results to export")
            return False
        
        try:
            with open(filepath, 'w') as f:
                if format == "json":
                    json.dump(self.last_scan_results, f, indent=2)
                else:
                    f.write(str(self.last_scan_results))
            print(f"[+] Results exported to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Export failed: {str(e)}")
            return False


# CLI Entry Point
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target>")
        print("Example: python scanner.py 192.168.1.1")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = VulnerabilityScanner()
    
    print("=" * 60)
    print("SENTINEL-AUTOFIX - Vulnerability Scanner")
    print("=" * 60)
    
    results = scanner.quick_scan(target)
    
    if "error" in results:
        print(f"[!] Scan failed: {results['error']}")
    else:
        print(f"\n[+] Scan completed for {target}")
        for host in results.get("hosts", []):
            print(f"\nHost: {host['ip']} ({host['hostname']})")
            print(f"State: {host['state']}")
            print("\nOpen Ports:")
            for port in host.get("ports", []):
                print(f"  {port['port']}/{port['protocol']} - {port['service']} {port['version']}")
