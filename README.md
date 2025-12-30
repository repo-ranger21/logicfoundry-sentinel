 🛡️ Sentinel-AutoFix

> Automated Vulnerability Detection and Remediation Engine  
> A Python-based SOAR (Security Orchestration, Automation, and Response) tool for network security.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

 🎯 What Is This?

Sentinel-AutoFix is an automated security pipeline that:

1. Scans networks for open ports and vulnerable services (using Nmap/Nikto)
2. Analyzes findings to identify security risks and prioritizes by severity
3. Remediates issues by generating ready-to-run Ansible playbooks and shell scripts

This implements the SOAR (Security Orchestration, Automation, and Response) methodology—automating the detection-to-fix workflow that security teams typically do manually.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   SCANNER   │ ──▶ │  ANALYZER   │ ──▶ │ REMEDIATOR  │
│  (Nmap)     │     │ (Risk Score)│     │ (Ansible)   │
└─────────────┘     └─────────────┘     └─────────────┘
     │                    │                    │
     ▼                    ▼                    ▼
  Open Ports         Vulnerabilities      Fix Scripts
  Services           CVE Matching         Playbooks
```

---

 🚀 Features

| Module | Description |
|--------|-------------|
| `scanner.py` | Nmap integration for port scanning, service detection, and vulnerability scripts |
| `analyzer.py` | Risk classification engine with severity ratings (Critical/High/Medium/Low) |
| `remediator.py` | Auto-generates Ansible playbooks and shell scripts for common fixes |
| `logic_core.py` | Data ingestion and ETL processing module |

 Detected Vulnerabilities

- 🔴 Critical: SMBv1 (EternalBlue), backdoored FTP, path traversal
- 🟠 High: Open Telnet, exposed RDP/VNC, legacy Apache/SSH versions
- 🟡 Medium: Unencrypted FTP, outdated services, exposed NetBIOS
- 🟢 Low: Informational findings

 Auto-Generated Remediations

- Ansible playbooks for service hardening (SSH, SMB, Apache)
- Firewall rules (iptables) to block risky ports
- Shell scripts for package updates and configuration changes

---

 📋 Prerequisites

- Python 3.8+
- Nmap installed and in PATH
- Root/sudo access (required for certain scan types)
- Ansible (optional, for running generated playbooks)

 Install Nmap

```bash
 macOS
brew install nmap

 Ubuntu/Debian
sudo apt-get install nmap

 RHEL/CentOS
sudo yum install nmap
```

---

 ⚡ Quick Start

 1. Clone the Repository

```bash
git clone https://github.com/repo-ranger21/logicfoundry-sentinel.git
cd logicfoundry-sentinel
```

 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate   On Windows: venv\Scripts\activate
```

 3. Install Dependencies

```bash
pip install -r requirements.txt
```

 4. Run a Scan

```bash
 Quick scan on a target
python src/scanner.py 192.168.1.1

 Or use the full pipeline in Python
python -c "
from src.scanner import VulnerabilityScanner
from src.analyzer import VulnerabilityAnalyzer
from src.remediator import Remediator

 Scan
scanner = VulnerabilityScanner()
results = scanner.quick_scan('192.168.1.1')

 Analyze
analyzer = VulnerabilityAnalyzer()
vulns = analyzer.analyze(results)
print(analyzer.generate_report())

 Generate fixes
remediator = Remediator()
remediator.generate_remediation(vulns)
remediator.export_playbooks()
"
```

---

 📖 Usage Guide

 Scanner Module

```python
from src.scanner import VulnerabilityScanner

scanner = VulnerabilityScanner()

 Quick scan (common ports, fast)
results = scanner.quick_scan("192.168.1.1")

 Full scan (all ports, slow but thorough)
results = scanner.full_scan("192.168.1.1", ports="1-65535")

 Vulnerability-specific scan (uses Nmap vuln scripts)
results = scanner.vulnerability_scan("192.168.1.1")

 Export results
scanner.export_results("scan_results.json")
```

 Analyzer Module

```python
from src.analyzer import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer()
vulnerabilities = analyzer.analyze(scan_results)

 Get summary
summary = analyzer.get_summary()
print(f"Found {summary['critical']} critical, {summary['high']} high severity issues")

 Check if immediate action needed
if analyzer.needs_immediate_action():
    print("🚨 CRITICAL vulnerabilities detected!")

 Generate report
print(analyzer.generate_report())
```

 Remediator Module

```python
from src.remediator import Remediator

remediator = Remediator(output_dir="./fixes")
actions = remediator.generate_remediation(vulnerabilities)

 Export Ansible playbooks and shell scripts
remediator.export_playbooks()

 View summary
print(remediator.get_summary())
```

---

 🧪 Running Tests

```bash
 Run all tests
pytest tests/ -v

 Run with coverage
pytest tests/ --cov=src --cov-report=html
```

---

 📁 Project Structure

```
logicfoundry-sentinel/
│
├── README.md               This file
├── requirements.txt        Python dependencies
├── LICENSE                 MIT License
├── .gitignore              Git ignore rules
│
├── src/                    Source code
│   ├── __init__.py         Package initialization
│   ├── scanner.py          Nmap/Nikto scanning logic
│   ├── analyzer.py         Vulnerability analysis engine
│   ├── remediator.py       Remediation script generator
│   └── logic_core.py       Data ingestion/ETL module
│
├── tests/                  Unit tests
│   ├── __init__.py
│   └── test_scanner.py     Pytest test suite
│
└── remediation/            Generated fix scripts (created at runtime)
    ├── playbook_01_ansible.yml
    └── remediate_02_shell.sh
```

---

 🔐 Security Considerations

> ⚠️ Important: Only scan systems you own or have explicit permission to test.

- This tool performs active network reconnaissance
- Some scans require root privileges (`-sS` SYN scans)
- Generated remediation scripts should be reviewed before execution
- Always test fixes in a staging environment first

---

 🛠️ How SOAR Works

SOAR (Security Orchestration, Automation, and Response) is a methodology that combines:

| Component | Implementation in Sentinel-AutoFix |
|-----------|-----------------------------------|
| Orchestration | Pipeline connecting scanner → analyzer → remediator |
| Automation | Auto-generated Ansible playbooks and scripts |
| Response | Pre-built remediation actions for common vulnerabilities |

 Traditional vs. Automated Workflow

```
Traditional (Manual):
  Alert → Triage → Investigate → Document → Remediate → Verify
  ────────────────── Hours to Days ──────────────────

Sentinel-AutoFix (Automated):
  Scan → Analyze → Generate Fix → Review → Apply
  ────────────── Minutes ──────────────
```

---

 📊 Example Output

 Vulnerability Report

```
============================================================
VULNERABILITY ANALYSIS REPORT
============================================================

Total Findings: 4
  Critical: 1
  High:     2
  Medium:   1
  Low:      0

Auto-fix Available: 4

------------------------------------------------------------
DETAILED FINDINGS
------------------------------------------------------------

[CRITICAL] Port 445/smb
  Description: SMBv1 vulnerable to EternalBlue (Samba 3.6.25)
  Auto-fix: Yes

[HIGH] Port 23/telnet
  Description: Telnet is unencrypted - use SSH (Port 23 open)
  Auto-fix: Yes
```

---

 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

 🙏 Acknowledgments

- [Nmap](https://nmap.org/) - Network scanner
- [python-nmap](https://pypi.org/project/python-nmap/) - Python bindings for Nmap
- [Ansible](https://www.ansible.com/) - Automation platform

---

<p align="center">
  <b>Built with 🛡️ for security automation</b>
</p>

