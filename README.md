# nmap_pro_oss_enterprise
Enterprise-grade Nmap orchestration framework designed for safe security assessment in hybrid IT/OT environments
The tool focuses on:
• network discovery
• exposure assessment
• asset classification
• attack surface analysis
• visualization and reporting
while protecting fragile infrastructure such as industrial control systems and IoT devices.

Table of Contents 
Overview
• Architecture
• Key Features
• Scan Workflow
• Dashboard
• Installation
• Usage
• Reports
• Security Design
Example Output
Roadmap
License

NMAP_PRO_OSS_ENTERPRISE extends Nmap with enterprise-scale orchestration features.
It provides:
• adaptive scan control
• asset classification
• attack surface scoring
• topology mapping
• automated reporting
• scheduling
• web dashboards

The framework is designed for authorized enterprise security assessments, including environments containing 
• corporate IT infrastructure
• OT / ICS networks
• IoT deployments
• data center networks
• mixed enterprise environments

Architecture Flow
Target Selection
        │
        ▼
Network Discovery
        │
        ▼
Pre-Scan Device Detection
        │
        ▼
Adaptive Scan Waves
        │
        ▼
Result Parsing
        │
        ▼
Asset Classification
        │
        ▼
Risk Scoring
        │
        ▼
Report Generation
        │
        ▼
Visualization & Dashboard 

Dashboard components include:
• host inventory
• risk rankings
• exposure findings
• subnet attack surface scores
• topology maps
• attack graph modeling
• risk heatmaps

Optional Flask web interface allows browsing reports from a browser.
Default Address :http://127.0.0.1:5000 

Installation -Requirements Python 3.9+ -  Nmap installed on the system

Python Dependencies
rich
jinja2
flask
networkx
matplotlib

Install Manually 
pip install rich jinja2 flask networkx matplotlib

Run the Tool
python3 nmap_pro_oss_enterprise.py

Interactive menu options include:
1  Exposure Assessment Scan
2  Full TCP + UDP Scan
3  OS Detection + SMB Fingerprinting
4  Malware Indicator + AD Enumeration
6  Full Combo Scan
7  SSL/TLS Certificate Scan
8  SMB Deep Scan

Recommended starting configuration:
Scan Type: Exposure Assessment
Ports: Top 1000
Profile: OT_SAFE

Reports -Each scan produces multiple outputs. Host Reports 
TXT summaries 

Data Tables
hosts.csv
findings.csv
subnet_scores.csv

Visualizations
Topology Map
Risk Heatmap
Attack Graph

Dashboard 
HTML report
Web interface

Example Output Structure 
nmap_pro_data/
 ├── nmap_scans/
 ├── reports/
 │    └── run_<scope>_<timestamp>/
 │         ├── dashboard.html
 │         ├── hosts.csv
 │         ├── findings.csv
 │         ├── subnet_scores.csv
 │         ├── topology.png
 │         ├── risk_heatmap.png
 │         ├── attack_graph.png
 │         └── summaries/
 ├── logs/
 └── state/

 The framework deliberately avoids unsafe behavior.
 Excluded features include:
• exploit frameworks
• brute-force attacks
• unsafe NSE scripts
• denial-of-service techniques

License
MIT License

Disclaimer
This tool must be used only on systems you are authorized to test.
Unauthorized network scanning may violate:
local laws
organizational policies
ISP terms of service
The authors assume no responsibility for misuse.
