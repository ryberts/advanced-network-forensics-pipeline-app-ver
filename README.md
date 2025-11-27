<a id="readme-top"></a>


<!-- PROJECT -->

<br />
<div align="center">

<h1 align="center">🛡️Advanced Network Forensics Pipeline</h1>

  <p align="center">
      An interactive PCAP generator that creates realistic network traffic.</br>
      Related Project - Generate Simulated PCAP alert <a href="https://github.com/ryberts/pcap-attack-generator">PCAP Attack Simulation Generator</a>
    <br />
    </a>
    &middot;
    <a href="https://github.com/ryberts/advanced-network-forensics-pipeline-cmd/issues">Report Bug or Request a Feature</a>

  </p>
</div>

---
<details>
<summary class="toc-summary"><strong>Table of Contents</summary>

- [Live Demo](#live-demo)
- [About the Project](#about-the-project)
- [Use Cases](#use-cases)
- [Key Features](#key-features)
  - [Multi-Phase Analysis Pipeline](#multi-phase-analysis-pipeline)
  - [Professional Streamlit Dashboard](#professional-streamlit-dashboard)
  - [File Handling](#file-handling)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Install \& Run](#install--run)
- [Project Structure](#project-structure)
- [Usage](#usage)
  - [Via Streamlit UI (Recommended)](#via-streamlit-ui-recommended)
- [Threat Detection Examples](#threat-detection-examples)
  - [1. Port Scanning](#1-port-scanning)
  - [2. Suspicious Port Communication](#2-suspicious-port-communication)
  - [3. DNS Anomalies](#3-dns-anomalies)
  - [4. Data Exfiltration](#4-data-exfiltration)
- [Report Examples](#report-examples)
  - [JSON](#json)
  - [HTML](#html)
  - [TXT](#txt)
- [Technology Stack](#technology-stack)
- [Configuration](#configuration)
  - [Adjustable Settings](#adjustable-settings)
  - [Threat Detection Tuning](#threat-detection-tuning)
- [Testing](#testing)
  - [Generate Sample PCAP](#generate-sample-pcap)
  - [Run Test](#run-test)
- [Security Notes](#security-notes)
- [Use Cases and Scenarios](#use-cases-and-scenarios)
  - [SOC Workflow](#soc-workflow)
  - [Incident Response](#incident-response)
  - [Malware Analysis](#malware-analysis)
  - [Security Training](#security-training)
- [Contributing](#contributing)
- [Resources](#resources)
- [Disclaimer](#disclaimer)
</details>

## Live Demo

[![Open in GitHub Codespaces](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://anfpav.streamlit.app/)



## About the Project
This project provides a complete **network forensics pipeline** for analyzing packet captures (PCAP files). It processes network traffic, extracts protocol and conversation data, detects abnormalities, and generates structured forensic reports.

The updated version has been optimized for:
- **Streamlit Cloud compatibility**
- **GitHub Codespaces environments**
- **Cleaner dependency management and imports**
- **Cloud-safe directory handling**

The pipeline is designed to mimic workflows used in real SOC and IR environments.

---

## Use Cases
- 🔴 **Incident Response & Threat Hunting**
- 🟠 **Network Intrusion Detection**
- 🟡 **Security Audits & Compliance**
- 🟢 **Malware Network Behavior Analysis**
- 🔵 **Cybersecurity Training & Education**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Key Features
### Multi-Phase Analysis Pipeline
**Phase 1 — Packet Analysis**
- Protocol extraction
- Conversations & ports mapping
- DNS & HTTP parsing

**Phase 2 — Threat Detection**
- Port scan detection
- Suspicious/backdoor port identification
- DNS anomaly detection
- Data exfiltration indicators

**Phase 3 — Reporting**
- JSON (machine-readable)
- HTML (formatted for review)
- TXT (executive summary)
- Protocol visualization charts

### Professional Streamlit Dashboard
- Dark cybersecurity-themed UI
- Real-time progress feedback
- Multi-tab layout: Upload → Results → Threats → Reports

### File Handling
- Drag‑and‑drop PCAP upload
- Supports `.pcap` and `.pcapng`
- 1K–50K packet configurable limit
- Quick Mode for faster processing

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Quick Start
### Prerequisites
- Python 3.8+
- pip
- *(Optional)* Wireshark/tshark for PCAP inspection

### Install & Run
```
# Clone repository
git clone https://github.com/yourusername/advanced-network-forensics-pipeline-app-ver.git
cd advanced-network-forensics-pipeline-app-ver

# Virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run app
streamlit run app.py
```
App runs at: **http://localhost:8501**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Project Structure
```
network-forensics-pipeline/
├── app.py                        # Main Streamlit UI
├── core/
│   ├── analyzer.py               # Scapy-based packet analysis
│   ├── detector.py               # Threat detection logic
│   └── reporter.py               # Report generator
├── utils/
├── samples/                      # Example PCAP files
├── reports/                      # Generated reports
├── requirements.txt
└── README.md
```
<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Usage
### Via Streamlit UI (Recommended)
1. Launch app
2. Upload a PCAP file
3. Configure packet limits
4. Run analysis
5. Review:
   - Network stats
   - Detected threats
   - Downloadable reports

---

## Threat Detection Examples
### 1. Port Scanning
**Severity:** 🔴 High  
**Example:** 15 targeted ports → flagged as port scan

### 2. Suspicious Port Communication
**Port:** `tcp/4444` (Metasploit / reverse shell)  
**Severity:** 🔴 High

### 3. DNS Anomalies
**Query Count:** 87  
**Interpretation:** Potential tunneling or C2 beaconing

### 4. Data Exfiltration
**Packet Count:** 15,234  
**Severity:** 🟡 Low

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Report Examples
### JSON
- Metadata
- Packet statistics
- Threat summary & details

### HTML
- Executive summary
- Review‑friendly layout

### TXT
- Manager-facing summary
- Risk level

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Technology Stack
| Component | Technology |
|----------|------------|
| UI Framework | Streamlit |
| Packet Parsing | Scapy 2.5.0 |
| Data Analysis | Pandas |
| Visualization | Matplotlib (Agg), Seaborn |
| Reporting | JSON, HTML |
| Language | Python 3.8+ |

---

## Configuration
### Adjustable Settings
- `max_packets` (default 50,000)
- `quick_mode` (skip heavy visualizations)

### Threat Detection Tuning
Edit `core/detector.py`:
```
self.suspicious_ports = {
    'tcp': [4444, 5555, 6666, 7777, 8888],
    'udp': [69, 161, 5353]
}
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Testing
### Generate Sample PCAP
```
python utils/traffic_generator.py
```
Creates `samples/example.pcap` containing:
- Web browsing
- Port scans
- DNS traffic
- Suspicious ports

### Run Test
```
streamlit run app.py
```
Upload `samples/example.pcap` → Click **Start Analysis**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Security Notes
- Local‑only analysis
- PCAPs never leave your device
- Reports stored only in local `reports/` directory
- No telemetry or data collection

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Use Cases and Scenarios
### SOC Workflow
1. SOC receives alert
2. Export PCAP from SIEM / IDS
3. Upload to pipeline
4. Identify threats
5. Generate full HTML report

### Incident Response
- Detect attack vectors
- Identify exfiltration or C2 channels
- Attach executive summary to IR ticket

### Malware Analysis
- Analyze sandboxed malware PCAP
- Identify command & control (C2)
- Detect unusual DNS or payload patterns

### Security Training
- Generate synthetic PCAPs
- Train students on threat identification

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Contributing
Contributions welcome! Potential areas:
- Additional threat signatures
- ML‑based anomaly detection
- Integration with OTX/VirusTotal APIs
- Real‑time PCAP streaming
- 
<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Resources
- Scapy Documentation
- Streamlit Docs
- MITRE ATT&CK
- PCAP File Format Spec
- Wireshark User Guide

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Disclaimer
This tool is intended for authorized security testing on networks you own or have explicit permission to analyze.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

**Built with Python 3.8+ · Streamlit · Scapy · MIT Licensed**

