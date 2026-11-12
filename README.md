# NETWATCH — Network Traffic Analyzer and Firewall Management System

**A Python-based network monitoring and firewall management application.**

NETWATCH is a network traffic analysis system designed to capture, monitor, inspect and analyze network packets in real time. It provides a web-based dashboard to visualize network activity, inspect IP addresses and manage firewall blocking rules.

## Project Overview

NETWATCH combines packet capture, network traffic analysis, IP intelligence and firewall management in a single web application.

The project is developed using Python, Flask, Scapy, SQLite, HTML, CSS and JavaScript.

## Features

- **Live Packet Capture:** Capture IPv4 network packets using Scapy.
- **Traffic Monitoring:** Monitor TCP, UDP, ICMP and other traffic.
- **Network Dashboard:** View packet statistics and network activity.
- **Packet Inspector:** Inspect packet source, destination, protocol and related information.
- **IP Intelligence:** Retrieve approximate IP location, ISP, organization and ASN information.
- **Firewall Management:** Block and unblock destination IP addresses using nftables.
- **Traffic Database:** Store captured packet information using SQLite.
- **Search and Filters:** Search and filter network packet records.
- **CSV Export:** Export packet information for further analysis.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend | Flask |
| Packet Capture | Scapy |
| Database | SQLite |
| Firewall | Linux nftables |
| Frontend | HTML, CSS, JavaScript |
| IP Intelligence | ipwho.is API |
| Operating System | Kali Linux |

## Project Structure

```text
network-traffic-analyzer/
│
├── backend/
│   ├── app.py
│   ├── capture.py
│   ├── database.py
│   ├── firewall.py
│   └── firewall_api.py
│
├── frontend/
│   └── index.html
│
├── .gitignore
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/princechauhan835944-lgtm/NETWATCH-Network-Traffic-Analyzer.git
cd NETWATCH-Network-Traffic-Analyzer
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install flask flask-cors scapy
```

If a `requirements.txt` file is added to the repository, you can instead install dependencies using:

```bash
pip install -r requirements.txt
```

### 4. Start packet capture

Open Terminal 1:

```bash
sudo .venv/bin/python backend/capture.py
```

### 5. Start the Flask application

Open Terminal 2:

```bash
.venv/bin/python backend/app.py
```

### 6. Open the dashboard

Visit:

http://127.0.0.1:5000

## Important Notes

- NETWATCH is designed for Linux environments.
- Packet capture may require root privileges.
- Firewall functionality requires nftables and appropriate system permissions.
- Firewall rules managed by NETWATCH apply to the local Linux host, not automatically to every device on the network.
- IP geolocation is approximate and depends on an external API.
- Only monitor networks and devices for which you have authorization.

## Current Limitations

- IPv4 packet monitoring is currently implemented.
- IP geolocation depends on internet connectivity and an external service.
- Firewall management requires Linux-specific configuration.
- The application is intended to run locally on a compatible Linux machine.

## Future Scope

- IPv6 packet analysis.
- Advanced traffic visualization.
- Intrusion detection capabilities.
- Network anomaly detection.
- More detailed packet inspection.
- Enhanced security alerts and reporting.

## Developer

**Prince Chauhan**

B.Tech — Computer Science and Engineering

Gateway Institute of Engineering and Technology

Affiliated to DCRUST University, Haryana, India.

## Repository

[NETWATCH — Network Traffic Analyzer on GitHub](https://github.com/princechauhan835944-lgtm/NETWATCH-Network-Traffic-Analyzer)

---

*NETWATCH — Monitor. Analyze. Protect.*
