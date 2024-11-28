# Network Scanner and Security Framework

A Python-based network scanning and security framework that scans a network for connected devices, detects potential anomalies, and provides a graphical user interface (GUI) for monitoring. It combines functionalities like network scanning, anomaly detection, and basic threat response mechanisms.

---

## Features

- **Network Scanning:**
  - Scans a target network and retrieves the IP and MAC addresses of connected devices.
- **Anomaly Detection:**
  - Detects anomalies, such as IP address spoofing, by identifying mismatched IP and MAC address mappings.
- **Security Response:**
  - Displays alerts for potential threats using a GUI.
- **Customizable Output:**
  - Supports flexible output formats and rate-limited packet sending.
- **User-Friendly GUI:**
  - Interactive interface for monitoring live network activity and anomalies.

---

## Installation

### Prerequisites
- Python 3.7 or higher
- Required libraries:
  - `scapy`
  - `tkinter`

### Setup

   ```bash
   pip install -r requirements.txt
```
### Usage
### Launching the Application
-**Update the target_network variable in the __main__ block to match your desired network range.**
```bash
target_network = "192.168.0.0/24"
```
 ### Run the script:
``` bash
python main.py
```

The GUI will launch, displaying connected devices in the specified network range.
GUI Instructions
IP Address & MAC Address Table:
Displays the list of active devices on the network.
Security Alerts:
Pop-up alerts notify the user of any detected anomalies or potential threats.