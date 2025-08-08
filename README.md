# **Wi-Fi Security Analyzer – Professional Edition**

A modern, Linux-optimized GUI application for Wi-Fi network security analysis and testing.
Built with **Python 3** and **Tkinter**, it integrates popular security tools like `aircrack-ng`, `aireplay-ng`, `hashcat`, and `hcxpcapngtool` into an intuitive interface designed for security professionals and researchers.

⚠ **This tool is for educational and authorized penetration testing only. Unauthorized use is illegal.**

---

## 🚀 **Features**

### **Modern User Interface**

* **Professional Design**: Clean, card-based layout for better navigation
* **Responsive Layout**: Scales to different screen sizes
* **Real-time Logging**: Live operation feedback with color-coded messages
* **Tabbed Navigation**: Separate, organized sections for each functionality

---

### **1. Network Discovery**

Scan for nearby Wi-Fi networks and view:

* **BSSID, ESSID, Channel**
* **Signal Strength**
* **Encryption, Cipher, Authentication**
* **Automatic Interface Detection**
* **Monitor Mode Enablement**
* **Real-Time Updates** during scans

---

### **2. Handshake Capture**

Capture WPA/WPA2 handshakes with:

* **Client Detection** – Identify devices connected to target APs
* **Deauthentication Attacks** – Force reconnections to capture handshakes
* **Passive or Active Capture Modes**
* **File Management** – Save/load `.cap` or `.pcap` files

---

### **3. Password Cracking**

Multiple cracking workflows:

* **Quick Crack** – Fast dictionary-based cracking with auto-BSSID detection
* **Advanced Crack** – Manual BSSID specification for targeted attacks
* **Robust Crack (Hashcat)** – Multi-stage attacks: dictionary, hybrid, mask, brute force
* **Custom Wordlist Generation** – Using `crunch` or defined patterns
* **Progress Tracking** – Real-time status and verification

---

### **4. Advanced & Support Features**

* **Custom Character Sets** for mask attacks
* **Background Threading** for non-blocking UI
* **Comprehensive Logging** with timestamps and color codes
* **Linux Optimization** – Root privilege checks, interface compatibility
* **Error Handling** – Friendly messages, validation, and cleanup

---

## 🛠 **Prerequisites**

**Recommended OS:**

* Linux (Kali Linux or Debian-based preferred) for full functionality.
  Windows/macOS supported with limitations.

**Requirements:**

* **Python 3.6+** (Tkinter included)
* External Tools:

  ```
  aircrack-ng
  aireplay-ng
  iw
  tcpdump
  hashcat
  hcxpcapngtool
  crunch
  ```
* **Root Privileges** for network operations

---

## 📥 **Installation**

**1. Clone the repository**

```bash
git clone <repository-url>
cd wifi_security_analyzer
```

**2. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**3. Install required system tools**
*Debian/Kali:*

```bash
sudo apt-get update
sudo apt-get install aircrack-ng tcpdump iw hashcat hcxtools crunch python3-tk
```

*macOS (via Homebrew):*

```bash
brew install aircrack-ng hashcat tcpdump
```

*Windows:*
Download & install:

* [Aircrack-ng](https://www.aircrack-ng.org/downloads.html)
* [Hashcat](https://hashcat.net/hashcat/)

---

## ▶ **Running the Application**

```bash
# Linux/macOS
sudo python3 app.py

# Windows (Run as Administrator)
python app.py
```

> Root/Administrator privileges are required for network operations.

---

## 📋 **Usage Guide**

**1. Network Discovery**

1. Select interface
2. Enable monitor mode
3. Scan for networks
4. View details in the results table

**2. Handshake Capture**

1. Choose target from scan
2. Detect connected clients
3. Perform deauthentication or passive capture
4. Save handshake file

**3. Cracking**

* **Quick Crack** → Select handshake + wordlist → Start
* **Advanced Crack** → Specify BSSID + wordlist → Start
* **Robust Crack** → Configure dictionary/mask/brute force → Run

**4. Monitoring**

* Follow all output in the **System Log** section
* Color-coded statuses: info, success, error

---

## 📂 **File Structure**

```
app.py              # Main Tkinter app & tab setup
network_tab.py      # Interface detection & Wi-Fi scanning
handshake_tab.py    # Handshake capture logic
quick_crack_tab.py  # Fast cracking (aircrack-ng)
cracking_tab.py     # Advanced cracking
robust_crack_tab.py # Hashcat multi-stage cracking
utils.py            # Helper functions (command execution, logging)
requirements.txt    # Python dependencies
```

---

## ⚠ **Legal Disclaimer**

This software is **only for authorized penetration testing and educational use**.
By using this tool, you agree to:

* Test **only** networks you own or have explicit written permission to test
* Comply with all local laws and regulations
* Take full responsibility for any misuse

Unauthorized access to networks is **illegal** and may lead to criminal charges.

---

## 🛠 **Troubleshooting**

* **No interfaces found** → Ensure adapter supports monitor mode
* **Permission errors** → Run with `sudo`
* **Missing dependencies** → Install listed tools
* **Scan failures** → Ensure interface is in monitor mode & drivers are installed

---

## 🤝 **Contributing**

We welcome contributions:

1. Fork the repo
2. Create a feature branch
3. Commit changes
4. Submit a PR

---

## 📄 **License**

Licensed under the **MIT License** – see `LICENSE` for details.

---

## 🔄 **Version History**

**v2.0.0** – Modern UI, advanced cracking modes, mask attack support, enhanced Linux compatibility, improved error handling.
**v1.0.0** – Basic functionality, initial release.

---
<img width="1022" height="143" alt="Tabs" src="https://github.com/user-attachments/assets/3738bd5b-a06e-488a-a2b6-b3ee6182a990" />
<img width="1366" height="768" alt="Scanned And Discovered Networks" src="https://github.com/user-attachments/assets/3b8477df-675b-4366-a5cf-3a08847498e7" />
<img width="1366" height="768" alt="Robust Crack" src="https://github.com/user-attachments/assets/9a39a638-3ead-4141-a449-ba4ab027be2b" />
<img width="1366" height="768" alt="Robust Crack In Play" src="https://github.com/user-attachments/assets/836cc0a0-6556-4de7-90d2-87dca433eeca" />
<img width="1366" height="768" alt="Quick Crack" src="https://github.com/user-attachments/assets/4422e869-8e19-4b73-b0b4-b2e80e517506" />
<img width="1366" height="768" alt="Password Found" src="https://github.com/user-attachments/assets/53172b79-b580-4ac8-a156-86335f08bbf3" />
<img width="1366" height="768" alt="Password Crack" src="https://github.com/user-attachments/assets/446db5b3-6028-4fa5-88cc-7ea7ca7b06f8" />
<img width="1366" height="768" alt="Network Discovery" src="https://github.com/user-attachments/assets/13ba0ff2-b3c1-4401-9c46-53d504f3e3e2" />
<img width="1366" height="768" alt="Handshake and Capture" src="https://github.com/user-attachments/assets/9ee8040c-2092-41be-ab52-f375885d147a" />
<img width="1366" height="768" alt="Error Please select a device to deauth" src="https://github.com/user-attachments/assets/227b504f-abe3-45c1-ba86-0ee6173d0cdc" />
<img width="1366" height="768" alt="Deauth In Play" src="https://github.com/user-attachments/assets/15cb5580-f38c-47b7-9aaf-9ce3ebac423b" />
<img width="1366" height="768" alt="Connected Devices" src="https://github.com/user-attachments/assets/a84aaaef-e57d-4954-816e-d0251fba2de4" />
<img width="1366" height="768" alt="Capture and Deauth Stopped" src="https://github.com/user-attachments/assets/1daa8cef-c48d-4060-91c0-da1da1d4691c" />

