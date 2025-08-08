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

If you want, I can also **add diagrams or screenshots** of the interface and workflow so your README looks even more polished and GitHub-ready. That will make it much more attractive for users and contributors.
