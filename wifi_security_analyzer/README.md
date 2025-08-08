Wi-Fi Security Analyzer
Wi-Fi Security Analyzer is a Python-based GUI application built with Tkinter for analyzing Wi-Fi network security. It provides tools for network scanning, handshake capturing, and password cracking using tools like aircrack-ng, aireplay-ng, hashcat, and hcxpcapngtool. This tool is for educational and authorized security testing purposes only. Unauthorized use is illegal.
Features

Network Discovery: Scans for nearby Wi-Fi networks, displaying details like BSSID, ESSID, channel, signal strength, encryption, cipher, and authentication.
Handshake Capture: Captures WPA/WPA2 handshakes by targeting specific networks and sending deauthentication packets.
Password Cracking:
Quick Crack: Uses aircrack-ng for fast dictionary-based cracking without manual BSSID specification.
Advanced Crack: Allows manual BSSID specification for targeted aircrack-ng cracking.
Robust Crack: Employs Hashcat for multi-stage attacks (dictionary, hybrid, mask, brute force) with custom wordlist generation.


User-Friendly Interface: Modern Tkinter GUI with fieldsets (using ttk.LabelFrame) for organized sections, real-time logging, and responsive controls.
Monitor Mode Management: Automatically enables monitor mode on selected network interfaces.

Prerequisites

Operating System: Linux (recommended, e.g., Kali Linux) for full functionality. Some features may work on Windows/Mac with limitations.
Root Privileges: Required for network operations (sudo python3 app.py).
Dependencies:
Python 3.6+
Tkinter (included with Python)
External tools: aircrack-ng, aireplay-ng, iw, tcpdump, hashcat, hcxpcapngtool, crunch
Install dependencies via requirements.txt (see Installation).



Installation

Clone the repository or download the project files:git clone <repository-url>
cd wifi_security_analyzer


Install Python dependencies:pip install -r requirements.txt


Install required system tools (on Debian-based systems like Kali Linux):sudo apt-get update
sudo apt-get install aircrack-ng tcpdump iw hashcat hcxtools crunch



Usage

Run the application with root privileges:sudo python3 app.py


Accept the legal disclaimer to proceed.
Navigate through the tabs:
Network Discovery: Select an interface, enable monitor mode, and scan for networks. Double-click a network to select it for handshake capture.
Handshake Capture: Configure BSSID, channel, and client settings, then capture handshakes using deauthentication attacks.
Quick Crack: Select a handshake file and wordlist for fast cracking with aircrack-ng.
Advanced Crack: Specify BSSID and wordlist for targeted cracking with aircrack-ng.
Robust Crack: Use Hashcat for advanced cracking with dictionary, hybrid, mask, or brute-force attacks. Generate custom wordlists with patterns.


Monitor progress via the System Log section at the bottom.

File Structure

app.py: Main application script, initializes the Tkinter GUI, sets up styles, and manages tabs.
network_tab.py: Handles network scanning and interface configuration, displaying results in a table.
handshake_tab.py: Manages handshake capture with deauthentication options.
cracking_tab.py: Implements advanced cracking with manual BSSID specification using aircrack-ng.
quick_crack_tab.py: Provides fast dictionary-based cracking with automatic BSSID detection.
robust_crack_tab.py: Offers multi-stage Hashcat-based cracking with custom wordlist generation.
utils.py: Utility functions (e.g., run_command) for executing system commands safely.
requirements.txt: Lists Python dependencies required for the project.

Legal Disclaimer
This tool is for educational purposes and authorized security testing only. Unauthorized access to networks is illegal and may result in criminal charges. Use only on networks you own or have explicit written permission to test. Always comply with local laws and regulations.
Troubleshooting

No interfaces found: Ensure a compatible wireless adapter is connected and supports monitor mode.
Permission errors: Run the application with sudo to enable network operations.
Missing dependencies: Install all required tools listed in Prerequisites.
Scan failures: Verify the interface is in monitor mode and aircrack-ng is installed.

Contributing
Contributions are welcome! Please submit pull requests or issues via the repository. Ensure compliance with the legal disclaimer in all modifications.
License
This project is licensed under the MIT License. See the LICENSE file for details (not included in this structure but recommended to add).