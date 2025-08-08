import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import threading
import os
import time
from utils import run_command

class NetworkTab:
    def __init__(self, notebook, app):
        self.app = app
        self.network_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.network_tab, text="Network Discovery")

        # Create main container with proper layout
        self.create_interface_and_scan()
        self.create_network_list()

        self.refresh_interfaces()

    def create_interface_and_scan(self):
        """Create the combined interface configuration and network scan section within a fieldset with legend."""
        # Using ttk.LabelFrame as a fieldset with 'Interface Configuration and Network Scan' as the legend
        interface_frame = ttk.LabelFrame(self.network_tab, text="Interface Configuration and Network Scan", style='Card.TLabelframe')
        interface_frame.pack(fill="x", padx=15, pady=15)

        # Interface and scan controls container
        controls_container = ttk.Frame(interface_frame)
        controls_container.pack(fill="x", padx=15, pady=10)

        # Interface label
        ttk.Label(controls_container, text="Select Interface:", style='Info.TLabel').pack(side="left", padx=(0, 10))
        
        # Interface combo (wider)
        self.interface_combo = ttk.Combobox(controls_container, textvariable=self.app.interface, font=('Arial', 11), width=20)
        self.interface_combo.pack(side="left", padx=(0, 10))
        
        # Refresh button
        refresh_btn = ttk.Button(controls_container, text="Refresh", style='Primary.TButton', command=self.refresh_interfaces)
        refresh_btn.pack(side="left", padx=(0, 10))

        # Enable monitor mode button
        monitor_btn = ttk.Button(controls_container, text="Enable Monitor Mode", style='Success.TButton', command=self.enable_monitor_mode)
        monitor_btn.pack(side="left", padx=(0, 10))

        # Scan networks button
        scan_btn = ttk.Button(controls_container, text="Scan Networks", style='Primary.TButton', command=self.scan_networks)
        scan_btn.pack(side="left", padx=(0, 10))

        # Stop scan button
        stop_scan_btn = ttk.Button(controls_container, text="Stop Scan", style='Secondary.TButton', command=self.stop_scan)
        stop_scan_btn.pack(side="left", padx=(0, 10))

        # Load scan file button
        load_btn = ttk.Button(controls_container, text="Load Scan File Manually", style='Warning.TButton', command=self.load_scan_file)
        load_btn.pack(side="left")

    def create_network_list(self):
        """Create the network list display with visible scrollbars within a fieldset with legend."""
        # Using ttk.LabelFrame as a fieldset with 'Discovered Networks' as the legend
        list_frame = ttk.LabelFrame(self.network_tab, text="Discovered Networks", style='Card.TLabelframe')
        list_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Treeview container
        tree_container = ttk.Frame(list_frame)
        tree_container.pack(fill="both", expand=True, padx=15, pady=10)

        # Create treeview with clean styling
        self.network_tree = ttk.Treeview(tree_container, 
                                        columns=("BSSID", "ESSID", "Channel", "Power", "ENC", "CIPHER", "AUTH"), 
                                        show="headings",
                                        height=15,
                                        style='Clean.Treeview')
        
        # Configure custom Treeview style
        style = ttk.Style()
        style.configure('Clean.Treeview',
                       background='#ffffff',
                       foreground='#000000',
                       fieldbackground='#ffffff',
                       font=('Arial', 11))
        style.map('Clean.Treeview',
                 background=[('selected', '#b3d7ff')],
                 foreground=[('selected', '#000000')])
        
        # Configure tag for WPA2 networks
        style.configure('wpa2_tag', foreground='#0078d7')  # Blue for WPA2
        
        # Configure columns
        self.network_tree.heading("BSSID", text="BSSID")
        self.network_tree.heading("ESSID", text="Network Name")
        self.network_tree.heading("Channel", text="Channel")
        self.network_tree.heading("Power", text="Signal (dBm)")
        self.network_tree.heading("ENC", text="Encryption")
        self.network_tree.heading("CIPHER", text="Cipher")
        self.network_tree.heading("AUTH", text="Authentication")

        # Set column widths
        self.network_tree.column("BSSID", width=150, minwidth=120)
        self.network_tree.column("ESSID", width=200, minwidth=150)
        self.network_tree.column("Channel", width=80, minwidth=60)
        self.network_tree.column("Power", width=100, minwidth=80)
        self.network_tree.column("ENC", width=100, minwidth=80)
        self.network_tree.column("CIPHER", width=100, minwidth=80)
        self.network_tree.column("AUTH", width=120, minwidth=100)

        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_container, orient="vertical", command=self.network_tree.yview, style='Vertical.TScrollbar')
        tree_scroll_x = ttk.Scrollbar(tree_container, orient="horizontal", command=self.network_tree.xview, style='Horizontal.TScrollbar')
        self.network_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Pack treeview and scrollbars
        self.network_tree.pack(side="left", fill="both", expand=True)
        tree_scroll_y.pack(side="right", fill="y")
        tree_scroll_x.pack(side="bottom", fill="x")

        # Bind double-click event for network selection
        self.network_tree.bind("<Double-1>", self.on_network_select)

    def on_network_select(self, event):
        """Handle network selection from treeview."""
        selection = self.network_tree.selection()
        if selection:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values:
                bssid = values[0]
                essid = values[1]
                channel = values[2]
                
                # Update app variables
                self.app.selected_bssid.set(bssid)
                self.app.selected_channel.set(channel)
                
                # Log selection
                self.app.log_message(f"Selected network: {essid} ({bssid}) on channel {channel}", "SUCCESS")

    def refresh_interfaces(self):
        """Populate available network interfaces."""
        self.app.log_message("Scanning for wireless interfaces...", "INFO")

        interfaces = []
        output = run_command("iwconfig")
        if output and not output.startswith("Error"):
            interfaces = re.findall(r"(\w+)\s+IEEE 802\.11", output)
            self.app.log_message(f"iwconfig found: {', '.join(interfaces) if interfaces else 'No interfaces'}", "INFO")
        else:
            self.app.log_message("iwconfig command failed or returned no output.", "ERROR")

        if not interfaces:
            output = run_command("iw dev")
            if output and not output.startswith("Error"):
                interfaces = re.findall(r"Interface (\w+)", output)
                self.app.log_message(f"iw dev found: {', '.join(interfaces) if interfaces else 'No interfaces'}", "INFO")
            else:
                self.app.log_message("iw dev command failed or returned no output.", "ERROR")

        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.current(0)  # Auto-select first interface
            self.app.interface.set(interfaces[0])
            self.app.log_message(f"Auto-selected interface: {interfaces[0]}", "INFO")
        else:
            self.interface_combo.set("")
            self.interface_combo.configure(state="normal")
            self.interface_combo.delete(0, tk.END)
            self.interface_combo.insert(0, "Select or type interface")
            self.interface_combo.configure(state="readonly")
            self.app.log_message("No wireless interfaces found. Enter interface manually (e.g., wlan0).", "WARNING")

    def enable_monitor_mode(self):
        """Enable monitor mode on selected interface."""
        interface = self.app.interface.get()
        if not interface or interface == "Select or type interface":
            self.app.log_message("No network interface selected.", "ERROR")
            messagebox.showerror("Error", "Please select or enter a network interface.")
            return

        self.app.log_message(f"Verifying interface {interface}...", "INFO")

        iw_output = run_command(f"iw dev {interface} info")
        if iw_output and "type monitor" in iw_output:
            self.app.log_message(f"{interface} is already in monitor mode.", "INFO")
            self.app.monitor_interface.set(interface)
            messagebox.showinfo("Success", f"{interface} is already in monitor mode. Using it as the monitor interface.")
            return

        if not iw_output or ("type managed" not in iw_output and "type monitor" not in iw_output):
            self.app.log_message(f"{interface} is not a valid wireless interface.", "ERROR")
            messagebox.showerror("Error", f"{interface} is not a valid wireless interface. Check with 'iw dev'.")
            return

        self.app.log_message(f"Stopping conflicting services for {interface}...", "INFO")
        run_command("service NetworkManager stop", capture_output=False)
        run_command("airmon-ng check kill", capture_output=False)

        run_command(f"airmon-ng stop {interface}mon", capture_output=False)
        run_command("airmon-ng stop mon0", capture_output=False)

        self.app.log_message(f"Starting monitor mode on {interface}...", "INFO")
        output = run_command(f"airmon-ng start {interface}")
        if output and not output.startswith("Error"):
            self.app.log_message(f"airmon-ng output: {output}", "INFO")
            match = re.search(r"monitor mode (?:enabled|vif enabled) (?:for.*?\[phy\d+\]\S+ on \[phy\d+\](\S+)|on (\S+))", output)
            if not match:
                iw_output = run_command("iw dev")
                if iw_output and not output.startswith("Error"):
                    match = re.search(r"Interface (\w+mon|mon\d+|\d+)", iw_output)
            if match:
                monitor_if = match.group(1) if match.group(1) else match.group(2)
                self.app.monitor_interface.set(monitor_if)
                self.app.log_message(f"Monitor mode enabled on {monitor_if}", "SUCCESS")
                messagebox.showinfo("Success", f"Monitor mode enabled on {monitor_if}")
            else:
                self.app.log_message("Failed to detect monitor interface. Try entering manually (e.g., wlan0mon, mon0, or 10).", "ERROR")
                messagebox.showerror("Error", "Failed to detect monitor interface. Run 'airmon-ng start wlan0' manually to check the name.")
        else:
            self.app.log_message("airmon-ng command failed. Ensure aircrack-ng is installed and adapter supports monitor mode.", "ERROR")
            messagebox.showerror("Error", "Failed to enable monitor mode.")

    def scan_networks(self):
        """Scan for nearby Wi-Fi networks."""
        monitor = self.app.monitor_interface.get()
        if not monitor:
            self.app.log_message("No monitor interface selected.", "ERROR")
            messagebox.showerror("Error", "Please enable monitor mode first.")
            return

        self.app.log_message(f"Verifying monitor interface {monitor}...", "INFO")

        iw_output = run_command(f"iw dev {monitor} info")
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode. Please enable monitor mode.", "ERROR")
            messagebox.showerror("Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return

        self.app.log_message("Network scan started, please wait ~20 seconds or click 'Stop Scan'...", "INFO")

        for item in self.network_tree.get_children():
            self.network_tree.delete(item)

        def scan():
            if os.path.exists("scan-01.csv"):
                try:
                    os.remove("scan-01.csv")
                    self.app.log_message("Removed existing scan-01.csv.", "INFO")
                except Exception as e:
                    self.app.log_message(f"Error removing scan-01.csv: {str(e)}", "ERROR")

            cmd = f"airodump-ng --write scan --output-format csv {monitor}"
            self.app.log_message(f"Running: {cmd}", "INFO")
            try:
                self.app.scan_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            except Exception as e:
                self.app.log_message(f"Failed to start airodump-ng: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Failed to start network scan: {str(e)}. Ensure aircrack-ng is installed and run with sudo.")
                self.app.scan_process = None
                return

            time.sleep(20)
            if self.app.scan_process:
                try:
                    self.app.scan_process.terminate()
                    stdout, stderr = self.app.scan_process.communicate(timeout=5)
                    self.app.log_message("airodump-ng terminated gracefully.", "INFO")
                    if stdout:
                        self.app.log_message(f"airodump-ng stdout: {stdout}", "INFO")
                    if stderr:
                        self.app.log_message(f"airodump-ng stderr: {stderr}", "ERROR")
                except subprocess.TimeoutExpired:
                    self.app.log_message("airodump-ng did not terminate gracefully, forcing kill.", "WARNING")
                    run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)
                    stdout, stderr = self.app.scan_process.communicate(timeout=1)
                    if stdout:
                        self.app.log_message(f"airodump-ng stdout: {stdout}", "INFO")
                    if stderr:
                        self.app.log_message(f"airodump-ng stderr: {stderr}", "ERROR")
                finally:
                    self.app.scan_process = None
            else:
                self.app.log_message("No active scan process to terminate.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)

            if not os.path.exists("scan-01.csv"):
                self.app.log_message("Error: scan-01.csv not found. Scan may have failed.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", "Scan failed: scan-01.csv not found. Check log output for airodump-ng errors.")
                return

            try:
                networks = []
                with open("scan-01.csv", "r", encoding="utf-8") as f:
                    self.app.log_message("Reading scan-01.csv...", "INFO")
                    lines = f.readlines()
                    self.app.log_message(f"Found {len(lines)} lines in scan-01.csv.", "INFO")
                    ap_section = True
                    for i, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            self.app.log_message(f"Line {i+1}: Skipping empty line.", "INFO")
                            continue
                        if line.startswith("Station MAC"):
                            ap_section = False
                            self.app.log_message(f"Line {i+1}: Reached station section, stopping AP parsing.", "INFO")
                            break
                        if ap_section and "," in line:
                            parts = [part.strip() for part in line.split(",")]
                            self.app.log_message(f"Line {i+1}: {len(parts)} fields - {line}", "INFO")
                            if len(parts) >= 14:  # Ensure enough fields for ESSID
                                bssid = parts[0].strip()
                                channel = parts[3].strip() if len(parts) > 3 else ""
                                power = parts[8].strip() if len(parts) > 8 else ""
                                essid = parts[13].strip() if len(parts) > 13 else ""
                                enc = parts[5].strip() if len(parts) > 5 else ""
                                cipher = parts[6].strip() if len(parts) > 6 else ""
                                auth = parts[7].strip() if len(parts) > 7 else ""
                                if bssid and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                                    try:
                                        power_val = int(power) if power and power != "-1" else -100
                                    except ValueError:
                                        power_val = -100
                                    networks.append((bssid, essid, channel, power, enc, cipher, auth, power_val))
                                    self.app.log_message(f"Line {i+1}: Added AP - BSSID: {bssid}, ESSID: {essid}", "SUCCESS")
                                else:
                                    self.app.log_message(f"Line {i+1}: Invalid BSSID format: {bssid}", "WARNING")
                            else:
                                self.app.log_message(f"Line {i+1}: Too few fields ({len(parts)}), skipping.", "WARNING")
                    if not networks:
                        self.app.log_message("No valid access points found in scan-01.csv.", "WARNING")

                # Sort networks by power (descending)
                networks.sort(key=lambda x: x[7], reverse=True)
                for network in networks:
                    bssid, essid, channel, power, enc, cipher, auth, _ = network
                    item_id = self.network_tree.insert("", "end", values=(bssid, essid, channel, power, enc, cipher, auth))
                    if "WPA2" in enc:
                        self.network_tree.item(item_id, tags=('wpa2_tag',))
                self.network_tree.update_idletasks()
                self.app.log_message(f"Treeview refreshed. Current items: {len(self.network_tree.get_children())}", "DEBUG")
            except FileNotFoundError:
                self.app.log_message("Error: scan-01.csv not found after scan.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", "Scan failed: scan-01.csv not found.")
            except Exception as e:
                self.app.log_message(f"Error parsing scan-01.csv: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Error parsing scan-01.csv: {str(e)}")
            finally:
                if os.path.exists("scan-01.csv"):
                    try:
                        os.remove("scan-01.csv")
                        self.app.log_message("Cleaned up scan-01.csv.", "INFO")
                    except Exception as e:
                        self.app.log_message(f"Error cleaning up scan-01.csv: {str(e)}", "ERROR")

        threading.Thread(target=scan, daemon=True).start()

    def stop_scan(self):
        """Stop the network scan process."""
        monitor = self.app.monitor_interface.get()
        if self.app.scan_process:
            try:
                self.app.scan_process.terminate()
                stdout, stderr = self.app.scan_process.communicate(timeout=5)
                self.app.log_message("Network scan stopped gracefully.", "INFO")
                if stdout:
                    self.app.log_message(f"airodump-ng stdout: {stdout}", "INFO")
                if stderr:
                    self.app.log_message(f"airodump-ng stderr: {stderr}", "ERROR")
            except subprocess.TimeoutExpired:
                self.app.log_message("Network scan did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)
                stdout, stderr = self.app.scan_process.communicate(timeout=1)
                if stdout:
                    self.app.log_message(f"airodump-ng stdout: {stdout}", "INFO")
                if stderr:
                    self.app.log_message(f"airodump-ng stderr: {stderr}", "ERROR")
            finally:
                self.app.scan_process = None
            self.app.root.after(0, messagebox.showinfo, "Success", "Network scan stopped.")
        else:
            self.app.log_message("No active scan to stop.", "INFO")
            self.app.root.after(0, messagebox.showinfo, "Info", "No active scan to stop.")
        # Ensure no lingering processes
        run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)

    def load_scan_file(self):
        """Manually load a scan-01.csv file."""
        file_path = tk.filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        self.app.log_message(f"Loading scan file: {file_path}...", "INFO")

        for item in self.network_tree.get_children():
            self.network_tree.delete(item)

        try:
            networks = []
            with open(file_path, "r", encoding="utf-8") as f:
                self.app.log_message(f"Found {len(lines)} lines in {file_path}.", "INFO")
                ap_section = True
                for i, line in enumerate(lines):
                    line = line.strip()
                    if not line:
                        self.app.log_message(f"Line {i+1}: Skipping empty line.", "INFO")
                        continue
                    if line.startswith("Station MAC"):
                        ap_section = False
                        self.app.log_message(f"Line {i+1}: Reached station section, stopping AP parsing.", "INFO")
                        break
                    if ap_section and "," in line:
                        parts = [part.strip() for part in line.split(",")]
                        self.app.log_message(f"Line {i+1}: {len(parts)} fields - {line}", "INFO")
                        if len(parts) >= 14:  # Ensure enough fields for ESSID
                            bssid = parts[0].strip()
                            channel = parts[3].strip() if len(parts) > 3 else ""
                            power = parts[8].strip() if len(parts) > 8 else ""
                            essid = parts[13].strip() if len(parts) > 13 else ""
                            enc = parts[5].strip() if len(parts) > 5 else ""
                            cipher = parts[6].strip() if len(parts) > 6 else ""
                            auth = parts[7].strip() if len(parts) > 7 else ""
                            if bssid and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
                                try:
                                    power_val = int(power) if power and power != "-1" else -100
                                except ValueError:
                                    power_val = -100
                                networks.append((bssid, essid, channel, power, enc, cipher, auth, power_val))
                                self.app.log_message(f"Line {i+1}: Added AP - BSSID: {bssid}, ESSID: {essid}", "SUCCESS")
                            else:
                                self.app.log_message(f"Line {i+1}: Invalid BSSID format: {bssid}", "WARNING")
                        else:
                            self.app.log_message(f"Line {i+1}: Too few fields ({len(parts)}), skipping.", "WARNING")
                if not networks:
                    self.app.log_message("No valid access points found in scan file.", "WARNING")

            # Sort networks by power (descending)
            networks.sort(key=lambda x: x[7], reverse=True)
            for network in networks:
                bssid, essid, channel, power, enc, cipher, auth, _ = network
                item_id = self.network_tree.insert("", "end", values=(bssid, essid, channel, power, enc, cipher, auth))
                if "WPA2" in enc:
                    self.network_tree.item(item_id, tags=('wpa2_tag',))
            self.network_tree.update_idletasks()
            self.app.log_message(f"Treeview refreshed after loading scan file. Current items: {len(self.network_tree.get_children())}", "DEBUG")
        except Exception as e:
            self.app.log_message(f"Error parsing scan file: {str(e)}", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"Error parsing scan file: {str(e)}")