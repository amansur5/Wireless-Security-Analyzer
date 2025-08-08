import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from utils import run_command

class CrackingTab:
    def __init__(self, notebook, app):
        self.app = app
        self.cracking_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.cracking_tab, text="Password Cracking")

        # Initialize variables
        self.wordlist_file = tk.StringVar()
        self.is_cracking = False
        self.current_progress = ""

        # Create main container
        self.create_file_selection()

    def create_file_selection(self):
        """Create the file selection section with handshake and wordlist on one line."""
        file_frame = ttk.LabelFrame(self.cracking_tab, text="File Selection", style='Card.TLabelframe')
        file_frame.pack(fill="x", padx=10, pady=10)

        # File selection container
        file_container = ttk.Frame(file_frame)
        file_container.pack(fill="x", padx=15, pady=10)

        # Handshake and Wordlist file selection on one line
        file_selection_frame = ttk.Frame(file_container)
        file_selection_frame.pack(fill="x", pady=(0, 10))

        # Handshake file
        ttk.Label(file_selection_frame, text="Handshake File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.app.handshake_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        handshake_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_handshake_file)
        handshake_btn.pack(side="left", padx=(0, 10))

        # Wordlist file
        ttk.Label(file_selection_frame, text="Wordlist File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.wordlist_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        wordlist_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_wordlist_file)
        wordlist_btn.pack(side="left")

        # BSSID input
        bssid_frame = ttk.Frame(file_container)
        bssid_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(bssid_frame, text="Target BSSID:", style='Info.TLabel').pack(anchor="w")
        ttk.Label(bssid_frame, text="(From Handshake & Capture tab or enter manually)", style='Info.TLabel').pack(anchor="w")
        ttk.Entry(bssid_frame, textvariable=self.app.selected_bssid, font=('Arial', 10)).pack(fill="x", pady=(5, 0))

        # Control buttons
        control_container = ttk.Frame(file_container)
        control_container.pack(fill="x", pady=10)
        crack_btn = ttk.Button(control_container, text="🔓 Start Cracking", style='Success.TButton', command=self.start_cracking)
        crack_btn.pack(side="left", padx=(0, 10))
        stop_btn = ttk.Button(control_container, text="⏹️ Stop Cracking", style='Danger.TButton', command=self.stop_cracking)
        stop_btn.pack(side="left", padx=(0, 10))
        clear_btn = ttk.Button(control_container, text="🗑️ Clear Wordlist", style='Warning.TButton', command=self.clear_wordlist)
        clear_btn.pack(side="left")

        # Progress bar
        self.progress_bar = ttk.Progressbar(file_container, mode='indeterminate', style='TProgressbar')
        self.progress_bar.pack(fill="x", pady=(10, 5))

        # Status indicator
        self.status_label = ttk.Label(file_container, text="Ready to crack passwords", style='Info.TLabel')
        self.status_label.pack(pady=(5, 0))

    def select_handshake_file(self):
        """Select handshake capture file."""
        file_path = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap")])
        if file_path:
            self.app.handshake_file.set(file_path)
            self.app.log_message(f"Selected handshake file: {file_path}", "SUCCESS")

    def select_wordlist_file(self):
        """Select wordlist file."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.wordlist_file.set(file_path)
            self.app.log_message(f"Selected wordlist file: {file_path}", "SUCCESS")

    def clear_wordlist(self):
        """Clear the selected wordlist."""
        self.wordlist_file.set("")
        self.app.log_message("Wordlist selection cleared.", "INFO")

    def stop_cracking(self):
        """Stop the cracking process."""
        if self.is_cracking:
            run_command("pkill -9 -f 'aircrack-ng'", capture_output=False)
            self.is_cracking = False
            self.progress_bar.stop()
            self.status_label.configure(text="Cracking stopped")
            self.app.log_message("Password cracking stopped.", "INFO")
            self.app.root.after(0, lambda: messagebox.showinfo("Success", "Password cracking process stopped."))

    def start_cracking(self):
        """Start password cracking with aircrack-ng."""
        handshake = self.app.handshake_file.get()
        wordlist = self.wordlist_file.get()
        bssid = self.app.selected_bssid.get()

        if not handshake or not wordlist:
            self.app.log_message("Please select both handshake and wordlist files.", "ERROR")
            messagebox.showerror("Error", "Please select both handshake and wordlist files.")
            return
        if not os.path.exists(handshake):
            self.app.log_message(f"Handshake file does not exist: {handshake}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return
        if not os.path.exists(wordlist):
            self.app.log_message(f"Wordlist file does not exist: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file does not exist.")
            return
        if os.path.getsize(wordlist) == 0:
            self.app.log_message(f"Wordlist file is empty: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file is empty.")
            return
        if not bssid:
            self.app.log_message("Please enter or select a network BSSID.", "ERROR")
            messagebox.showerror("Error", "Please enter or select a network BSSID.")
            return
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", bssid):
            self.app.log_message(f"Invalid BSSID format: {bssid}", "ERROR")
            messagebox.showerror("Error", "Invalid BSSID format. Use XX:XX:XX:XX:XX:XX (e.g., 00:11:22:33:44:55).")
            return

        def validate_handshake():
            self.app.log_message("Validating handshake file...", "INFO")
            self.status_label.configure(text="Validating handshake")
            process = subprocess.Popen(
                f"aircrack-ng {handshake}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output, error = process.communicate()
            if "No valid WPA handshakes found" in output or "No valid WPA handshakes found" in error:
                self.app.log_message("No valid WPA handshake found in the capture file.", "ERROR")
                self.status_label.configure(text="Invalid handshake file")
                return False
            self.app.log_message("Handshake file validated successfully.", "SUCCESS")
            return True

        def crack():
            if not validate_handshake():
                self.progress_bar.stop()
                self.status_label.configure(text="Ready to crack passwords")
                return

            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Cracking in progress...")
            self.app.log_message(f"Starting password cracking with handshake: {handshake}, wordlist: {wordlist}, BSSID: {bssid}", "INFO")

            process = subprocess.Popen(
                f"aircrack-ng -w {wordlist} -b {bssid} {handshake}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            progress_regex = re.compile(r"\[\s*(\d+)/(\d+)\s*\]\s*(\d+\.\d+\s*keys/s)?")
            while process.poll() is None and self.is_cracking:
                line = process.stdout.readline()
                if line:
                    self.app.log_message(line.strip(), "INFO")
                    match = progress_regex.search(line)
                    if match:
                        current_keys, total_keys = match.group(1), match.group(2)
                        speed = match.group(3) or "N/A"
                        progress_text = f"Cracking: {current_keys}/{total_keys} keys tested ({speed})"
                        self.current_progress = progress_text
                        self.app.root.after(0, lambda: self.status_label.configure(text=progress_text))
                        self.app.log_message(f"Progress: {progress_text}", "INFO")
                    self.app.log_text.see(tk.END)
                    self.app.root.update()
                time.sleep(0.1)

            if not self.is_cracking:
                return

            output, error = process.communicate()
            self.is_cracking = False
            self.progress_bar.stop()

            if output:
                self.app.log_message(output.strip(), "INFO")
            if error:
                self.app.log_message(f"Error: {error.strip()}", "ERROR")

            if "KEY FOUND" in output:
                match = re.search(r"KEY FOUND! \[ (.+?) \]", output)
                if match:
                    password = match.group(1)
                    self.app.log_message(f"Password found: {password}", "SUCCESS")
                    self.status_label.configure(text=f"Password found: {password}")
                    self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                else:
                    self.app.log_message("Password found but could not parse key.", "WARNING")
                    self.status_label.configure(text="Password found (key parsing failed)")
            else:
                self.app.log_message("Password not found in wordlist.", "WARNING")
                self.status_label.configure(text="Password not found")
                self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found in wordlist. Try a different wordlist or capture."))

            self.app.log_text.see(tk.END)

        threading.Thread(target=crack, daemon=True).start()