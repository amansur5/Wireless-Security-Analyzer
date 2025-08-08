import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import re
import threading
import os
import time
from utils import run_command

class QuickCrackTab:
    def __init__(self, notebook, app):
        self.app = app
        self.quick_crack_tab = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.quick_crack_tab, text="Quick Crack")

        # Initialize variables
        self.is_cracking = False

        # Create main container
        self.create_file_selection()

    def create_file_selection(self):
        """Create the file selection section with handshake and wordlist on one line."""
        file_frame = ttk.LabelFrame(self.quick_crack_tab, text="File Selection", style='Card.TLabelframe')
        file_frame.pack(fill="x", padx=10, pady=10)

        # File selection container
        file_container = ttk.Frame(file_frame)
        file_container.pack(fill="x", padx=15, pady=10)

        # Handshake and Wordlist file selection on one line
        file_selection_frame = ttk.Frame(file_container)
        file_selection_frame.pack(fill="x", pady=(0, 10))

        # Handshake file
        ttk.Label(file_selection_frame, text="Handshake File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.app.quick_handshake_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        handshake_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_quick_handshake_file)
        handshake_btn.pack(side="left", padx=(0, 10))

        # Wordlist file
        ttk.Label(file_selection_frame, text="Wordlist File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        ttk.Entry(file_selection_frame, textvariable=self.app.quick_wordlist_file, state="readonly", font=('Arial', 10), width=15).pack(side="left", padx=(0, 10))
        wordlist_btn = ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', command=self.select_quick_wordlist_file)
        wordlist_btn.pack(side="left")

        # Description
        desc_label = ttk.Label(file_container, text="Quick crack mode automatically detects BSSID from handshake file", style='Info.TLabel')
        desc_label.pack(anchor="w", pady=(0, 10))

        # Control buttons
        control_container = ttk.Frame(file_container)
        control_container.pack(fill="x", pady=10)
        crack_btn = ttk.Button(control_container, text="⚡ Start Quick Crack", style='Success.TButton', command=self.start_quick_crack)
        crack_btn.pack(side="left", padx=(0, 10))
        stop_btn = ttk.Button(control_container, text="⏹️ Stop Quick Crack", style='Danger.TButton', command=self.stop_quick_crack)
        stop_btn.pack(side="left", padx=(0, 10))
        clear_btn = ttk.Button(control_container, text="🗑️ Clear Wordlist", style='Warning.TButton', command=self.clear_wordlist)
        clear_btn.pack(side="left")

        # Progress bar
        self.progress_bar = ttk.Progressbar(file_container, mode='indeterminate', style='TProgressbar')
        self.progress_bar.pack(fill="x", pady=(10, 5))

        # Status indicator
        self.status_label = ttk.Label(file_container, text="Ready for quick password cracking", style='Info.TLabel')
        self.status_label.pack(pady=(5, 0))

    def select_quick_handshake_file(self):
        """Select handshake file for quick crack."""
        file_path = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap")])
        if file_path:
            self.app.quick_handshake_file.set(file_path)
            self.app.log_message(f"Selected quick crack handshake file: {file_path}", "SUCCESS")

    def select_quick_wordlist_file(self):
        """Select wordlist file for quick crack."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.app.quick_wordlist_file.set(file_path)
            self.app.log_message(f"Selected quick crack wordlist file: {file_path}", "SUCCESS")

    def clear_wordlist(self):
        """Clear the selected wordlist."""
        self.app.quick_wordlist_file.set("")
        self.app.log_message("Quick crack wordlist selection cleared.", "INFO")

    def stop_quick_crack(self):
        """Stop the quick crack process."""
        if self.is_cracking:
            run_command("pkill -9 -f 'aircrack-ng'", capture_output=False)
            self.is_cracking = False
            self.progress_bar.stop()
            self.status_label.configure(text="Quick cracking stopped")
            self.app.log_message("Quick password cracking stopped.", "INFO")
            self.app.root.after(0, lambda: messagebox.showinfo("Success", "Quick password cracking process stopped."))

    def start_quick_crack(self):
        """Start password cracking with aircrack-ng without specifying BSSID."""
        handshake = self.app.quick_handshake_file.get()
        wordlist = self.app.quick_wordlist_file.get()

        if not handshake or not wordlist:
            self.app.log_message("Please select both handshake and wordlist files for quick crack.", "ERROR")
            messagebox.showerror("Error", "Please select both handshake and wordlist files.")
            return
        if not os.path.exists(handshake):
            self.app.log_message(f"Quick crack handshake file does not exist: {handshake}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return
        if not os.path.exists(wordlist):
            self.app.log_message(f"Quick crack wordlist file does not exist: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file does not exist.")
            return
        if os.path.getsize(wordlist) == 0:
            self.app.log_message(f"Quick crack wordlist file is empty: {wordlist}", "ERROR")
            messagebox.showerror("Error", "Wordlist file is empty.")
            return

        def validate_handshake():
            self.app.log_message("Validating quick crack handshake file...", "INFO")
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
                self.app.log_message("No valid WPA handshake found in the quick crack capture file.", "ERROR")
                self.status_label.configure(text="Invalid handshake file")
                return False, None
            bssid_match = re.search(r"BSSID\s+([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", output)
            bssid = bssid_match.group(1) if bssid_match else None
            if bssid:
                self.app.log_message(f"Detected BSSID: {bssid}", "SUCCESS")
            else:
                self.app.log_message("Could not detect BSSID from handshake file.", "WARNING")
            self.app.log_message("Quick crack handshake file validated successfully.", "SUCCESS")
            return True, bssid

        def crack():
            valid, bssid = validate_handshake()
            if not valid:
                self.progress_bar.stop()
                self.status_label.configure(text="Ready for quick password cracking")
                return

            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Quick cracking in progress...")
            self.app.log_message(f"Starting quick password cracking with handshake: {handshake}, wordlist: {wordlist}", "INFO")

            process = subprocess.Popen(
                f"aircrack-ng -w {wordlist} {handshake}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            while process.poll() is None and self.is_cracking:
                line = process.stdout.readline()
                if line:
                    self.app.log_message(line.strip(), "INFO")
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