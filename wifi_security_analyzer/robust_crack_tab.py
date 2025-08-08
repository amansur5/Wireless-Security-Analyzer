import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import subprocess
import threading
import time
import re

class RobustCrackTab:
    def __init__(self, notebook, app):
        self.app = app
        self.frame = ttk.Frame(notebook, style='Main.TFrame')
        notebook.add(self.frame, text="Robust Crack")
        self.is_cracking = False
        self.create_widgets()

    def create_widgets(self):
        """Create and configure widgets for the Robust Crack tab, mirroring QuickCrackTab design with a fieldset legend."""
        # Fieldset with legend for configuration
        file_frame = ttk.LabelFrame(self.frame, text="Robust Crack Configuration", style='Card.TLabelframe')
        file_frame.pack(fill="x", padx=10, pady=10)

        # File selection and mask input container
        file_container = ttk.Frame(file_frame)
        file_container.pack(fill="x", padx=15, pady=10)

        # File and mask selection on one line
        file_selection_frame = ttk.Frame(file_container)
        file_selection_frame.pack(fill="x", pady=(0, 10))

        # Handshake file
        ttk.Label(file_selection_frame, text="Handshake File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        self.handshake_entry = ttk.Entry(file_selection_frame, textvariable=tk.StringVar(), state="readonly", font=('Arial', 10), width=15)
        self.handshake_entry.pack(side="left", padx=(0, 10))
        ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', 
                  command=self.select_handshake_file).pack(side="left", padx=(0, 10))

        # Wordlist file
        ttk.Label(file_selection_frame, text="Wordlist File:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        self.wordlist_entry = ttk.Entry(file_selection_frame, textvariable=tk.StringVar(), state="readonly", font=('Arial', 10), width=15)
        self.wordlist_entry.pack(side="left", padx=(0, 10))
        ttk.Button(file_selection_frame, text="📁 Select", style='Primary.TButton', 
                  command=self.select_wordlist_file).pack(side="left", padx=(0, 10))

        # Mask input
        ttk.Label(file_selection_frame, text="Mask:", style='Info.TLabel').pack(side="left", padx=(0, 5))
        self.mask_entry = ttk.Entry(file_selection_frame, font=('Arial', 10), width=15)
        self.mask_entry.pack(side="left", padx=(0, 10))
        self.mask_entry.insert(0, "?l?l?l?l?d?d?d?d")

        # Custom wordlist generation
        custom_wordlist_frame = ttk.Frame(file_container)
        custom_wordlist_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(custom_wordlist_frame, text="Custom Pattern (e.g., @@@@199%d):", style='Info.TLabel').pack(side="left", padx=(0, 5))
        self.custom_pattern_entry = ttk.Entry(custom_wordlist_frame, font=('Arial', 10), width=15)
        self.custom_pattern_entry.pack(side="left", padx=(0, 10))
        ttk.Button(custom_wordlist_frame, text="📝 Generate", style='Primary.TButton', 
                  command=self.generate_custom_wordlist).pack(side="left")

        # Description
        desc_label = ttk.Label(file_container, 
                              text="Robust crack mode uses multi-stage Hashcat attacks (dictionary, hybrid, mask, brute force)", 
                              style='Info.TLabel')
        desc_label.pack(anchor="w", pady=(0, 10))

        # Control buttons
        control_container = ttk.Frame(file_container)
        control_container.pack(fill="x", pady=10)
        ttk.Button(control_container, text="⚡ Dictionary", style='Success.TButton', 
                  command=self.run_dictionary_attack).pack(side="left", padx=(0, 10))
        ttk.Button(control_container, text="⚡ Hybrid", style='Success.TButton', 
                  command=self.run_hybrid_attack).pack(side="left", padx=(0, 10))
        ttk.Button(control_container, text="⚡ Mask", style='Success.TButton', 
                  command=self.run_mask_attack).pack(side="left", padx=(0, 10))
        ttk.Button(control_container, text="⚡ Brute Force", style='Warning.TButton', 
                  command=self.run_brute_force).pack(side="left", padx=(0, 10))
        ttk.Button(control_container, text="⏹️ Stop", style='Danger.TButton', 
                  command=self.stop_attack).pack(side="left", padx=(0, 10))
        ttk.Button(control_container, text="🗑️ Clear Wordlist", style='Warning.TButton', 
                  command=self.clear_wordlist).pack(side="left")

        # Progress bar
        self.progress_bar = ttk.Progressbar(file_container, mode='indeterminate', style='TProgressbar')
        self.progress_bar.pack(fill="x", pady=(10, 5))

        # Status indicator
        self.status_label = ttk.Label(file_container, text="Ready for robust password cracking", style='Info.TLabel')
        self.status_label.pack(pady=(5, 0))

        # Configure grid weights
        file_container.grid_rowconfigure(0, weight=0)
        file_container.grid_rowconfigure(1, weight=0)
        file_container.grid_rowconfigure(2, weight=0)
        file_container.grid_rowconfigure(3, weight=1)
        file_container.grid_columnconfigure(0, weight=1)

    def select_handshake_file(self):
        """Select handshake file for robust crack."""
        file_path = filedialog.askopenfilename(filetypes=[("Capture files", "*.cap *.pcap *.hc22000")])
        if file_path:
            self.handshake_entry.configure(state='normal')
            self.handshake_entry.delete(0, tk.END)
            self.handshake_entry.insert(0, file_path)
            self.handshake_entry.configure(state='readonly')
            self.app.log_message(f"Selected robust crack handshake file: {file_path}", "SUCCESS")

    def select_wordlist_file(self):
        """Select wordlist file for robust crack."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.wordlist_entry.configure(state='normal')
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, file_path)
            self.wordlist_entry.configure(state='readonly')
            self.app.log_message(f"Selected robust crack wordlist file: {file_path}", "SUCCESS")

    def clear_wordlist(self):
        """Clear the selected wordlist."""
        self.wordlist_entry.configure(state='normal')
        self.wordlist_entry.delete(0, tk.END)
        self.wordlist_entry.configure(state='readonly')
        self.app.log_message("Robust crack wordlist selection cleared.", "INFO")

    def generate_custom_wordlist(self):
        """Generate a custom wordlist using crunch."""
        pattern = self.custom_pattern_entry.get().strip()
        if not pattern:
            self.app.log_message("Please enter a valid pattern for wordlist generation.", "ERROR")
            messagebox.showerror("Error", "Please enter a valid pattern for wordlist generation.")
            return

        output_file = "custom_wordlist.txt"
        cmd = ["crunch", "8", "12", "-t", pattern, "-o", output_file]
        
        def run_crunch():
            self.progress_bar.start()
            self.status_label.configure(text="Generating custom wordlist...")
            try:
                self.app.log_message(f"Generating custom wordlist with pattern: {pattern}", "INFO")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.wordlist_entry.configure(state='normal')
                    self.wordlist_entry.delete(0, tk.END)
                    self.wordlist_entry.insert(0, os.path.abspath(output_file))
                    self.wordlist_entry.configure(state='readonly')
                    self.app.log_message(f"Custom wordlist generated: {output_file}", "SUCCESS")
                    self.status_label.configure(text="Custom wordlist generated")
                else:
                    self.app.log_message(f"Failed to generate wordlist: {result.stderr}", "ERROR")
                    self.status_label.configure(text="Wordlist generation failed")
                    messagebox.showerror("Error", f"Failed to generate wordlist: {result.stderr}")
            except Exception as e:
                self.app.log_message(f"Error generating wordlist: {str(e)}", "ERROR")
                self.status_label.configure(text="Wordlist generation failed")
                messagebox.showerror("Error", f"Error generating wordlist: {str(e)}")
            finally:
                self.progress_bar.stop()

        threading.Thread(target=run_crunch, daemon=True).start()

    def convert_handshake(self, handshake_file):
        """Convert handshake file to Hashcat format if necessary."""
        if not handshake_file.endswith(".hc22000"):
            output_file = os.path.splitext(handshake_file)[0] + ".hc22000"
            cmd = ["hcxpcapngtool", "-o", output_file, handshake_file]
            try:
                self.app.log_message(f"Converting handshake to Hashcat format: {output_file}", "INFO")
                self.status_label.configure(text="Converting handshake...")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    self.app.log_message("Handshake converted successfully.", "SUCCESS")
                    return output_file
                else:
                    self.app.log_message(f"Failed to convert handshake: {result.stderr}", "ERROR")
                    self.status_label.configure(text="Handshake conversion failed")
                    return None
            except Exception as e:
                self.app.log_message(f"Error converting handshake: {str(e)}", "ERROR")
                self.status_label.configure(text="Handshake conversion failed")
                return None
        return handshake_file

    def validate_handshake(self, handshake_file):
        """Validate handshake file using aircrack-ng."""
        self.app.log_message("Validating robust crack handshake file...", "INFO")
        self.status_label.configure(text="Validating handshake")
        process = subprocess.Popen(
            f"aircrack-ng {handshake_file}",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output, error = process.communicate()
        if "No valid WPA handshakes found" in output or "No valid WPA handshakes found" in error:
            self.app.log_message("No valid WPA handshake found in the robust crack capture file.", "ERROR")
            self.status_label.configure(text="Invalid handshake file")
            return False
        self.app.log_message("Robust crack handshake file validated successfully.", "SUCCESS")
        return True

    def run_dictionary_attack(self):
        """Run enhanced dictionary attack with Hashcat."""
        if self.is_cracking:
            self.app.log_message("Another cracking process is running.", "ERROR")
            messagebox.showerror("Error", "Another cracking process is running.")
            return

        handshake_file = self.handshake_entry.get().strip()
        wordlist_file = self.wordlist_entry.get().strip()
        
        if not handshake_file or not wordlist_file:
            self.app.log_message("Please select both handshake and wordlist files.", "ERROR")
            messagebox.showerror("Error", "Please select both handshake and wordlist files.")
            return
        if not os.path.exists(handshake_file):
            self.app.log_message(f"Handshake file does not exist: {handshake_file}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return
        if not os.path.exists(wordlist_file):
            self.app.log_message(f"Wordlist file does not exist: {wordlist_file}", "ERROR")
            messagebox.showerror("Error", "Wordlist file does not exist.")
            return
        if os.path.getsize(wordlist_file) == 0:
            self.app.log_message(f"Wordlist file is empty: {wordlist_file}", "ERROR")
            messagebox.showerror("Error", "Wordlist file is empty.")
            return

        if not self.validate_handshake(handshake_file):
            return

        handshake_file = self.convert_handshake(handshake_file)
        if not handshake_file:
            return

        cmd = ["hashcat", "-m", "22000", "-a", "0", "-r", "rules/best64.rule", handshake_file, wordlist_file]

        def run_attack():
            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Dictionary attack in progress...")
            try:
                self.app.log_message("Starting dictionary attack...", "INFO")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.app.capture_process = process

                while process.poll() is None and self.is_cracking:
                    line = process.stdout.readline()
                    if line:
                        self.app.log_message(line.strip(), "INFO")
                        if "Recovered" in line and "Hashes" in line:
                            match = re.search(r"Recovered.*?: \d+/(\d+) Hashes.*?\((\w+):(.+?)\)", line)
                            if match:
                                password = match.group(2).strip()
                                self.app.log_message(f"Password found: {password}", "SUCCESS")
                                self.status_label.configure(text=f"Password found: {password}")
                                self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                                break
                    time.sleep(0.1)

                if not self.is_cracking:
                    return

                output, error = process.communicate()
                if output:
                    self.app.log_message(output.strip(), "INFO")
                if error:
                    self.app.log_message(f"Error: {error.strip()}", "ERROR")

                if process.returncode == 0 and not ("Recovered" in output and "Hashes" in output):
                    self.app.log_message("Password not found in wordlist.", "WARNING")
                    self.status_label.configure(text="Password not found")
                    self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found in wordlist. Try a different wordlist or attack type."))
            except Exception as e:
                self.app.log_message(f"Error during dictionary attack: {str(e)}", "ERROR")
                self.status_label.configure(text="Dictionary attack failed")
            finally:
                self.is_cracking = False
                self.progress_bar.stop()
                self.app.capture_process = None
                self.app.log_text.see(tk.END)

        threading.Thread(target=run_attack, daemon=True).start()

    def run_hybrid_attack(self):
        """Run hybrid attack with Hashcat."""
        if self.is_cracking:
            self.app.log_message("Another cracking process is running.", "ERROR")
            messagebox.showerror("Error", "Another cracking process is running.")
            return

        handshake_file = self.handshake_entry.get().strip()
        wordlist_file = self.wordlist_entry.get().strip()
        
        if not handshake_file or not wordlist_file:
            self.app.log_message("Please select both handshake and wordlist files.", "ERROR")
            messagebox.showerror("Error", "Please select both handshake and wordlist files.")
            return
        if not os.path.exists(handshake_file):
            self.app.log_message(f"Handshake file does not exist: {handshake_file}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return
        if not os.path.exists(wordlist_file):
            self.app.log_message(f"Wordlist file does not exist: {wordlist_file}", "ERROR")
            messagebox.showerror("Error", "Wordlist file does not exist.")
            return
        if os.path.getsize(wordlist_file) == 0:
            self.app.log_message(f"Wordlist file is empty: {wordlist_file}", "ERROR")
            messagebox.showerror("Error", "Wordlist file is empty.")
            return

        if not self.validate_handshake(handshake_file):
            return

        handshake_file = self.convert_handshake(handshake_file)
        if not handshake_file:
            return

        cmd = ["hashcat", "-m", "22000", "-a", "6", handshake_file, wordlist_file, "?d?d?d"]

        def run_attack():
            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Hybrid attack in progress...")
            try:
                self.app.log_message("Starting hybrid attack...", "INFO")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.app.capture_process = process

                while process.poll() is None and self.is_cracking:
                    line = process.stdout.readline()
                    if line:
                        self.app.log_message(line.strip(), "INFO")
                        if "Recovered" in line and "Hashes" in line:
                            match = re.search(r"Recovered.*?: \d+/(\d+) Hashes.*?\((\w+):(.+?)\)", line)
                            if match:
                                password = match.group(2).strip()
                                self.app.log_message(f"Password found: {password}", "SUCCESS")
                                self.status_label.configure(text=f"Password found: {password}")
                                self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                                break
                    time.sleep(0.1)

                if not self.is_cracking:
                    return

                output, error = process.communicate()
                if output:
                    self.app.log_message(output.strip(), "INFO")
                if error:
                    self.app.log_message(f"Error: {error.strip()}", "ERROR")

                if process.returncode == 0 and not ("Recovered" in output and "Hashes" in output):
                    self.app.log_message("Password not found in wordlist.", "WARNING")
                    self.status_label.configure(text="Password not found")
                    self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found in wordlist. Try a different wordlist or attack type."))
            except Exception as e:
                self.app.log_message(f"Error during hybrid attack: {str(e)}", "ERROR")
                self.status_label.configure(text="Hybrid attack failed")
            finally:
                self.is_cracking = False
                self.progress_bar.stop()
                self.app.capture_process = None
                self.app.log_text.see(tk.END)

        threading.Thread(target=run_attack, daemon=True).start()

    def run_mask_attack(self):
        """Run mask attack with Hashcat."""
        if self.is_cracking:
            self.app.log_message("Another cracking process is running.", "ERROR")
            messagebox.showerror("Error", "Another cracking process is running.")
            return

        handshake_file = self.handshake_entry.get().strip()
        mask = self.mask_entry.get().strip()
        
        if not handshake_file or not mask:
            self.app.log_message("Please select handshake file and enter a mask.", "ERROR")
            messagebox.showerror("Error", "Please select handshake file and enter a mask.")
            return
        if not os.path.exists(handshake_file):
            self.app.log_message(f"Handshake file does not exist: {handshake_file}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return

        if not self.validate_handshake(handshake_file):
            return

        handshake_file = self.convert_handshake(handshake_file)
        if not handshake_file:
            return

        cmd = ["hashcat", "-m", "22000", "-a", "3", handshake_file, mask]

        def run_attack():
            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Mask attack in progress...")
            try:
                self.app.log_message(f"Starting mask attack with mask: {mask}", "INFO")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.app.capture_process = process

                while process.poll() is None and self.is_cracking:
                    line = process.stdout.readline()
                    if line:
                        self.app.log_message(line.strip(), "INFO")
                        if "Recovered" in line and "Hashes" in line:
                            match = re.search(r"Recovered.*?: \d+/(\d+) Hashes.*?\((\w+):(.+?)\)", line)
                            if match:
                                password = match.group(2).strip()
                                self.app.log_message(f"Password found: {password}", "SUCCESS")
                                self.status_label.configure(text=f"Password found: {password}")
                                self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                                break
                    time.sleep(0.1)

                if not self.is_cracking:
                    return

                output, error = process.communicate()
                if output:
                    self.app.log_message(output.strip(), "INFO")
                if error:
                    self.app.log_message(f"Error: {error.strip()}", "ERROR")

                if process.returncode == 0 and not ("Recovered" in output and "Hashes" in output):
                    self.app.log_message("Password not found with mask.", "WARNING")
                    self.status_label.configure(text="Password not found")
                    self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found with mask. Try a different mask or attack type."))
            except Exception as e:
                self.app.log_message(f"Error during mask attack: {str(e)}", "ERROR")
                self.status_label.configure(text="Mask attack failed")
            finally:
                self.is_cracking = False
                self.progress_bar.stop()
                self.app.capture_process = None
                self.app.log_text.see(tk.END)

        threading.Thread(target=run_attack, daemon=True).start()

    def run_brute_force(self):
        """Run brute force attack with Hashcat."""
        if self.is_cracking:
            self.app.log_message("Another cracking process is running.", "ERROR")
            messagebox.showerror("Error", "Another cracking process is running.")
            return

        handshake_file = self.handshake_entry.get().strip()
        
        if not handshake_file:
            self.app.log_message("Please select handshake file.", "ERROR")
            messagebox.showerror("Error", "Please select handshake file.")
            return
        if not os.path.exists(handshake_file):
            self.app.log_message(f"Handshake file does not exist: {handshake_file}", "ERROR")
            messagebox.showerror("Error", "Handshake file does not exist.")
            return

        if not self.validate_handshake(handshake_file):
            return

        handshake_file = self.convert_handshake(handshake_file)
        if not handshake_file:
            return

        cmd = ["hashcat", "-m", "22000", "-a", "3", "-i", "--increment-min=8", "--increment-max=10", handshake_file, "?l?d"]

        def run_attack():
            self.is_cracking = True
            self.progress_bar.start()
            self.status_label.configure(text="Brute force attack in progress...")
            try:
                self.app.log_message("Starting brute force attack (lowercase + digits, 8-10 chars)...", "INFO")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.app.capture_process = process

                while process.poll() is None and self.is_cracking:
                    line = process.stdout.readline()
                    if line:
                        self.app.log_message(line.strip(), "INFO")
                        if "Recovered" in line and "Hashes" in line:
                            match = re.search(r"Recovered.*?: \d+/(\d+) Hashes.*?\((\w+):(.+?)\)", line)
                            if match:
                                password = match.group(2).strip()
                                self.app.log_message(f"Password found: {password}", "SUCCESS")
                                self.status_label.configure(text=f"Password found: {password}")
                                self.app.root.after(0, lambda: messagebox.showinfo("Success", f"Password found: {password}"))
                                break
                    time.sleep(0.1)

                if not self.is_cracking:
                    return

                output, error = process.communicate()
                if output:
                    self.app.log_message(output.strip(), "INFO")
                if error:
                    self.app.log_message(f"Error: {error.strip()}", "ERROR")

                if process.returncode == 0 and not ("Recovered" in output and "Hashes" in output):
                    self.app.log_message("Password not found with brute force.", "WARNING")
                    self.status_label.configure(text="Password not found")
                    self.app.root.after(0, lambda: messagebox.showwarning("Warning", "Password not found with brute force. Try a different charset or attack type."))
            except Exception as e:
                self.app.log_message(f"Error during brute force attack: {str(e)}", "ERROR")
                self.status_label.configure(text="Brute force attack failed")
            finally:
                self.is_cracking = False
                self.progress_bar.stop()
                self.app.capture_process = None
                self.app.log_text.see(tk.END)

        threading.Thread(target=run_attack, daemon=True).start()

    def stop_attack(self):
        """Stop the current cracking process."""
        if self.is_cracking:
            subprocess.run(["pkill", "-9", "-f", "hashcat"], capture_output=True)
            self.is_cracking = False
            self.progress_bar.stop()
            self.status_label.configure(text="Robust cracking stopped")
            self.app.log_message("Robust password cracking stopped.", "INFO")
            self.app.root.after(0, lambda: messagebox.showinfo("Success", "Robust password cracking process stopped."))
            self.app.capture_process = None
        else:
            self.app.log_message("No cracking process is running.", "INFO")
            self.status_label.configure(text="No cracking process running")