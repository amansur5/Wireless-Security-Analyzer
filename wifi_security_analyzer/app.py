import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import platform
import subprocess
import datetime
from network_tab import NetworkTab
from handshake_tab import HandshakeTab
from cracking_tab import CrackingTab
from quick_crack_tab import QuickCrackTab
from robust_crack_tab import RobustCrackTab

class ModernWifiCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_styles()
        self.initialize_variables()
        self.check_dependencies()
        self.create_widgets()
        self.show_disclaimer()
        
    def setup_window(self):
        """Configure the main window with clean settings."""
        self.root.title("Wi-Fi Security Analyzer Pro")
        self.root.configure(bg='#ffffff')  # White background
        
        # Make window responsive and set minimum size
        self.root.minsize(800, 500)
        self.root.geometry("800x500")  # Smaller for Kali Linux
        
        # Center window on screen
        self.center_window()
        
        # Configure window icon (if available)
        try:
            if platform.system() == "Windows":
                self.root.iconbitmap("icon.ico")
            else:
                self.root.iconphoto(True, tk.PhotoImage(file="icon.png"))
        except:
            pass  # Icon not available, continue without it
            
    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
    def setup_styles(self):
        """Configure clean, professional ttk styles for the application."""
        style = ttk.Style()
        
        # Use 'clam' theme for Linux compatibility
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        else:
            style.theme_use('default')
            
        # Configure root window background
        self.root.configure(bg='#ffffff')
        
        # Configure colors and fonts
        style.configure('Title.TLabel', 
                       font=('Arial', 16, 'bold'),
                       foreground='#000000',
                       background='#ffffff')
        
        style.configure('Header.TLabel',
                       font=('Arial', 12, 'bold'),
                       foreground='#000000',
                       background='#ffffff')
        
        style.configure('Info.TLabel',
                       font=('Arial', 10),
                       foreground='#000000',
                       background='#ffffff')
        
        style.configure('Success.TLabel',
                       font=('Arial', 10, 'bold'),
                       foreground='#0078d7',  # Blue for success
                       background='#ffffff')
        
        style.configure('Warning.TLabel',
                       font=('Arial', 10, 'bold'),
                       foreground='#d83b01',  # Orange for warning
                       background='#ffffff')
        
        style.configure('Error.TLabel',
                       font=('Arial', 10, 'bold'),
                       foreground='#d13438',  # Red for error
                       background='#ffffff')
        
        # Configure buttons
        style.configure('Primary.TButton',
                       font=('Arial', 11, 'bold'),
                       background='#0078d7',
                       foreground='#ffffff',
                       padding=(15, 8),
                       borderwidth=2,
                       relief='raised')
        
        style.map('Primary.TButton',
                 background=[('active', '#005ea6'), ('pressed', '#004c87')],
                 foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        style.configure('Secondary.TButton',
                       font=('Arial', 11, 'bold'),
                       background='#6c757d',
                       foreground='#ffffff',
                       padding=(15, 8),
                       borderwidth=2,
                       relief='raised')
        
        style.map('Secondary.TButton',
                 background=[('active', '#5a6268'), ('pressed', '#4b5156')],
                 foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        style.configure('Success.TButton',
                       font=('Arial', 11, 'bold'),
                       background='#0078d7',
                       foreground='#ffffff',
                       padding=(15, 8),
                       borderwidth=2,
                       relief='raised')
        
        style.map('Success.TButton',
                 background=[('active', '#005ea6'), ('pressed', '#004c87')],
                 foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        style.configure('Warning.TButton',
                       font=('Arial', 11, 'bold'),
                       background='#d83b01',
                       foreground='#ffffff',
                       padding=(15, 8),
                       borderwidth=2,
                       relief='raised')
        
        style.map('Warning.TButton',
                 background=[('active', '#b32d00'), ('pressed', '#8f2300')],
                 foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        style.configure('Danger.TButton',
                       font=('Arial', 11, 'bold'),
                       background='#d13438',
                       foreground='#ffffff',
                       padding=(15, 8),
                       borderwidth=2,
                       relief='raised')
        
        style.map('Danger.TButton',
                 background=[('active', '#a12a2e'), ('pressed', '#7f2023')],
                 foreground=[('active', '#ffffff'), ('pressed', '#ffffff')])
        
        # Configure notebook
        style.configure('TNotebook',
                       background='#ffffff',
                       borderwidth=0)
        
        style.configure('TNotebook.Tab',
                       font=('Arial', 11, 'bold'),
                       padding=(20, 8),
                       background='#e5e5e5',
                       foreground='#000000')
        
        style.map('TNotebook.Tab',
                 background=[('selected', '#0078d7'), ('active', '#b3d7ff')],
                 foreground=[('selected', '#ffffff'), ('active', '#000000')])
        
        # Configure frames
        style.configure('Main.TFrame',
                       background='#ffffff')
        
        style.configure('Card.TFrame',
                       background='#f5f5f5',
                       relief='solid',
                       borderwidth=1)
        
        style.configure('Card.TLabelframe',
                       background='#f5f5f5',
                       relief='solid',
                       borderwidth=1)
        style.configure('Card.TLabelframe.Label',
                       font=('Arial', 12, 'bold'),
                       foreground='#000000',
                       background='#f5f5f5')
        
        # Configure entry
        style.configure('TEntry',
                       font=('Arial', 11),
                       padding=(10, 8),
                       fieldbackground='#ffffff',
                       foreground='#000000',
                       insertbackground='#000000',
                       borderwidth=1,
                       relief='solid')
        
        # Configure text widget
        style.configure('Log.TFrame',
                       background='#f5f5f5',
                       relief='solid',
                       borderwidth=1)
        
        # Configure scrollbar
        style.configure('Vertical.TScrollbar',
                       background='#e5e5e5',
                       troughcolor='#ffffff',
                       arrowcolor='#000000')
        style.map('Vertical.TScrollbar',
                 background=[('active', '#b3d7ff')])
        
        style.configure('Horizontal.TScrollbar',
                       background='#e5e5e5',
                       troughcolor='#ffffff',
                       arrowcolor='#000000')
        style.map('Horizontal.TScrollbar',
                 background=[('active', '#b3d7ff')])
        
    def initialize_variables(self):
        """Initialize all application variables."""
        self.interface = tk.StringVar()
        self.monitor_interface = tk.StringVar(value="wlan0")
        self.selected_bssid = tk.StringVar()
        self.selected_channel = tk.StringVar()
        self.selected_client = tk.StringVar()
        self.capture_process = None
        self.deauth_process = None
        self.scan_process = None
        self.handshake_file = tk.StringVar()
        self.quick_handshake_file = tk.StringVar()
        self.quick_wordlist_file = tk.StringVar()
        self.continuous_deauth = tk.BooleanVar(value=False)
        self.broadcast_deauth = tk.BooleanVar(value=False)
        self.is_capturing = tk.BooleanVar(value=False)
        self.is_cracking = tk.BooleanVar(value=False)
        
    def check_dependencies(self):
        """Check for required dependencies."""
        dependencies = ["aircrack-ng", "tcpdump", "iw", "hashcat", "hcxpcapngtool"]
        missing = []
        paths = ["/usr/bin", "/usr/local/bin", "/bin", "/sbin"]
        
        for dep in dependencies:
            found = False
            # Check using 'which'
            result = subprocess.run(["which", dep], capture_output=True, text=True)
            if result.stdout.strip():
                found = True
            else:
                # Fallback: Check common paths
                for path in paths:
                    if os.path.isfile(os.path.join(path, dep)):
                        found = True
                        break
            if not found:
                missing.append(dep)
                
        if missing:
            self.log_message(f"Missing dependencies: {', '.join(missing)}", "ERROR")
            install_cmd = "sudo apt-get install " + " ".join([d if d != "hcxpcapngtool" else "hcxtools" for d in missing])
            messagebox.showerror("Missing Dependencies", f"Required tools not found: {', '.join(missing)}.\nInstall with: {install_cmd}")
            self.root.quit()
            sys.exit(1)
        else:
            self.log_message("All dependencies found.", "SUCCESS")
        
    def create_widgets(self):
        """Create and configure all GUI widgets."""
        # Main container with padding
        self.main_container = ttk.Frame(self.root, style='Main.TFrame')
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Log area (before notebook)
        self.create_log_area(self.main_container)
        
        # Notebook container
        self.create_notebook()
        
        # Configure grid weights for responsiveness
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=0)
        self.main_container.grid_columnconfigure(0, weight=1)
        
    def create_notebook(self):
        """Create the main notebook with tabs."""
        notebook_frame = ttk.Frame(self.main_container)
        notebook_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        
        # Create notebook
        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill="both", expand=True)

        # Initialize tabs
        self.network_tab = NetworkTab(self.notebook, self)
        self.handshake_tab = HandshakeTab(self.notebook, self)
        self.cracking_tab = CrackingTab(self.notebook, self)
        self.quick_crack_tab = QuickCrackTab(self.notebook, self)
        self.robust_crack_tab = RobustCrackTab(self.notebook, self)
        
        # Configure notebook grid weights
        notebook_frame.grid_rowconfigure(0, weight=1)
        notebook_frame.grid_columnconfigure(0, weight=1)
        
    def create_log_area(self, parent):
        """Create the log output area with scrollbar."""
        log_frame = ttk.LabelFrame(parent, text="System Log", style='Card.TLabelframe')
        log_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        # Log header (for Clear Log button)
        log_header = ttk.Frame(log_frame)
        log_header.pack(fill="x", pady=(5, 5))
        
        # Clear log button
        clear_btn = ttk.Button(log_header, 
                              text="Clear Log",
                              style='Primary.TButton',
                              command=self.clear_log)
        clear_btn.pack(side="right")
        
        # Log text area
        log_container = ttk.Frame(log_frame, style='Log.TFrame')
        log_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        
        # Text widget with scrollbar
        self.log_text = tk.Text(log_container, 
                               height=8,
                               bg='#ffffff',
                               fg='#000000',
                               font=('Arial', 11),
                               insertbackground='#000000',
                               selectbackground='#b3d7ff',
                               relief='flat',
                               padx=10,
                               pady=10)
        
        scrollbar_y = ttk.Scrollbar(log_container, orient="vertical", command=self.log_text.yview, style='Vertical.TScrollbar')
        scrollbar_x = ttk.Scrollbar(log_container, orient="horizontal", command=self.log_text.xview, style='Horizontal.TScrollbar')
        self.log_text.config(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")
        scrollbar_x.pack(side="bottom", fill="x")
        
    def clear_log(self):
        """Clear the log output."""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Log cleared.")
        
    def log_message(self, message, level="INFO"):
        """Add a message to the log with timestamp and level."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        colors = {
            "INFO": "#000000",
            "SUCCESS": "#0078d7",
            "WARNING": "#d83b01",
            "ERROR": "#d13438"
        }
        
        color = colors.get(level, "#000000")
        log_entry = f"[{timestamp}] {level}: {message}\n"
        
        # Fallback to console if log_text is not initialized
        if not hasattr(self, 'log_text'):
            print(log_entry.strip())
            return
        
        # Insert with color
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, log_entry)
        
        # Apply color to the last line
        last_line_start = self.log_text.index("end-2c linestart")
        last_line_end = self.log_text.index("end-1c")
        
        self.log_text.tag_add(f"color_{level}", last_line_start, last_line_end)
        self.log_text.tag_config(f"color_{level}", foreground=color)
        
        self.log_text.configure(state='disabled')
        self.log_text.see(tk.END)
        
    def update_status(self, capture_active=False, cracking_active=False, interface=""):
        """Update the status bar indicators (no longer used)."""
        pass
            
    def show_disclaimer(self):
        """Show the legal disclaimer."""
        disclaimer_text = """
        ⚠️  LEGAL DISCLAIMER ⚠️
        
        This tool is designed for educational purposes and authorized security testing ONLY.
        
        IMPORTANT:
        • Use only on networks you own or have explicit written permission to test
        • Unauthorized access to networks is illegal and may result in criminal charges
        • This tool should only be used by security professionals and researchers
        • Always comply with local laws and regulations
        
        By using this tool, you acknowledge that you are responsible for ensuring
        compliance with all applicable laws and regulations.
        """
        
        # Create custom disclaimer dialog
        disclaimer_window = tk.Toplevel(self.root)
        disclaimer_window.title("Legal Disclaimer")
        disclaimer_window.geometry("600x450")  # Increased height to accommodate buttons
        disclaimer_window.resizable(False, False)
        disclaimer_window.transient(self.root)
        disclaimer_window.grab_set()
        disclaimer_window.configure(bg='#ffffff')
        
        # Center the disclaimer window
        disclaimer_window.update_idletasks()
        x = (disclaimer_window.winfo_screenwidth() // 2) - (300)
        y = (disclaimer_window.winfo_screenheight() // 2) - (225)
        disclaimer_window.geometry(f"600x450+{x}+{y}")
        
        # Disclaimer content
        content_frame = ttk.Frame(disclaimer_window, style='Card.TFrame')
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Warning icon and title
        header_frame = ttk.Frame(content_frame)
        header_frame.pack(fill="x", pady=(0, 15))
        
        warning_label = ttk.Label(header_frame, text="⚠️", font=('Arial', 24))
        warning_label.pack(side="left", padx=(0, 10))
        
        title_label = ttk.Label(header_frame, text="Legal Disclaimer", style='Title.TLabel')
        title_label.pack(side="left")
        
        # Text widget with scrollbar
        text_container = ttk.Frame(content_frame)
        text_container.pack(fill="both", expand=True, pady=(0, 15))
        
        text_widget = tk.Text(text_container,
                             wrap="word",
                             font=('Arial', 10),
                             bg='#ffffff',
                             fg='#000000',
                             relief='flat',
                             padx=15,
                             pady=15,
                             height=10)  # Fixed height to prevent overflow
        scrollbar_y = ttk.Scrollbar(text_container, orient="vertical", command=text_widget.yview, style='Vertical.TScrollbar')
        text_widget.config(yscrollcommand=scrollbar_y.set)
        
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar_y.pack(side="right", fill="y")
        
        text_widget.insert("1.0", disclaimer_text)
        text_widget.config(state="disabled")
        
        # Buttons
        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill="x", pady=(0, 10))
        
        accept_btn = ttk.Button(button_frame,
                               text="I Accept - Continue",
                               style='Success.TButton',
                               command=lambda: self.accept_disclaimer(disclaimer_window))
        accept_btn.pack(side="right", padx=(10, 0))
        
        decline_btn = ttk.Button(button_frame,
                                text="Decline - Exit",
                                style='Danger.TButton',
                                command=lambda: self.decline_disclaimer(disclaimer_window))
        decline_btn.pack(side="right", padx=(10, 10))
        
        # Ensure buttons are visible and focused
        accept_btn.focus_set()
        
        # Make window modal
        disclaimer_window.wait_window()
        
    def accept_disclaimer(self, window):
        """Handle disclaimer acceptance."""
        window.destroy()
        self.log_message("Disclaimer accepted. Application ready.", "SUCCESS")
        
    def decline_disclaimer(self, window):
        """Handle disclaimer decline."""
        window.destroy()
        self.root.quit()
        sys.exit(0)

def check_root_privileges():
    """Check if the application is running with root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        return os.geteuid() == 0

if __name__ == "__main__":
    # Check for root privileges
    if not check_root_privileges():
        print("❌ This application requires root/administrator privileges to function properly.")
        print("Please run the application with elevated privileges.")
        print("\nLinux/Mac: sudo python3 main.py")
        print("Windows: Run as Administrator")
        sys.exit(1)
    
    # Create and run the application
    root = tk.Tk()
    app = ModernWifiCrackerGUI(root)
    
    # Start the main loop
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user.")
    except Exception as e:
        print(f"Application error: {e}")
        sys.exit(1)