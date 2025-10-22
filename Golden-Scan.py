#!/usr/bin/env python3
"""
Golden-Scan - Professional VirusTotal Scanner
============================================

A cutting-edge security scanning tool 
that integrates with VirusTotal API to analyze files for potential threats.

Features:
- Real-time animated progress tracking
- Interactive visualizations
- Professional dashboard design
- Smooth transitions and micro-interactions
- Advanced filtering and search
- Export options with preview
- Live statistics dashboard
- Automatic report generation in multiple formats

Author: Mohamed A Jaber https://www.facebook.com/Mrm0hm3d
Version: 1.0 (First Edition)
"""

import os
import sys
import time
import json
import hashlib
import logging
import argparse
import requests
import threading
import queue
import webbrowser
import math
import random
import csv  # Added for CSV report generation
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass, asdict
from jinja2 import Template

# GUI imports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
import tkinter.simpledialog as simpledialog
from tkinter import Canvas
from tkinter import PhotoImage
# Optional imports with graceful fallback
try:
    import pefile
except ImportError:
    pefile = None

# ======================= CONFIGURATION =======================
@dataclass
class Config:
    """Configuration class for the scanner"""
    # API Configuration
    api_key: str = ""
    vt_file_url: str = "https://www.virustotal.com/api/v3/files"
    vt_analyses_url: str = "https://www.virustotal.com/api/v3/analyses"
    vt_upload_url: str = "https://www.virustotal.com/api/v3/files"
    
    # File paths
    input_file: str = "processes.txt"
    output_dir: str = "scan_results"
    vt_log_dir: str = "vt_logs"
    
    # Report files
    text_output: str = "scan_results.txt"
    html_output: str = "scan_report.html"
    json_output: str = "scan_data.json"
    csv_output: str = "scan_results.csv"
    threats_text: str = "threats.txt"
    threats_html: str = "threats_report.html"
    threats_json: str = "threats_data.json"
    
    # Scanner settings
    request_interval: float = 15.0
    max_retries: int = 5
    timeout: int = 30
    read_chunk: int = 8192
    upload_if_not_found: bool = True
    max_string_length: int = 100
    max_strings_count: int = 50
    
    # Thresholds
    malicious_threshold: int = 1
    suspicious_threshold: int = 1
    
    # UI Settings
    theme: str = "dark"  # dark or light
    auto_create_dirs: bool = True
    create_sample_input: bool = True
    
    # Modern UI Colors
    colors = {
        "dark": {
            "bg_primary": "#0a0e1a",
            "bg_secondary": "#141925",
            "bg_tertiary": "#1e2433",
            "bg_card": "#1a1f2e",
            "bg_hover": "#252b3d",
            "text_primary": "#ffffff",
            "text_secondary": "#a0a9c9",
            "text_muted": "#6b7280",
            "accent": "#3b82f6",
            "accent_hover": "#2563eb",
            "success": "#10b981",
            "warning": "#f59e0b",
            "danger": "#ef4444",
            "border": "#2a3142",
            "shadow": "rgba(0, 0, 0, 0.3)",
            "glass": "rgba(255, 255, 255, 0.05)",
            "gold": "#FFD700",
            "gold_light": "#FFED4E",
            "transparent": "#000000"
        },
        "light": {
            "bg_primary": "#ffffff",
            "bg_secondary": "#f8fafc",
            "bg_tertiary": "#f1f5f9",
            "bg_card": "#ffffff",
            "bg_hover": "#f8fafc",
            "text_primary": "#1e293b",
            "text_secondary": "#64748b",
            "text_muted": "#94a3b8",
            "accent": "#3b82f6",
            "accent_hover": "#2563eb",
            "success": "#10b981",
            "warning": "#f59e0b",
            "danger": "#ef4444",
            "border": "#e2e8f0",
            "shadow": "rgba(0, 0, 0, 0.1)",
            "glass": "rgba(255, 255, 255, 0.8)",
            "gold": "#FFD700",
            "gold_light": "#FFED4E",
            "transparent": "#ffffff"
        }
    }
    
    def __post_init__(self):
        """Post-initialization to set up derived values"""
        # Create output directory paths
        self.output_dir = Path(self.output_dir)
        self.vt_log_dir = self.output_dir / self.vt_log_dir
        
        # Create full paths for output files
        self.text_output = str(self.output_dir / self.text_output)
        self.html_output = str(self.output_dir / self.html_output)
        self.json_output = str(self.output_dir / self.json_output)
        self.csv_output = str(self.output_dir / self.csv_output)
        self.threats_text = str(self.output_dir / self.threats_text)
        self.threats_html = str(self.output_dir / self.threats_html)
        self.threats_json = str(self.output_dir / self.threats_json)

# Initialize configuration
config = Config()

# ======================= GLOBAL LOGGER =======================
logger = None

# ======================= LOGGING SETUP =======================
def setup_logging():
    """Setup logging configuration after config is initialized."""
    global logger
    
    # Ensure log directory exists
    log_file_path = config.output_dir / "scanner.log"
    ensure_directory_exists(log_file_path.parent)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(str(log_file_path)),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    return logger

# ======================= UTILITY FUNCTIONS =======================
def ensure_directory_exists(directory: Union[str, Path]) -> bool:
    """Ensure a directory exists, creating it if necessary."""
    try:
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        print(f"Failed to create directory {directory}: {e}")
        return False

def ensure_file_exists(file_path: Union[str, Path], create_if_missing: bool = True, 
                      default_content: str = "") -> bool:
    """Ensure a file exists, creating it with default content if necessary."""
    try:
        path = Path(file_path)
        if not ensure_directory_exists(path.parent):
            return False
        if path.exists():
            return True
        if create_if_missing:
            with open(path, "w", encoding="utf-8") as f:
                f.write(default_content)
            if logger:
                logger.info(f"Created missing file: {file_path}")
            else:
                print(f"Created missing file: {file_path}")
            return True
        return False
    except Exception as e:
        if logger:
            logger.error(f"Failed to ensure file exists {file_path}: {e}")
        else:
            print(f"Failed to ensure file exists {file_path}: {e}")
        return False

def create_sample_input_file(file_path: Union[str, Path]) -> bool:
    """Create a sample input file with example file paths."""
    try:
        path = Path(file_path)
        if not ensure_directory_exists(path.parent):
            return False
        
        sample_content = """# Sample input file for Golden-Scan
# Add one file path per line
# Example entries:

C:\\Windows\\System32\\notepad.exe
C:\\Windows\\System32\\calc.exe
C:\\Windows\\System32\\cmd.exe
C:\\Windows\\System32\\powershell.exe
C:\\Windows\\System32\\taskmgr.exe
C:\\Windows\\System32\\regedit.exe
C:\\Windows\\System32\\mspaint.exe
C:\\Windows\\System32\\write.exe
C:\\Windows\\System32\\winver.exe
C:\\Windows\\System32\\wmic.exe
"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(sample_content)
        
        if logger:
            logger.info(f"Created sample input file: {file_path}")
        else:
            print(f"Created sample input file: {file_path}")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Failed to create sample input file {file_path}: {e}")
        else:
            print(f"Failed to create sample input file {file_path}: {e}")
        return False

def setup_environment() -> bool:
    """Set up the environment for the scanner."""
    try:
        if config.auto_create_dirs:
            ensure_directory_exists(config.output_dir)
            ensure_directory_exists(config.vt_log_dir)
        else:
            config.output_dir.mkdir(exist_ok=True)
            config.vt_log_dir.mkdir(exist_ok=True)
        
        if config.create_sample_input and not os.path.exists(config.input_file):
            create_sample_input_file(config.input_file)
        
        if not config.api_key:
            config.api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        
        return bool(config.api_key)
    except Exception as e:
        if logger:
            logger.error(f"Failed to set up environment: {e}")
        else:
            print(f"Failed to set up environment: {e}")
        return False

def compute_hashes(filepath: str) -> Tuple[Optional[str], Optional[str], int]:
    """Compute SHA256 and MD5 hashes for a file."""
    try:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        file_size = 0
        
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(config.read_chunk)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                file_size += len(chunk)
                
        return sha256.hexdigest(), md5.hexdigest(), file_size
    except Exception as e:
        if logger:
            logger.error(f"Error computing hashes for {filepath}: {e}")
        else:
            print(f"Error computing hashes for {filepath}: {e}")
        return None, None, 0

def vt_get_by_hash(sha256: str) -> Tuple[Optional[int], Union[Dict, str, None]]:
    """Query VirusTotal for a file by SHA256."""
    headers = {"x-apikey": config.api_key}
    try:
        resp = requests.get(
            f"{config.vt_file_url}/{sha256}",
            headers=headers,
            timeout=config.timeout
        )
        
        try:
            return resp.status_code, resp.json()
        except ValueError:
            return resp.status_code, resp.text
    except Exception as e:
        if logger:
            logger.error(f"Exception querying VT for {sha256}: {e}")
        else:
            print(f"Exception querying VT for {sha256}: {e}")
        return None, f"Exception: {str(e)}"

def vt_upload_file(filepath: str) -> Tuple[bool, Union[Dict, str]]:
    """Upload a file to VirusTotal for analysis."""
    headers = {"x-apikey": config.api_key}
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            resp = requests.post(
                config.vt_upload_url,
                headers=headers,
                files=files,
                timeout=config.timeout
            )
        
        if resp.status_code == 200:
            return True, resp.json()
        else:
            return False, f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        if logger:
            logger.error(f"Exception uploading {filepath} to VT: {e}")
        else:
            print(f"Exception uploading {filepath} to VT: {e}")
        return False, f"Exception: {str(e)}"

def parse_vt_stats(response_json: Dict) -> Optional[Dict[str, int]]:
    """Extract analysis statistics from VT response."""
    try:
        return response_json['data']['attributes']['last_analysis_stats']
    except (KeyError, TypeError):
        return None

def determine_verdict(stats: Optional[Dict[str, int]], vt_text: str) -> str:
    """Determine the verdict based on VT stats."""
    if isinstance(stats, dict):
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        
        if malicious >= config.malicious_threshold:
            return "Malicious"
        elif suspicious >= config.suspicious_threshold:
            return "Suspicious"
        else:
            return "Clean"
    
    if isinstance(vt_text, str):
        vt_low = vt_text.lower()
        if "malicious" in vt_low and "0" not in vt_low:
            return "Malicious"
        if "suspicious" in vt_low and "0" not in vt_low:
            return "Suspicious"
        if "not found" in vt_low or "not in vt" in vt_low:
            return "Unknown"
    
    return "Unknown"

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable format."""
    if bytes_value == 0:
        return "0 Bytes"
    
    k = 1024
    sizes = ["Bytes", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(bytes_value) / math.log(k)))
    
    if i >= len(sizes):
        i = len(sizes) - 1
    
    return f"{round(bytes_value / math.pow(k, i), 2)} {sizes[i]}"

# ======================= DATA MODELS =======================
@dataclass
class ScanResult:
    """Data model for scan results"""
    file_name: str
    file_path: str
    file_size: int
    sha256: str
    md5: str
    vt_result: str
    vt_stats: Dict[str, int]
    verdict: str
    pe_info: Dict
    scan_time: str
    error: Optional[str] = None
    uploaded: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @property
    def is_threat(self) -> bool:
        """Check if this result represents a threat."""
        return self.verdict in ("Malicious", "Suspicious")

# ======================= MODERN UI COMPONENTS =======================
class ModernButton(tk.Canvas):
    """Modern button with hover effects and animations."""
    def __init__(self, parent, text="", command=None, width=100, height=35, 
                 bg_color="#3b82f6", hover_color="#2563eb", text_color="#ffffff",
                 font=("Segoe UI", 9, "bold"), corner_radius=6, **kwargs):
        super().__init__(parent, width=width, height=height, highlightthickness=0, **kwargs)
        
        self.command = command
        self.text = text
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text_color = text_color
        self.font = font
        self.corner_radius = corner_radius
        self.is_hovered = False
        
        self.configure(bg=parent.cget('bg'))
        
        # Store reference to the button shape
        self.button_shape = None
        
        # Create button shape
        self.button_shape = self.create_rounded_rect(2, 2, width-4, height-4, corner_radius, bg_color, "button")
        
        # Add text
        self.text_id = self.create_text(
            width//2, height//2,
            text=text, fill=text_color, font=font
        )
        
        # Bind events
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
    
    def create_rounded_rect(self, x1, y1, x2, y2, radius, color, tag):
        """Create a rounded rectangle."""
        points = []
        for x, y in [(x1+radius, y1), (x2-radius, y1), (x2, y1), (x2, y1+radius),
                     (x2, y2-radius), (x2, y2), (x2-radius, y2), (x1+radius, y2),
                     (x1, y2), (x1, y2-radius), (x1, y1+radius), (x1, y1)]:
            points.extend([x, y])
        
        return self.create_polygon(points, fill=color, smooth=True, tags=tag)
    
    def on_enter(self, event):
        """Handle mouse enter event."""
        self.is_hovered = True
        if self.button_shape:
            self.itemconfig(self.button_shape, fill=self.hover_color)
        self.config(cursor="hand2")
    
    def on_leave(self, event):
        """Handle mouse leave event."""
        self.is_hovered = False
        if self.button_shape:
            self.itemconfig(self.button_shape, fill=self.bg_color)
        self.config(cursor="")
    
    def on_click(self, event):
        """Handle button click event."""
        if self.command:
            self.command()

class ModernCard(tk.Frame):
    """Modern card with glassmorphism effect."""
    def __init__(self, parent, title="", **kwargs):
        super().__init__(parent, **kwargs)
        
        self.colors = config.colors[config.theme]
        
        # Configure frame
        self.configure(
            bg=self.colors["bg_card"],
            relief=tk.FLAT,
            borderwidth=0
        )
        
        # Add title if provided
        if title:
            title_label = tk.Label(
                self,
                text=title,
                bg=self.colors["bg_card"],
                fg=self.colors["text_primary"],
                font=("Segoe UI", 12, "bold")
            )
            title_label.pack(pady=(12, 6), padx=15, anchor=tk.W)
        
        # Add separator
        separator = tk.Frame(self, height=1, bg=self.colors["border"])
        separator.pack(fill=tk.X, padx=15, pady=(0, 12))

class ModernProgressBar(tk.Canvas):
    """Modern progress bar with animations."""
    def __init__(self, parent, width=300, height=8, **kwargs):
        super().__init__(parent, width=width, height=height, highlightthickness=0, **kwargs)
        
        self.colors = config.colors[config.theme]
        self.width = width
        self.height = height
        self.progress = 0
        self.target_progress = 0
        
        # Background
        self.create_rectangle(0, 0, width, height, fill=self.colors["bg_tertiary"], outline="")
        
        # Progress bar
        self.progress_bar = self.create_rectangle(
            0, 0, 0, height,
            fill=self.colors["accent"], outline=""
        )
        
        # Start animation loop
        self.animate()
    
    def set_progress(self, value):
        """Set progress value (0-100)."""
        self.target_progress = max(0, min(100, value))
    
    def animate(self):
        """Animate progress bar."""
        if abs(self.progress - self.target_progress) > 0.5:
            self.progress += (self.target_progress - self.progress) * 0.1
            self.coords(self.progress_bar, 0, 0, self.width * self.progress / 100, self.height)
        
        self.after(20, self.animate)

class ModernEntry(tk.Frame):
    """Modern entry field with floating label."""
    def __init__(self, parent, placeholder="", **kwargs):
        super().__init__(parent, **kwargs)
        
        self.colors = config.colors[config.theme]
        self.placeholder = placeholder
        self.is_focused = False
        
        # Configure frame
        self.configure(bg=self.colors["bg_card"])
        
        # Entry field
        self.entry = tk.Entry(
            self,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            borderwidth=0,
            insertbackground=self.colors["accent"]
        )
        self.entry.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Placeholder
        self.placeholder_label = tk.Label(
            self,
            text=placeholder,
            bg=self.colors["bg_card"],
            fg=self.colors["text_muted"],
            font=("Segoe UI", 9)
        )
        self.placeholder_label.place(x=10, y=5)
        
        # Bind events
        self.entry.bind("<FocusIn>", self.on_focus_in)
        self.entry.bind("<FocusOut>", self.on_focus_out)
        self.entry.bind("<KeyRelease>", self.on_key_release)
    
    def on_focus_in(self, event):
        """Handle focus in event."""
        self.is_focused = True
        self.placeholder_label.config(fg=self.colors["accent"])
        self.configure(bg=self.colors["accent"])
    
    def on_focus_out(self, event):
        """Handle focus out event."""
        self.is_focused = False
        if not self.entry.get():
            self.placeholder_label.config(fg=self.colors["text_muted"])
        self.configure(bg=self.colors["bg_card"])
    
    def on_key_release(self, event):
        """Handle key release event."""
        if self.entry.get():
            self.placeholder_label.place_forget()
        else:
            self.placeholder_label.place(x=10, y=5)
    
    def get(self):
        """Get entry value."""
        return self.entry.get()
    
    def set(self, value):
        """Set entry value."""
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
        if value:
            self.placeholder_label.place_forget()

class GoldenLogo(tk.Canvas):
    """Golden-Scan logo with transparent background."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, width=400, height=100, highlightthickness=0, **kwargs)
        
        self.colors = config.colors[config.theme]
        
        # Set transparent background
        self.configure(bg=self.colors["bg_secondary"])
        
        # Create logo text with shadow effect
        self.create_logo_text()
        
        # Create subtitle
        self.create_text(
            200, 70,
            text="Professional Security Analysis Tool",
            fill=self.colors["text_secondary"],
            font=("Segoe UI", 8)
        )
        
        # Create decorative elements
        self.create_decorative_elements()
    
    def create_logo_text(self):
        """Create the Golden-Scan logo text."""
        # Shadow text
        shadow_text = self.create_text(
            202, 35,
            text="Golden-Scan",
            fill=self.colors["bg_tertiary"],
            font=("Segoe UI", 24, "bold")
        )
        
        # Main golden text
        main_text = self.create_text(
            200, 32,
            text="Golden-Scan",
            fill=self.colors["gold"],
            font=("Segoe UI", 24, "bold")
        )
        
        # Add highlight effect
        highlight_text = self.create_text(
            200, 32,
            text="Golden-Scan",
            fill=self.colors["gold_light"],
            font=("Segoe UI", 24, "bold")
        )
        
        # Store references
        self.logo_texts = [shadow_text, main_text, highlight_text]
    
    def create_decorative_elements(self):
        """Create decorative golden elements."""
        # Left golden line
        self.create_line(
            50, 32, 140, 32,
            fill=self.colors["gold"], width=2, smooth=True
        )
        
        # Right golden line
        self.create_line(
            260, 32, 350, 32,
            fill=self.colors["gold"], width=2, smooth=True
        )
        
        # Golden dots
        for i in range(5):
            x = 60 + i * 15
            self.create_oval(
                x-2, 30, x+2, 34,
                fill=self.colors["gold"], outline=""
            )
        
        for i in range(5):
            x = 270 + i * 15
            self.create_oval(
                x-2, 30, x+2, 34,
                fill=self.colors["gold"], outline=""
            )

# ======================= MAIN GUI APPLICATION =======================
class VirusTotalScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Golden-Scan - Professional Security Scanner")
        self.root.geometry("1200x750")
        self.root.minsize(1000, 650)
        
        # Center window on screen
        self.center_window()
        
        # Initialize variables
        self.api_key = tk.StringVar(value=config.api_key)
        self.input_file = tk.StringVar(value=config.input_file)
        self.output_dir = tk.StringVar(value=str(config.output_dir))
        self.request_interval = tk.DoubleVar(value=config.request_interval)
        self.upload_if_not_found = tk.BooleanVar(value=config.upload_if_not_found)
        self.auto_create_dirs = tk.BooleanVar(value=config.auto_create_dirs)
        self.create_sample_input = tk.BooleanVar(value=config.create_sample_input)
        
        # Results storage
        self.results = []
        self.scan_thread = None
        self.stop_scan = False
        
        # Settings editing state
        self.editing_mode = False
        
        # Report generation state
        self.reports_generating = False
        self.report_threads_count = 0
        self.report_threads_completed = 0
        
        # Create UI
        self.setup_theme()
        
        # Check for API key at startup
        if not self.check_api_key():
            return
            
        self.create_widgets()
        
        # Check environment
        if not setup_environment():
            self.show_error("Failed to set up environment. Please check your settings.")
    
    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 7) - (height // 7)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        icon = PhotoImage(file="icon.png")
        self.root.iconphoto(False, icon)
    
    def check_api_key(self):
        """Check for API key and prompt if not set."""
        if not self.api_key.get():
            # Create API key dialog
            api_dialog = tk.Toplevel(self.root)
            api_dialog.title("VirusTotal API Key Required")
            api_dialog.geometry("500x477")
            api_dialog.configure(bg=config.colors[config.theme]["bg_primary"])
            api_dialog.transient(self.root)
            api_dialog.grab_set()
            api_dialog.focus_set()
            
            # Center the dialog
            api_dialog.update_idletasks()
            x = (api_dialog.winfo_screenwidth() // 2) - (500 // 2)
            y = (api_dialog.winfo_screenheight() // 5) - (300 // 5)
            api_dialog.geometry(f"500x477+{x}+{y}")
            icon = PhotoImage(file="icon.png")
            api_dialog.iconphoto(False, icon)
            # Create logo
            logo_frame = tk.Frame(api_dialog, bg=config.colors[config.theme]["bg_primary"])
            logo_frame.pack(pady=20)
            
            logo = GoldenLogo(logo_frame)
            logo.pack()
            
            # Create message
            message_frame = tk.Frame(api_dialog, bg=config.colors[config.theme]["bg_primary"])
            message_frame.pack(fill=tk.X, padx=30, pady=15)
            
            message_label = tk.Label(
                message_frame,
                text="Please enter your VirusTotal API key to continue.\n\nYou can get your API key from:\nhttps://www.virustotal.com/gui/join-us\n\nAuthor: Mohamed Abdellatif Jaber \nhttps://www.facebook.com/Mrm0hm3d \nVersion: 1.0 (First Edition)",
                bg=config.colors[config.theme]["bg_primary"],
                fg=config.colors[config.theme]["text_primary"],
                font=("Segoe UI", 10),
                justify=tk.CENTER
            )
            message_label.pack()
            
            # Create API key entry
            entry_frame = tk.Frame(api_dialog, bg=config.colors[config.theme]["bg_primary"])
            entry_frame.pack(fill=tk.X, padx=30, pady=20)
            
            api_entry = ModernEntry(entry_frame)
            api_entry.pack(fill=tk.X, padx=30, pady=20)
            
            # Create buttons
            button_frame = tk.Frame(api_dialog, bg=config.colors[config.theme]["bg_primary"])
            button_frame.pack(fill=tk.X, padx=30, pady=15)
            
            def save_api_key():
                key = api_entry.get().strip()
                if key:
                    self.api_key.set(key)
                    config.api_key = key
                    api_dialog.destroy()
                else:
                    messagebox.showerror("Error", "API key cannot be empty!")
            
            def quit_app():
                api_dialog.destroy()
                self.root.quit()
            
            save_btn = ModernButton(
                button_frame,
                text="Continue",
                command=save_api_key,
                width=100,
                height=35,
                bg_color=config.colors[config.theme]["success"],
                hover_color="#059669"
            )
            save_btn.pack(side=tk.RIGHT, padx=(10, 0))
            
            quit_btn = ModernButton(
                button_frame,
                text="Quit",
                command=quit_app,
                width=100,
                height=35,
                bg_color=config.colors[config.theme]["danger"],
                hover_color="#dc2626"
            )
            quit_btn.pack(side=tk.RIGHT)
            
            # Wait for dialog to close
            self.root.wait_window(api_dialog)
            
            # Check if API key was provided
            if not self.api_key.get():
                return False
        
        return True
    
    def setup_theme(self):
        """Setup the theme for the application."""
        self.colors = config.colors[config.theme]
        
        # Configure root
        self.root.configure(bg=self.colors["bg_primary"])
        
        # Configure styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure ttk styles
        style.configure("TFrame", background=self.colors["bg_primary"])
        style.configure("TLabel", background=self.colors["bg_primary"], foreground=self.colors["text_primary"])
        style.configure("TNotebook", background=self.colors["bg_primary"])
        style.configure("TNotebook.Tab", background=self.colors["bg_secondary"], foreground=self.colors["text_secondary"])
        style.map("TNotebook.Tab", background=[("selected", self.colors["bg_card"])])
    
    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container
        self.main_container = tk.Frame(self.root, bg=self.colors["bg_primary"])
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create header
        self.create_header()
        
        # Create content area
        self.create_content_area()
        
        # Create status bar
        self.create_status_bar()
    
    def create_header(self):
        """Create the header section."""
        header = tk.Frame(self.main_container, bg=self.colors["bg_secondary"], height=120)
        header.pack(fill=tk.X, padx=20, pady=(20, 15))
        header.pack_propagate(False)
        
        # Logo container with transparent background
        logo_container = tk.Frame(header, bg=self.colors["bg_secondary"])
        logo_container.pack(side=tk.LEFT, padx=20, pady=20)
        
        # Create logo on transparent canvas
        self.logo = GoldenLogo(logo_container)
        self.logo.pack()
        
        # Theme toggle button
        theme_frame = tk.Frame(header, bg=self.colors["bg_secondary"])
        theme_frame.pack(side=tk.RIGHT, padx=20, pady=20)
        
        self.theme_button = ModernButton(
            theme_frame,
            text="🌙 Dark",
            command=self.toggle_theme,
            width=90,
            height=35,
            bg_color=self.colors["bg_tertiary"],
            hover_color=self.colors["bg_hover"],
            corner_radius=18
        )
        self.theme_button.pack()
    
    def create_content_area(self):
        """Create the main content area."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_results_tab()
        self.create_settings_tab()
        self.create_logs_tab()
    
    def create_dashboard_tab(self):
        """Create the dashboard tab."""
        self.dashboard_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(self.dashboard_frame, text="📊 Dashboard")
        
        # Statistics cards
        stats_container = tk.Frame(self.dashboard_frame, bg=self.colors["bg_primary"])
        stats_container.pack(fill=tk.X, padx=20, pady=20)
        
        # Create stat cards
        self.total_files_card = self.create_stat_card(stats_container, "Total Files", "0", "#3b82f6")
        self.total_files_card.pack(side=tk.LEFT, padx=10)
        
        self.malicious_files_card = self.create_stat_card(stats_container, "Malicious", "0", "#ef4444")
        self.malicious_files_card.pack(side=tk.LEFT, padx=10)
        
        self.suspicious_files_card = self.create_stat_card(stats_container, "Suspicious", "0", "#f59e0b")
        self.suspicious_files_card.pack(side=tk.LEFT, padx=10)
        
        self.clean_files_card = self.create_stat_card(stats_container, "Clean", "0", "#10b981")
        self.clean_files_card.pack(side=tk.LEFT, padx=10)
        
        # Recent scans
        recent_frame = ModernCard(self.dashboard_frame, title="Recent Scans")
        recent_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Create treeview for recent scans
        self.recent_tree = self.create_modern_treeview(recent_frame)
        self.recent_tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
    
    def create_scan_tab(self):
        """Create the scan tab."""
        self.scan_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(self.scan_frame, text="🔍 Scan")
        
        # Scan controls card
        controls_card = ModernCard(self.scan_frame, title="Scan Configuration")
        controls_card.pack(fill=tk.X, padx=20, pady=20)
        
        # Input file selection
        input_frame = tk.Frame(controls_card, bg=self.colors["bg_card"])
        input_frame.pack(fill=tk.X, padx=15, pady=12)
        
        tk.Label(
            input_frame,
            text="Input File:",
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.input_entry = ModernEntry(input_frame, placeholder="Select input file...")
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.input_entry.set(self.input_file.get())
        
        browse_btn = ModernButton(
            input_frame,
            text="Browse",
            command=self.browse_input_file,
            width=80,
            height=35
        )
        browse_btn.pack(side=tk.RIGHT)
        
        # Output directory selection
        output_frame = tk.Frame(controls_card, bg=self.colors["bg_card"])
        output_frame.pack(fill=tk.X, padx=15, pady=12)
        
        tk.Label(
            output_frame,
            text="Output Directory:",
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.output_entry = ModernEntry(output_frame, placeholder="Select output directory...")
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.output_entry.set(self.output_dir.get())
        
        browse_output_btn = ModernButton(
            output_frame,
            text="Browse",
            command=self.browse_output_dir,
            width=80,
            height=35
        )
        browse_output_btn.pack(side=tk.RIGHT)
        
        # Scan buttons
        buttons_frame = tk.Frame(controls_card, bg=self.colors["bg_card"])
        buttons_frame.pack(fill=tk.X, padx=15, pady=20)
        
        self.scan_button = ModernButton(
            buttons_frame,
            text="🚀 Start Scan",
            command=self.start_scan,
            width=120,
            height=40,
            bg_color=self.colors["success"],
            hover_color="#059669"
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ModernButton(
            buttons_frame,
            text="⏹ Stop Scan",
            command=self.stop_scan_func,
            width=120,
            height=40,
            bg_color=self.colors["danger"],
            hover_color="#dc2626"
        )
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.view_reports_button = ModernButton( # Store reference
            buttons_frame,
            text="📄 View Reports",
            command=self.view_reports,
            width=120,
            height=40,
            bg_color=self.colors["accent"],
            hover_color=self.colors["accent_hover"]
        )
        self.view_reports_button.pack(side=tk.RIGHT)
        
        # Progress section
        progress_card = ModernCard(self.scan_frame, title="Scan Progress")
        progress_card.pack(fill=tk.X, padx=20, pady=15)
        
        # Progress bar
        progress_frame = tk.Frame(progress_card, bg=self.colors["bg_card"])
        progress_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.progress_bar = ModernProgressBar(progress_frame, width=350)
        self.progress_bar.pack(side=tk.LEFT, padx=(0, 20))
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to scan",
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        )
        self.progress_label.pack(side=tk.LEFT)
        
        # Current file display
        self.current_file_label = tk.Label(
            progress_card,
            text="",
            bg=self.colors["bg_card"],
            fg=self.colors["text_muted"],
            font=("Segoe UI", 9)
        )
        self.current_file_label.pack(pady=(0, 15))
    
    def create_results_tab(self):
        """Create the results tab."""
        self.results_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(self.results_frame, text="📋 Results")
        
        # Results card
        results_card = ModernCard(self.results_frame, title="Scan Results")
        results_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create treeview for results
        self.results_tree = self.create_modern_treeview(results_card)
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Bind double-click event
        self.results_tree.bind("<Double-1>", self.show_result_details)
    
    def create_settings_tab(self):
        """Create the settings tab."""
        self.settings_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        
        # API settings card
        self.api_card = ModernCard(self.settings_frame, title="API Settings")
        self.api_card.pack(fill=tk.X, padx=20, pady=20)
        
        self.create_api_settings()
        
        # Scanner settings card
        scanner_card = ModernCard(self.settings_frame, title="Scanner Settings")
        scanner_card.pack(fill=tk.X, padx=20, pady=15)
        
        self.create_scanner_settings(scanner_card)
    
    def create_api_settings(self):
        """Create API settings section."""
        # Clear existing widgets
        for widget in self.api_card.winfo_children():
            if isinstance(widget, tk.Frame) and widget.winfo_children():
                for child in widget.winfo_children():
                    child.destroy()
            widget.destroy()
        
        api_frame = tk.Frame(self.api_card, bg=self.colors["bg_card"])
        api_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Title and Edit button
        title_frame = tk.Frame(api_frame, bg=self.colors["bg_card"])
        title_frame.pack(fill=tk.X, pady=(0, 12))
        
        tk.Label(
            title_frame,
            text="VirusTotal API Key:",
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT)
        
        # Show API key masked
        masked_key = self.mask_api_key(self.api_key.get())
        self.api_display_label = tk.Label(
            title_frame,
            text=masked_key,
            bg=self.colors["bg_card"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10, "normal")
        )
        self.api_display_label.pack(side=tk.LEFT, padx=(12, 12))
        
        # Edit button
        edit_btn = ModernButton(
            title_frame,
            text="✏️ Edit",
            command=self.enable_api_edit,
            width=80,
            height=32,
            bg_color=self.colors["accent"],
            hover_color=self.colors["accent_hover"]
        )
        edit_btn.pack(side=tk.RIGHT)
    
    def create_scanner_settings(self, parent):
        """Create scanner settings section."""
        # Clear existing widgets
        for widget in parent.winfo_children():
            if isinstance(widget, tk.Frame):
                for child in widget.winfo_children():
                    child.destroy()
            widget.destroy()
        
        scanner_frame = tk.Frame(parent, bg=self.colors["bg_card"])
        scanner_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Request interval
        interval_frame = tk.Frame(scanner_frame, bg=self.colors["bg_card"])
        interval_frame.pack(fill=tk.X, pady=6)
        
        tk.Label(
            interval_frame,
            text="Request Interval (seconds):",
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        ).pack(side=tk.LEFT)
        
        interval_entry = tk.Entry(
            interval_frame,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10),
            width=10,
            textvariable=self.request_interval,
            state=tk.NORMAL if self.editing_mode else tk.DISABLED
        )
        interval_entry.pack(side=tk.RIGHT)
        
        # Upload checkbox
        upload_check = tk.Checkbutton(
            scanner_frame,
            text="Upload files not found in VT",
            variable=self.upload_if_not_found,
            bg=self.colors["bg_card"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10),
            selectcolor=self.colors["bg_tertiary"],
            state=tk.NORMAL if self.editing_mode else tk.DISABLED
        )
        upload_check.pack(anchor=tk.W, pady=12)
        
        # Auto-creation settings
        auto_frame = tk.Frame(scanner_frame, bg=self.colors["bg_card"])
        auto_frame.pack(fill=tk.X, pady=12)
        
        auto_dirs_check = tk.Checkbutton(
            auto_frame,
            text="Automatically create missing directories",
            variable=self.auto_create_dirs,
            bg=self.colors["bg_card"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10),
            selectcolor=self.colors["bg_tertiary"],
            state=tk.NORMAL if self.editing_mode else tk.DISABLED
        )
        auto_dirs_check.pack(anchor=tk.W, pady=6)
        
        sample_input_check = tk.Checkbutton(
            auto_frame,
            text="Create sample input file if missing",
            variable=self.create_sample_input,
            bg=self.colors["bg_card"],
            fg=self.colors["text_primary"],
            font=("Segoe UI", 10),
            selectcolor=self.colors["bg_tertiary"],
            state=tk.NORMAL if self.editing_mode else tk.DISABLED
        )
        sample_input_check.pack(anchor=tk.W, pady=6)
        
        # Edit/Save buttons
        buttons_frame = tk.Frame(scanner_frame, bg=self.colors["bg_card"])
        buttons_frame.pack(fill=tk.X, pady=20)
        
        if not self.editing_mode:
            edit_all_btn = ModernButton(
                buttons_frame,
                text="✏️ Edit All Settings",
                command=self.enable_edit_mode,
                width=150,
                height=38,
                bg_color=self.colors["accent"],
                hover_color=self.colors["accent_hover"]
            )
            edit_all_btn.pack(side=tk.LEFT)
        else:
            cancel_all_btn = ModernButton(
                buttons_frame,
                text="Cancel",
                command=self.cancel_edit_mode,
                width=100,
                height=38,
                bg_color=self.colors["bg_tertiary"],
                hover_color=self.colors["bg_hover"]
            )
            cancel_all_btn.pack(side=tk.LEFT, padx=(0, 10))
            
            save_all_btn = ModernButton(
                buttons_frame,
                text="💾 Save All Settings",
                command=self.save_all_settings,
                width=150,
                height=38,
                bg_color=self.colors["success"],
                hover_color="#059669"
            )
            save_all_btn.pack(side=tk.LEFT)
    
    def mask_api_key(self, api_key):
        """Mask the API key for display."""
        if not api_key:
            return "Not set"
        if len(api_key) <= 8:
            return "*" * len(api_key)
        return api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:]
    
    def enable_api_edit(self):
        """Enable API key editing."""
        self.editing_mode = True
        self.create_api_settings()
        self.create_scanner_settings(self.api_card.master.winfo_children()[1])
    
    def cancel_api_edit(self):
        """Cancel API key editing."""
        self.editing_mode = False
        self.create_api_settings()
        self.create_scanner_settings(self.api_card.master.winfo_children()[1])
    
    def save_api_settings(self):
        """Save API settings."""
        new_key = self.api_entry.get().strip()
        if new_key:
            self.api_key.set(new_key)
            config.api_key = new_key
            self.editing_mode = False
            self.create_api_settings()
            self.create_scanner_settings(self.api_card.master.winfo_children()[1])
            self.show_success("API key saved successfully!")
        else:
            self.show_error("API key cannot be empty!")
    
    def enable_edit_mode(self):
        """Enable edit mode for all settings."""
        self.editing_mode = True
        self.create_api_settings()
        self.create_scanner_settings(self.api_card.master.winfo_children()[1])
    
    def cancel_edit_mode(self):
        """Cancel edit mode."""
        self.editing_mode = False
        self.create_api_settings()
        self.create_scanner_settings(self.api_card.master.winfo_children()[1])
    
    def save_all_settings(self):
        """Save all settings."""
        # Save API key
        if hasattr(self, 'api_entry'):
            new_key = self.api_entry.get().strip()
            if new_key:
                self.api_key.set(new_key)
                config.api_key = new_key
        
        # Save other settings
        config.input_file = self.input_file.get()
        config.output_dir = Path(self.output_dir.get())
        config.request_interval = self.request_interval.get()
        config.upload_if_not_found = self.upload_if_not_found.get()
        config.auto_create_dirs = self.auto_create_dirs.get()
        config.create_sample_input = self.create_sample_input.get()
        
        # Update environment
        setup_environment()
        
        # Exit edit mode
        self.editing_mode = False
        self.create_api_settings()
        self.create_scanner_settings(self.api_card.master.winfo_children()[1])
        
        self.show_success("All settings saved successfully!")
    
    def create_logs_tab(self):
        """Create the logs tab."""
        self.logs_frame = tk.Frame(self.notebook, bg=self.colors["bg_primary"])
        self.notebook.add(self.logs_frame, text="📝 Logs")
        
        # Logs card
        logs_card = ModernCard(self.logs_frame, title="System Logs")
        logs_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Create text widget for logs
        self.logs_text = scrolledtext.ScrolledText(
            logs_card,
            wrap=tk.WORD,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 9),
            insertbackground=self.colors["accent"]
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Configure text tags
        self.logs_text.tag_config("INFO", foreground=self.colors["text_primary"])
        self.logs_text.tag_config("WARNING", foreground=self.colors["warning"])
        self.logs_text.tag_config("ERROR", foreground=self.colors["danger"])
        
        # Add log handler
        self.log_handler = GUILogHandler(self.logs_text)
        if logger:
            logger.addHandler(self.log_handler)
    
    def create_status_bar(self):
        """Create the status bar."""
        status_bar = tk.Frame(self.main_container, bg=self.colors["bg_secondary"], height=35)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        
        # Status text
        self.status_text = tk.StringVar(value="Ready")
        status_label = tk.Label(
            status_bar,
            textvariable=self.status_text,
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 9)
        )
        status_label.pack(side=tk.LEFT, padx=20, pady=8)
        
        # Version info
        version_label = tk.Label(
            status_bar,
            text="Golden-Scan v1.0 Premium Edition",
            bg=self.colors["bg_secondary"],
            fg=self.colors["text_muted"],
            font=("Segoe UI", 8)
        )
        version_label.pack(side=tk.RIGHT, padx=20, pady=8)
    
    def create_stat_card(self, parent, title, value, color):
        """Create a statistics card."""
        card = tk.Frame(parent, bg=self.colors["bg_card"], width=200, height=90)
        card.pack_propagate(False)
        
        # Value
        value_label = tk.Label(
            card,
            text=value,
            bg=self.colors["bg_card"],
            fg=color,
            font=("Segoe UI", 22, "bold")
        )
        value_label.pack(pady=(18, 6))
        
        # Title
        title_label = tk.Label(
            card,
            text=title,
            bg=self.colors["bg_card"],
            fg=self.colors["text_secondary"],
            font=("Segoe UI", 10)
        )
        title_label.pack()
        
        return card
    
    def create_modern_treeview(self, parent):
        """Create a modern treeview widget."""
        # Create frame for treeview
        tree_frame = tk.Frame(parent, bg=self.colors["bg_card"])
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview
        columns = ("file_name", "path", "size", "sha256", "vt_result", "verdict", "status")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        # Configure headings
        tree.heading("file_name", text="File Name")
        tree.heading("path", text="Path")
        tree.heading("size", text="Size")
        tree.heading("sha256", text="SHA256")
        tree.heading("vt_result", text="VT Detection")
        tree.heading("verdict", text="Verdict")
        tree.heading("status", text="Status")
        
        # Configure columns
        tree.column("file_name", width=150)
        tree.column("path", width=280)
        tree.column("size", width=80)
        tree.column("sha256", width=140)
        tree.column("vt_result", width=120)
        tree.column("verdict", width=100)
        tree.column("status", width=80)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        return tree
    
    def toggle_theme(self):
        """Toggle between dark and light theme."""
        if config.theme == "dark":
            config.theme = "light"
            self.theme_button.configure(text="☀️ Light")
        else:
            config.theme = "dark"
            self.theme_button.configure(text="🌙 Dark")
        
        # Update colors
        self.colors = config.colors[config.theme]
        
        # Recreate UI with new theme
        for widget in self.main_container.winfo_children():
            widget.destroy()
        
        self.setup_theme()
        self.create_widgets()
    
    def browse_input_file(self):
        """Browse for input file."""
        filename = filedialog.askopenfilename(
            title="Select Input File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            self.input_file.set(filename)
            self.input_entry.set(filename)
    
    def browse_output_dir(self):
        """Browse for output directory."""
        dirname = filedialog.askdirectory(title="Select Output Directory")
        if dirname:
            self.output_dir.set(dirname)
            self.output_entry.set(dirname)
    
    def start_scan(self):
        """Start the scanning process."""
        # Validate settings
        if not self.api_key.get():
            self.show_error("VirusTotal API key is required!")
            return
        
        # Update UI
        self.scan_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress_bar.set_progress(0)
        self.progress_label.config(text="Initializing scan...")
        self.status_text.set("Scanning...")
        
        # Clear previous results
        self.results = []
        self.results_tree.delete(*self.results_tree.get_children())
        self.recent_tree.delete(*self.recent_tree.get_children())
        
        # Reset stop flag
        self.stop_scan = False
        
        # Start scan thread
        self.scan_thread = threading.Thread(target=self.scan_worker)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan_func(self):
        """Stop the scanning process."""
        self.stop_scan = True
        self.progress_label.config(text="Stopping scan...")
        self.status_text.set("Stopping...")
    
    def scan_worker(self):
        """Worker function for scanning."""
        try:
            # Update config with current settings
            self.save_settings()
            
            # Extract file paths
            files = self.extract_paths_from_input(config.input_file)
            if not files:
                self.root.after(0, lambda: self.show_error("No files found in input file!"))
                return
            
            total_files = len(files)
            
            # Scan files
            for idx, file_path in enumerate(files):
                if self.stop_scan:
                    break
                
                # Update status
                self.root.after(0, lambda i=idx, f=file_path: self.update_scan_status(i+1, total_files, f))
                
                # Check if file exists
                if not os.path.exists(file_path):
                    if logger:
                        logger.warning(f"File not found: {file_path}")
                    else:
                        print(f"File not found: {file_path}")
                    result = ScanResult(
                        file_name=os.path.basename(file_path),
                        file_path=file_path,
                        file_size=0,
                        sha256="",
                        md5="",
                        vt_result="File not found",
                        vt_stats={},
                        verdict="Unknown",
                        pe_info={},
                        scan_time=datetime.now().isoformat(),
                        error="File not found",
                        uploaded=False
                    )
                else:
                    # Scan the file
                    result = self.scan_one_file(file_path)
                
                # Add to results
                self.results.append(result)
                
                # Update UI
                self.root.after(0, lambda r=result: self.add_result_to_tree(r))
                self.root.after(0, self.update_dashboard)
                
                # Update progress
                progress = ((idx + 1) / total_files) * 100
                self.root.after(0, lambda p=progress: self.progress_bar.set_progress(p))
                
                # Wait to respect VT rate limit
                if config.request_interval > 0:
                    time.sleep(config.request_interval)
            
            # Update UI when done
            self.root.after(0, self.scan_complete)
        
        except Exception as e:
            if logger:
                logger.error(f"Error during scan: {e}")
            else:
                print(f"Error during scan: {e}")
            self.root.after(0, lambda: self.show_error(f"An error occurred during scanning: {str(e)}"))
            self.root.after(0, self.scan_complete)
    
    def save_settings(self):
        """Save settings (for backward compatibility)."""
        self.save_all_settings()
    
    def update_scan_status(self, current, total, file_path):
        """Update scan status display."""
        self.progress_label.config(text=f"Scanning ({current}/{total})")
        self.current_file_label.config(text=f"Current file: {os.path.basename(file_path)}")
    
    def scan_one_file(self, file_path: str) -> ScanResult:
        """Scan a single file and return the result."""
        file_name = os.path.basename(file_path)
        scan_time = datetime.now().isoformat()
        
        # Compute hashes and file size
        sha256, md5, file_size = compute_hashes(file_path)
        
        if not sha256:
            return ScanResult(
                file_name=file_name,
                file_path=file_path,
                file_size=0,
                sha256="",
                md5="",
                vt_result="Error reading file",
                vt_stats={},
                verdict="Unknown",
                pe_info={},
                scan_time=scan_time,
                error="Failed to compute file hashes",
                uploaded=False
            )
        
        # Initialize result
        result = ScanResult(
            file_name=file_name,
            file_path=file_path,
            file_size=file_size,
            sha256=sha256,
            md5=md5,
            vt_result="",
            vt_stats={},
            verdict="Unknown",
            pe_info={},
            scan_time=scan_time,
            uploaded=False
        )
        
        # Query VirusTotal
        status, payload = vt_get_by_hash(sha256)
        
        if status == 200:
            # Parse VT response
            result.vt_stats = parse_vt_stats(payload) or {}
            result.vt_result = f"M:{result.vt_stats.get('malicious', 0)} S:{result.vt_stats.get('suspicious', 0)} U:{result.vt_stats.get('undetected', 0)}"
            result.verdict = determine_verdict(result.vt_stats, result.vt_result)
            result.uploaded = False
        elif status == 404:
            result.vt_result = "Not in VT DB"
            
            # Upload to VT if enabled
            if config.upload_if_not_found:
                if logger:
                    logger.info(f"Uploading {file_name} to VT...")
                else:
                    print(f"Uploading {file_name} to VT...")
                success, upload_response = vt_upload_file(file_path)
                if success:
                    result.uploaded = True
                    result.vt_result = "Uploaded - Pending Analysis"
                    
                    # Wait a bit and try to get analysis
                    time.sleep(5)
                    upload_status, upload_payload = vt_get_by_hash(sha256)
                    if upload_status == 200:
                        result.vt_stats = parse_vt_stats(upload_payload) or {}
                        result.vt_result = f"M:{result.vt_stats.get('malicious', 0)} S:{result.vt_stats.get('suspicious', 0)} U:{result.vt_stats.get('undetected', 0)}"
                        result.verdict = determine_verdict(result.vt_stats, result.vt_result)
                else:
                    result.vt_result = f"Upload failed: {upload_response}"
                    result.error = str(upload_response)
            
            result.verdict = determine_verdict(None, result.vt_result)
        else:
            result.vt_result = f"Error querying VT: {payload}"
            result.error = str(payload)
        
        return result
    
    def extract_paths_from_input(self, input_path: str) -> List[str]:
        """Extract file paths from an input file."""
        paths = []
        
        if not ensure_file_exists(input_path, config.create_sample_input):
            if logger:
                logger.error(f"Input file {input_path} not found and could not be created.")
            else:
                print(f"Input file {input_path} not found and could not be created.")
            return paths
        
        with open(input_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.rstrip("\n\r")
                if not line.strip() or line.strip().startswith("#"):
                    continue
                
                cols = line.split("\t")
                
                # Try to find column that looks like a path
                candidate = None
                for c in cols[::-1]:
                    if (":\\" in c) or c.startswith("\\\\") or c.lower().endswith((".exe", ".dll", ".sys")):
                        candidate = c.strip()
                        break
                
                if candidate:
                    # Remove quotes if present
                    if candidate.startswith('"') and candidate.endswith('"'):
                        candidate = candidate[1:-1]
                    paths.append(candidate)
        
        # Deduplicate while preserving order
        seen = set()
        unique_paths = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                unique_paths.append(p)
        
        return unique_paths
    
    def add_result_to_tree(self, result):
        """Add a scan result to the tree view."""
        # Format file size
        if result.file_size > 1024*1024:
            size_str = f"{result.file_size/1024/1024:.0f}M"
        elif result.file_size > 1024:
            size_str = f"{result.file_size/1024:.0f}K"
        else:
            size_str = f"{result.file_size}"
        
        # Truncate SHA256
        sha256_short = result.sha256[:14] + "..." if len(result.sha256) > 14 else result.sha256
        
        # Truncate path
        path_short = result.file_path
        if len(path_short) > 40:
            path_short = "..." + path_short[-40:]
        
        # Determine status
        status = "↑" if result.uploaded else "✓"
        
        # Insert into results tree
        item = self.results_tree.insert(
            "", tk.END,
            values=(
                result.file_name,
                path_short,
                size_str,
                sha256_short,
                result.vt_result,
                result.verdict,
                status
            )
        )
        
        # Insert into recent tree (only last 10)
        if self.recent_tree.get_children():
            if len(self.recent_tree.get_children()) >= 10:
                self.recent_tree.delete(self.recent_tree.get_children()[0])
        
        recent_item = self.recent_tree.insert(
            "", tk.END,
            values=(
                result.file_name,
                result.verdict,
                result.vt_result
            )
        )
        
        # Color code based on verdict
        if result.verdict == "Malicious":
            self.results_tree.item(item, tags=("malicious",))
            self.recent_tree.item(recent_item, tags=("malicious",))
        elif result.verdict == "Suspicious":
            self.results_tree.item(item, tags=("suspicious",))
            self.recent_tree.item(recent_item, tags=("suspicious",))
        elif result.verdict == "Clean":
            self.results_tree.item(item, tags=("clean",))
            self.recent_tree.item(recent_item, tags=("clean",))
        
        # Configure tags
        self.results_tree.tag_configure("malicious", foreground=self.colors["danger"])
        self.results_tree.tag_configure("suspicious", foreground=self.colors["warning"])
        self.results_tree.tag_configure("clean", foreground=self.colors["success"])
        
        self.recent_tree.tag_configure("malicious", foreground=self.colors["danger"])
        self.recent_tree.tag_configure("suspicious", foreground=self.colors["warning"])
        self.recent_tree.tag_configure("clean", foreground=self.colors["success"])
    
    def update_dashboard(self):
        """Update dashboard statistics."""
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.verdict == "Malicious")
        suspicious = sum(1 for r in self.results if r.verdict == "Suspicious")
        clean = sum(1 for r in self.results if r.verdict == "Clean")
        
        # Update stat cards
        self.total_files_card.winfo_children()[0].config(text=str(total))
        self.malicious_files_card.winfo_children()[0].config(text=str(malicious))
        self.suspicious_files_card.winfo_children()[0].config(text=str(suspicious))
        self.clean_files_card.winfo_children()[0].config(text=str(clean))
    
    def scan_complete(self):
        """Called when scanning is complete."""
        # Update UI
        self.scan_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.progress_label.config(text="Scan completed")
        self.current_file_label.config(text="")
        
        # Show summary
        total = len(self.results)
        malicious = sum(1 for r in self.results if r.verdict == "Malicious")
        suspicious = sum(1 for r in self.results if r.verdict == "Suspicious")
        
        if malicious > 0 or suspicious > 0:
            self.show_warning(f"Scan completed with {malicious} malicious and {suspicious} suspicious files detected!")
        else:
            self.show_success(f"Scan completed successfully. No threats detected in {total} files.")
        
        # Start report generation process
        self.reports_generating = True
        self.report_threads_count = 0
        self.report_threads_completed = 0
        self.status_text.set("Generating reports...")
        self.view_reports_button.configure(state=tk.DISABLED) # Disable button
        
        self.generate_all_reports()
    
    def show_result_details(self, event):
        """Show details for the selected result."""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        # Get selected item
        item = selection[0]
        idx = self.results_tree.index(item)
        
        if idx >= len(self.results):
            return
        
        result = self.results[idx]
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"File Details: {result.file_name}")
        details_window.geometry("800x600")
        details_window.configure(bg=self.colors["bg_primary"])
        
        # Create notebook for tabs
        notebook = ttk.Notebook(details_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General tab
        general_frame = tk.Frame(notebook, bg=self.colors["bg_primary"])
        notebook.add(general_frame, text="General")
        
        # Create text widget for general info
        general_text = scrolledtext.ScrolledText(
            general_frame,
            wrap=tk.WORD,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10)
        )
        general_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add general info
        general_text.insert(tk.END, f"File Name: {result.file_name}\n")
        general_text.insert(tk.END, f"File Path: {result.file_path}\n")
        general_text.insert(tk.END, f"File Size: {result.file_size} bytes\n")
        general_text.insert(tk.END, f"SHA256: {result.sha256}\n")
        general_text.insert(tk.END, f"MD5: {result.md5}\n")
        general_text.insert(tk.END, f"Scan Time: {result.scan_time}\n")
        general_text.insert(tk.END, f"Verdict: {result.verdict}\n")
        general_text.insert(tk.END, f"Status: {'Uploaded to VT' if result.uploaded else 'Found in VT'}\n")
        
        if result.error:
            general_text.insert(tk.END, f"Error: {result.error}\n")
        
        # VirusTotal tab
        vt_frame = tk.Frame(notebook, bg=self.colors["bg_primary"])
        notebook.add(vt_frame, text="VirusTotal")
        
        # Create text widget for VT info
        vt_text = scrolledtext.ScrolledText(
            vt_frame,
            wrap=tk.WORD,
            bg=self.colors["bg_tertiary"],
            fg=self.colors["text_primary"],
            font=("Consolas", 10)
        )
        vt_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add VT info
        vt_text.insert(tk.END, f"VT Result: {result.vt_result}\n")
        
        if result.vt_stats and len(result.vt_stats) > 0:
            vt_text.insert(tk.END, "\nVT Statistics:\n")
            for key, value in result.vt_stats.items():
                vt_text.insert(tk.END, f"  {key}: {value}\n")
    
    def view_reports(self):
        """View generated reports."""
        # *** KEY FIX: Check if reports are being generated ***
        if self.reports_generating:
            self.show_info("Reports are currently being generated. Please wait...")
            return

        if not self.results:
            self.show_info("No scan results available. Please run a scan first.")
            return
        
        # Create reports window
        reports_window = tk.Toplevel(self.root)
        reports_window.title("Scan Reports")
        reports_window.geometry("400x300")
        reports_window.configure(bg=self.colors["bg_primary"])
        
        # Reports card
        reports_card = ModernCard(reports_window, title="Available Reports")
        reports_card.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Report files
        report_files = [
            ("HTML Report", config.html_output),
            ("Text Report", config.text_output),
            ("JSON Report", config.json_output),
            ("CSV Report", config.csv_output)
        ]
        
        # Add threats reports if available
        threats = [r for r in self.results if r.is_threat]
        if threats:
            report_files.extend([
                ("Threats HTML Report", config.threats_html),
                ("Threats Text Report", config.threats_text),
                ("Threats JSON Report", config.threats_json)
            ])
        
        # Create buttons for each report
        for name, path in report_files:
            btn_frame = tk.Frame(reports_card, bg=self.colors["bg_card"])
            btn_frame.pack(fill=tk.X, pady=6)
            
            tk.Label(
                btn_frame,
                text=name,
                bg=self.colors["bg_card"],
                fg=self.colors["text_primary"],
                font=("Segoe UI", 10)
            ).pack(side=tk.LEFT, padx=15)
            
            if os.path.exists(path):
                open_btn = ModernButton(
                    btn_frame,
                    text="Open",
                    command=lambda p=path: self.open_report(p),
                    width=70,
                    height=30
                )
                open_btn.pack(side=tk.RIGHT, padx=15)
            else:
                # *** IMPROVEMENT: Log the missing path for debugging ***
                if logger:
                    logger.warning(f"Report not found for viewing: {path}")
                tk.Label(
                    btn_frame,
                    text="Not available",
                    bg=self.colors["bg_card"],
                    fg=self.colors["text_muted"],
                    font=("Segoe UI", 9)
                ).pack(side=tk.RIGHT, padx=15)
    
    def open_report(self, path):
        """Open a report file."""
        try:
            if path.endswith('.html'):
                webbrowser.open(f"file://{os.path.abspath(path)}")
            else:
                # Use a more cross-platform way to open files
                if sys.platform == "win32":
                    os.startfile(path)
                elif sys.platform == "darwin": # macOS
                    os.system(f"open {path}")
                else: # Linux
                    os.system(f"xdg-open {path}")
        except Exception as e:
            self.show_error(f"Failed to open report: {str(e)}")
    
    def show_error(self, message):
        """Show error message."""
        messagebox.showerror("Error", message)
    
    def show_warning(self, message):
        """Show warning message."""
        messagebox.showwarning("Warning", message)
    
    def show_info(self, message):
        """Show info message."""
        messagebox.showinfo("Info", message)
    
    def show_success(self, message):
        """Show success message."""
        messagebox.showinfo("Success", message)

    # ======================= REPORT GENERATION FUNCTIONS =======================
    def generate_all_reports(self):
        """Generate all report formats after scan completion."""
        if not self.results:
            # This case is handled in view_reports, but as a safeguard:
            self._on_report_generation_complete()
            return
        
        try:
            # Ensure output directory exists
            ensure_directory_exists(config.output_dir)
            
            # Standard reports
            self._start_report_thread(self.generate_text_report)
            self._start_report_thread(self.generate_html_report)
            self._start_report_thread(self.generate_json_report)
            self._start_report_thread(self.generate_csv_report)
            
            # Check for threats and generate threat reports if needed
            threats = [r for r in self.results if r.is_threat]
            if threats:
                self._start_report_thread(self.generate_threats_text_report)
                self._start_report_thread(self.generate_threats_html_report)
                self._start_report_thread(self.generate_threats_json_report)
            
        except Exception as e:
            if logger:
                logger.error(f"Fatal error in report generation manager: {e}")
            else:
                print(f"Fatal error in report generation manager: {e}")
            # Ensure UI is reset even on failure
            self.root.after(0, self._on_report_generation_complete)

    def _start_report_thread(self, target_func):
        """Helper to start a report generation thread and track it."""
        self.report_threads_count += 1
        thread = threading.Thread(target=self._run_and_track_report, args=(target_func,))
        thread.daemon = True
        thread.start()

    def _run_and_track_report(self, target_func):
        """Wrapper for report generation functions to handle completion."""
        try:
            target_func()
        except Exception as e:
            if logger:
                logger.error(f"Error in report generation thread: {e}")
        finally:
            # Schedule the completion check on the main thread
            self.root.after(0, self._check_reports_complete)

    def _check_reports_complete(self):
        """Called by each thread when it finishes. Checks if all are done."""
        self.report_threads_completed += 1
        if self.report_threads_completed == self.report_threads_count:
            # All threads are done
            self._on_report_generation_complete()

    def _on_report_generation_complete(self):
        """Finalize the report generation process."""
        self.reports_generating = False
        self.status_text.set("Ready")
        self.view_reports_button.configure(state=tk.NORMAL) # Re-enable button
        self.show_success("All reports have been created successfully!")


    def generate_text_report(self):
        """Generate a text format report."""
        with open(config.text_output, "w", encoding="utf-8") as f:
            f.write("Golden-Scan Security Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Files Scanned: {len(self.results)}\n\n")
            
            # Summary
            malicious = sum(1 for r in self.results if r.verdict == "Malicious")
            suspicious = sum(1 for r in self.results if r.verdict == "Suspicious")
            clean = sum(1 for r in self.results if r.verdict == "Clean")
            unknown = sum(1 for r in self.results if r.verdict == "Unknown")
            
            f.write("SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Malicious: {malicious}\n")
            f.write(f"Suspicious: {suspicious}\n")
            f.write(f"Clean: {clean}\n")
            f.write(f"Unknown: {unknown}\n\n")
            
            # Detailed results
            f.write("DETAILED RESULTS\n")
            f.write("-" * 20 + "\n")
            
            for result in self.results:
                f.write(f"\nFile: {result.file_name}\n")
                f.write(f"Path: {result.file_path}\n")
                f.write(f"Size: {result.file_size} bytes\n")
                f.write(f"SHA256: {result.sha256}\n")
                f.write(f"MD5: {result.md5}\n")
                f.write(f"Verdict: {result.verdict}\n")
                f.write(f"VT Result: {result.vt_result}\n")
                if result.uploaded:
                    f.write("Status: Uploaded to VT\n")
                if result.error:
                    f.write(f"Error: {result.error}\n")
                f.write("-" * 40 + "\n")
                
        if logger:
            logger.info(f"Text report generated: {config.text_output}")

    def generate_html_report(self):
        """Generate an HTML format report with the new template."""
        # Calculate statistics
        malicious = sum(1 for r in self.results if r.verdict == "Malicious")
        suspicious = sum(1 for r in self.results if r.verdict == "Suspicious")
        clean = sum(1 for r in self.results if r.verdict == "Clean")
        unknown = sum(1 for r in self.results if r.verdict == "Unknown")
        
        # Render template
        template = Template(self.get_new_html_template())
        html_content = template.render(
            title="Golden-Scan Security Report",
            logo="""
   ____       _     _                 ____                  
  / ___| ___ | | __| | ___ _ __      / ___|  ___ __ _ _ __  
 | |  _ / _ \| |/ _` |/ _ \ '_ \ ____\___ \ / __/ _` | '_ \ 
 | |_| | (_) | | (_| |  __/ | | |_____|__) | (_| (_| | | | |
  \____|\___/|_|\__,_|\___|_| |_|    |____/ \___\__,_|_| |_| 
  """,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total=len(self.results),
            malicious_count=malicious,
            suspicious_count=suspicious,
            clean_count=clean,
            unknown_count=unknown,
            results=self.results,
            results_json=json.dumps([result.to_dict() for result in self.results]),
            format_bytes=format_bytes
        )
        
        # Write to file
        with open(config.html_output, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        if logger:
            logger.info(f"HTML report generated: {config.html_output}")

    def get_new_html_template(self):
        """Return the new HTML template as a string."""
        return """
<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ title }}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            :root {
                --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d; --bg-overlay: #30363d;
                --border-primary: #30363d; --border-secondary: #21262d; --text-primary: #f0f6fc;
                --text-secondary: #8b949e; --text-tertiary: #6e7681; --accent-primary: #58a6ff;
                --accent-secondary: #1f6feb; --success: #3fb950; --warning: #d29922; --danger: #f85149;
                --danger-subtle: #490202; --warning-subtle: #1f1a00; --success-subtle: #0d2818;
            }
            body { font-family: 'Inter', sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; line-height: 1.6; }
            .container { max-width: 1400px; margin: 0 auto; background: var(--bg-secondary); border: 1px solid var(--border-primary); border-radius: 12px; overflow: hidden; box-shadow: 0 16px 32px rgba(0, 0, 0, 0.85); }
            .header { background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-overlay) 100%); color: var(--text-primary); padding: 40px; text-align: center; border-bottom: 1px solid var(--border-primary); position: relative; overflow: hidden; }
            .header::before { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: radial-gradient(circle at 20% 50%, rgba(88, 166, 255, 0.1) 0%, transparent 50%); pointer-events: none; }
            .logo { font-family: 'JetBrains Mono', monospace; white-space: pre; color: var(--accent-primary); margin-bottom: 20px; font-size: 14px; position: relative; z-index: 1; display: inline-block; text-shadow: 0 0 20px rgba(88, 166, 255, 0.5); }
            .title { font-size: 36px; font-weight: 700; margin-bottom: 10px; position: relative; z-index: 1; background: linear-gradient(135deg, var(--accent-primary) 0%, var(--text-primary) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
            .subtitle { font-size: 18px; color: var(--text-secondary); position: relative; z-index: 1; }
            .summary { padding: 30px; background: var(--bg-tertiary); border-bottom: 1px solid var(--border-primary); }
            .summary h2 { color: var(--text-primary); margin-bottom: 20px; font-size: 20px; font-weight: 600; }
            .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
            .summary-card { background: var(--bg-overlay); padding: 24px; border-radius: 8px; border: 1px solid var(--border-primary); text-align: center; transition: all 0.3s ease; }
            .summary-card:hover { transform: translateY(-2px); border-color: var(--accent-primary); box-shadow: 0 8px 24px rgba(88, 166, 255, 0.1); }
            .summary-count { font-size: 32px; font-weight: 700; margin-bottom: 8px; font-variant-numeric: tabular-nums; }
            .summary-label { font-size: 14px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; }
            .malicious { color: var(--danger); } .suspicious { color: var(--warning); } .clean { color: var(--success); } .unknown { color: var(--text-tertiary); }
            .content { padding: 0; }
            .table-container { background: var(--bg-secondary); overflow: hidden; }
            table { width: 100%; border-collapse: collapse; }
            th { background: var(--bg-tertiary); color: var(--text-primary); padding: 16px; text-align: left; font-weight: 600; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid var(--border-primary); font-family: 'Inter', sans-serif; }
            td { padding: 16px; border-bottom: 1px solid var(--border-secondary); font-size: 14px; color: var(--text-primary); }
            tr:hover { background: var(--bg-tertiary); }
            tr:last-child td { border-bottom: none; }
            .file-path { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
            .hash { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-secondary); }
            .verdict { font-weight: 600; padding: 6px 12px; border-radius: 6px; text-align: center; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-family: 'Inter', sans-serif; }
            .verdict.clean { background: var(--success-subtle); color: var(--success); border: 1px solid rgba(63, 185, 80, 0.3); }
            .verdict.suspicious { background: var(--warning-subtle); color: var(--warning); border: 1px solid rgba(210, 153, 34, 0.3); }
            .verdict.malicious { background: var(--danger-subtle); color: var(--danger); border: 1px solid rgba(248, 81, 73, 0.3); }
            .verdict.unknown { background: var(--bg-overlay); color: var(--text-tertiary); border: 1px solid var(--border-primary); }
            .footer { padding: 30px; text-align: center; background: var(--bg-tertiary); color: var(--text-secondary); font-size: 14px; border-top: 1px solid var(--border-primary); }
            .details-btn { background: var(--accent-primary); color: var(--bg-primary); border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; transition: all 0.3s ease; font-family: 'Inter', sans-serif; }
            .details-btn:hover { background: var(--accent-secondary); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(88, 166, 255, 0.3); }
            .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(13, 17, 23, 0.9); backdrop-filter: blur(8px); }
            .modal-content { background: var(--bg-secondary); margin: 5% auto; padding: 0; width: 90%; max-width: 900px; border-radius: 12px; overflow: hidden; box-shadow: 0 24px 48px rgba(0, 0, 0, 0.9); border: 1px solid var(--border-primary); animation: modalSlideIn 0.3s ease; }
            @keyframes modalSlideIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
            .modal-header { background: var(--bg-tertiary); color: var(--text-primary); padding: 24px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-primary); }
            .modal-title { font-size: 20px; font-weight: 600; }
            .close { color: var(--text-secondary); font-size: 28px; font-weight: 300; cursor: pointer; transition: color 0.3s ease; line-height: 1; }
            .close:hover { color: var(--text-primary); }
            .modal-body { padding: 24px; }
            .tabs { display: flex; border-bottom: 1px solid var(--border-primary); margin-bottom: 24px; }
            .tab { padding: 12px 20px; cursor: pointer; background: none; border: none; font-size: 14px; font-weight: 500; color: var(--text-secondary); transition: all 0.3s ease; position: relative; font-family: 'Inter', sans-serif; }
            .tab:hover { color: var(--text-primary); }
            .tab.active { color: var(--accent-primary); }
            .tab.active::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background: var(--accent-primary); }
            .tab-content { display: none; }
            .tab-content.active { display: block; animation: fadeIn 0.3s ease; }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-bottom: 24px; }
            .info-item { background: var(--bg-tertiary); padding: 16px; border-radius: 8px; border: 1px solid var(--border-primary); }
            .info-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; font-weight: 500; }
            .info-value { font-size: 14px; font-weight: 400; color: var(--text-primary); word-break: break-all; font-family: 'JetBrains Mono', monospace; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 16px; margin-bottom: 24px; }
            .stat-item { background: var(--bg-tertiary); padding: 16px; border-radius: 8px; text-align: center; border: 1px solid var(--border-primary); }
            .stat-value { font-size: 24px; font-weight: 700; margin-bottom: 4px; color: var(--text-primary); font-variant-numeric: tabular-nums; }
            .stat-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; }
            .code-block { background: var(--bg-primary); border: 1px solid var(--border-primary); border-radius: 8px; padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; max-height: 300px; overflow-y: auto; color: var(--text-primary); }
            .section-table { width: 100%; margin-top: 16px; background: var(--bg-tertiary); border-radius: 8px; overflow: hidden; border: 1px solid var(--border-primary); }
            .section-table th { background: var(--bg-overlay); color: var(--text-primary); padding: 12px; font-size: 12px; border-bottom: 1px solid var(--border-primary); }
            .section-table td { padding: 12px; font-size: 12px; border-bottom: 1px solid var(--border-secondary); }
            .no-data { text-align: center; color: var(--text-tertiary); font-style: italic; padding: 24px; }
            h3, h4 { color: var(--text-primary); margin-bottom: 16px; font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header"><div class="logo">{{ logo }}</div><h1 class="title">{{ title }}</h1><p class="subtitle">Generated on {{ timestamp }}</p></div>
            <div class="summary"><h2>Scan Summary</h2><div class="summary-grid">
                <div class="summary-card"><div class="summary-count">{{ total }}</div><div class="summary-label">Total Files</div></div>
                <div class="summary-card"><div class="summary-count malicious">{{ malicious_count }}</div><div class="summary-label">Malicious</div></div>
                <div class="summary-card"><div class="summary-count suspicious">{{ suspicious_count }}</div><div class="summary-label">Suspicious</div></div>
                <div class="summary-card"><div class="summary-count clean">{{ clean_count }}</div><div class="summary-label">Clean</div></div>
                <div class="summary-card"><div class="summary-count unknown">{{ unknown_count }}</div><div class="summary-label">Unknown</div></div>
            </div></div>
            <div class="content"><div class="table-container"><table>
                <thead><tr><th>File Name</th><th>Path</th><th>SHA256</th><th>Size</th><th>VT Detection</th><th>Verdict</th><th>Details</th></tr></thead>
                <tbody>{% for result in results %}<tr>
                    <td><strong>{{ result.file_name }}</strong></td><td class="file-path" title="{{ result.file_path }}">{{ result.file_path }}</td>
                    <td class="hash">{{ result.sha256[:16] }}...</td><td>{{ format_bytes(result.file_size) }}</td><td>{{ result.vt_result }}</td>
                    <td><div class="verdict {{ result.verdict.lower() }}">{{ result.verdict }}</div></td>
                    <td><button class="details-btn" onclick="showDetails({{ loop.index0 }})">View</button></td>
                </tr>{% endfor %}</tbody>
            </table></div></div>
            <div class="footer"><p>Report generated by Professional VirusTotal Scanner</p><p style="margin-top: 8px; font-size: 12px; color: var(--text-tertiary);">© 2025 Security Analysis Tools By : Mohamed A Jaber https://www.facebook.com/Mrm0hm3d</p></div>
        </div>
        <div id="detailsModal" class="modal"><div class="modal-content"><div class="modal-header"><h2 class="modal-title">File Details</h2><span class="close">&times;</span></div><div class="modal-body">
                <div class="tabs"><button class="tab active" onclick="openTab(event, 'general')">General</button><button class="tab" onclick="openTab(event, 'vt')">VirusTotal</button><button class="tab" onclick="openTab(event, 'pe')">PE Analysis</button></div>
                <div id="general" class="tab-content active"><div class="info-grid">
                    <div class="info-item"><div class="info-label">File Name</div><div class="info-value" id="detail-filename"></div></div>
                    <div class="info-item"><div class="info-label">File Path</div><div class="info-value" id="detail-path"></div></div>
                    <div class="info-item"><div class="info-label">File Size</div><div class="info-value" id="detail-size"></div></div>
                    <div class="info-item"><div class="info-label">SHA256</div><div class="info-value" id="detail-sha256"></div></div>
                    <div class="info-item"><div class="info-label">MD5</div><div class="info-value" id="detail-md5"></div></div>
                    <div class="info-item"><div class="info-label">Scan Time</div><div class="info-value" id="detail-time"></div></div>
                    <div class="info-item"><div class="info-label">Verdict</div><div class="info-value" id="detail-verdict"></div></div>
                    <div class="info-item"><div class="info-label">Status</div><div class="info-value" id="detail-status"></div></div>
                </div></div>
                <div id="vt" class="tab-content"><h3>VirusTotal Analysis</h3><div id="vt-content"></div></div>
                <div id="pe" class="tab-content"><h3>PE Analysis</h3><div id="pe-content"></div></div>
            </div></div></div>
        <script>const resultsData = {{ results_json }}; const modal = document.getElementById("detailsModal"); const span = document.getElementsByClassName("close")[0];
        span.onclick = function() { modal.style.display = "none"; }
        window.onclick = function(event) { if (event.target == modal) { modal.style.display = "none"; } }
        function showDetails(index) { const result = resultsData[index];
            document.getElementById("detail-filename").textContent = result.file_name; document.getElementById("detail-path").textContent = result.file_path;
            document.getElementById("detail-size").textContent = formatBytes(result.file_size); document.getElementById("detail-sha256").textContent = result.sha256;
            document.getElementById("detail-md5").textContent = result.md5; document.getElementById("detail-time").textContent = result.scan_time;
            const verdictEl = document.getElementById("detail-verdict"); verdictEl.textContent = result.verdict; verdictEl.className = `info-value verdict-${result.verdict.toLowerCase()}`;
            document.getElementById("detail-status").textContent = result.uploaded ? "Uploaded to VT" : "Found in VT";
            let vtContent = `<div class="info-item" style="margin-bottom: 20px;"><div class="info-label">VT Result</div><div class="info-value">${result.vt_result}</div></div>`;
            if (result.vt_stats && Object.keys(result.vt_stats).length > 0) { vtContent += '<div class="stats-grid">';
                for (const [key, value] of Object.entries(result.vt_stats)) { vtContent += `<div class="stat-item"><div class="stat-value">${value}</div><div class="stat-label">${key}</div></div>`; }
                vtContent += '</div>'; } document.getElementById("vt-content").innerHTML = vtContent;
            let peContent = ''; if (result.pe_info) {
                if (result.pe_info.has_signature !== null) { peContent += `<div class="info-item" style="margin-bottom: 20px;"><div class="info-label">Digital Signature</div><div class="info-value">${result.pe_info.has_signature ? '✓ Present' : '✗ Not Present'}</div></div>`; }
                if (result.pe_info.imports && result.pe_info.imports.length > 0) { peContent += '<h4>Imports</h4><div class="section-table"><table><thead><tr><th>DLL</th><th>Functions</th></tr></thead><tbody>';
                    result.pe_info.imports.forEach(imp => { peContent += `<tr><td><strong>${imp.dll}</strong></td><td>${imp.functions.join(', ')}</td></tr>`; });
                    peContent += '</tbody></table></div>'; }
                if (result.pe_info.sections && result.pe_info.sections.length > 0) { peContent += '<h4 style="margin-top: 20px;">Sections</h4><div class="section-table"><table><thead><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr></thead><tbody>';
                    result.pe_info.sections.forEach(sec => { peContent += `<tr><td>${sec.name}</td><td>${sec.virtual_size}</td><td>${sec.raw_size}</td><td>${sec.entropy ? sec.entropy.toFixed(2) : 'N/A'}</td></tr>`; });
                    peContent += '</tbody></table></div>'; }
                if (result.pe_info.strings && result.pe_info.strings.length > 0) { peContent += '<h4 style="margin-top: 20px;">Strings</h4><div class="code-block">';
                    result.pe_info.strings.forEach(str => { peContent += `${str}\n`; }); peContent += '</div>'; }
                if (result.pe_info.error) { peContent += `<div class="info-item" style="margin-top: 20px;"><div class="info-label">Error</div><div class="info-value" style="color: var(--danger);">${result.pe_info.error}</div></div>`; }
            } else { peContent = '<div class="no-data">No PE analysis available</div>'; } document.getElementById("pe-content").innerHTML = peContent; modal.style.display = "block"; }
        function openTab(evt, tabName) { const tabContents = document.getElementsByClassName("tab-content"); for (let i = 0; i < tabContents.length; i++) { tabContents[i].classList.remove("active"); }
            const tabs = document.getElementsByClassName("tab"); for (let i = 0; i < tabs.length; i++) { tabs[i].classList.remove("active"); }
            document.getElementById(tabName).classList.add("active"); evt.currentTarget.classList.add("active"); }
        function formatBytes(bytes, decimals = 2) { if (bytes === 0) return '0 Bytes'; const k = 1024; const dm = decimals < 0 ? 0 : decimals; const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]; }
        </script>
    </body>
    </html>
        """

    def generate_json_report(self):
        """Generate a JSON format report."""
        malicious = sum(1 for r in self.results if r.verdict == "Malicious")
        suspicious = sum(1 for r in self.results if r.verdict == "Suspicious")
        clean = sum(1 for r in self.results if r.verdict == "Clean")
        unknown = sum(1 for r in self.results if r.verdict == "Unknown")
        
        report_data = {
            "report_info": { "tool": "Golden-Scan", "version": "5.0 Premium Edition", "timestamp": datetime.now().isoformat(), "total_files": len(self.results) },
            "summary": { "malicious": malicious, "suspicious": suspicious, "clean": clean, "unknown": unknown },
            "results": [result.to_dict() for result in self.results]
        }
        
        with open(config.json_output, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        if logger:
            logger.info(f"JSON report generated: {config.json_output}")

    def generate_csv_report(self):
        """Generate a CSV format report."""
        with open(config.csv_output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["File Name", "Path", "Size", "SHA256", "MD5", "VT Result", "Verdict", "Scan Time", "Uploaded", "Error"])
            for result in self.results:
                writer.writerow([result.file_name, result.file_path, result.file_size, result.sha256, result.md5, result.vt_result, result.verdict, result.scan_time, "Yes" if result.uploaded else "No", result.error or ""])
                
        if logger:
            logger.info(f"CSV report generated: {config.csv_output}")

    def generate_threats_text_report(self):
        """Generate a text format threats report."""
        threats = [r for r in self.results if r.is_threat]
        
        with open(config.threats_text, "w", encoding="utf-8") as f:
            f.write("Golden-Scan Security Threats Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Threats Found: {len(threats)}\n\n")
            
            malicious = sum(1 for r in threats if r.verdict == "Malicious")
            suspicious = sum(1 for r in threats if r.verdict == "Suspicious")
            
            f.write("THREATS SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Malicious: {malicious}\n")
            f.write(f"Suspicious: {suspicious}\n\n")
            
            f.write("DETAILED THREATS\n")
            f.write("-" * 20 + "\n")
            
            for result in threats:
                f.write(f"\nFile: {result.file_name}\n")
                f.write(f"Path: {result.file_path}\n")
                f.write(f"Size: {result.file_size} bytes\n")
                f.write(f"SHA256: {result.sha256}\n")
                f.write(f"MD5: {result.md5}\n")
                f.write(f"Verdict: {result.verdict}\n")
                f.write(f"VT Result: {result.vt_result}\n")
                if result.uploaded: f.write("Status: Uploaded to VT\n")
                if result.error: f.write(f"Error: {result.error}\n")
                f.write("-" * 40 + "\n")
                
        if logger:
            logger.info(f"Threats text report generated: {config.threats_text}")

    def generate_threats_html_report(self):
        """Generate an HTML format threats report."""
        threats = [r for r in self.results if r.is_threat]
        malicious = sum(1 for r in threats if r.verdict == "Malicious")
        suspicious = sum(1 for r in threats if r.verdict == "Suspicious")
        
        template = Template(self.get_threats_html_template())
        html_content = template.render(
            title="Golden-Scan Security Threats Report",
            logo="██████╗ ██╗████████╗ ██████╗ ██████╗ ██╗███╗   ██╗\n██╔══██╗██║╚══██╔══╝██╔════╝██╔═══██╗██║████╗  ██║\n██████╔╝██║   ██║   ██║     ██║   ██║██║██╔██╗ ██║\n██╔══██╗██║   ██║   ██║     ██║   ██║██║██║╚██╗██║\n██║  ██║██║   ██║   ╚██████╗╚██████╔╝██║██║ ╚████║\n╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝",
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_threats=len(threats), malicious_count=malicious, suspicious_count=suspicious,
            results=threats, results_json=json.dumps([result.to_dict() for result in threats]), format_bytes=format_bytes
        )
        
        with open(config.threats_html, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        if logger:
            logger.info(f"Threats HTML report generated: {config.threats_html}")

    def get_threats_html_template(self):
        """Return the threats HTML template as a string."""
        return """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{{ title }}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"><style>*{margin:0;padding:0;box-sizing:border-box;}:root{--bg-primary:#0d1117;--bg-secondary:#161b22;--bg-tertiary:#21262d;--bg-overlay:#30363d;--border-primary:#30363d;--border-secondary:#21262d;--text-primary:#f0f6fc;--text-secondary:#8b949e;--text-tertiary:#6e7681;--accent-primary:#58a6ff;--accent-secondary:#1f6feb;--success:#3fb950;--warning:#d29922;--danger:#f85149;--danger-subtle:#490202;--warning-subtle:#1f1a00;--success-subtle:#0d2818;}body{font-family:'Inter',sans-serif;background:var(--bg-primary);color:var(--text-primary);min-height:100vh;line-height:1.6;}.container{max-width:1400px;margin:0 auto;background:var(--bg-secondary);border:1px solid var(--border-primary);border-radius:12px;overflow:hidden;box-shadow:0 16px 32px rgba(0,0,0,0.85);}.header{background:linear-gradient(135deg,var(--bg-tertiary)0,var(--bg-overlay)100%);color:var(--text-primary);padding:40px;text-align:center;border-bottom:1px solid var(--border-primary);position:relative;overflow:hidden;}.header::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:radial-gradient(circle at 20% 50%,rgba(248,81,73,0.1)0,transparent 50%);pointer-events:none;}.logo{font-family:'JetBrains Mono',monospace;white-space:pre;color:var(--danger);margin-bottom:20px;font-size:14px;position:relative;z-index:1;display:inline-block;text-shadow:0 0 20px rgba(248,81,73,0.5);}.title{font-size:36px;font-weight:700;margin-bottom:10px;position:relative;z-index:1;background:linear-gradient(135deg,var(--danger)0,var(--text-primary)100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}.subtitle{font-size:18px;color:var(--text-secondary);position:relative;z-index:1;}.summary{padding:30px;background:var(--bg-tertiary);border-bottom:1px solid var(--border-primary);}.summary h2{color:var(--text-primary);margin-bottom:20px;font-size:20px;font-weight:600;}.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;}.summary-card{background:var(--bg-overlay);padding:24px;border-radius:8px;border:1px solid var(--border-primary);text-align:center;transition:all .3s ease;}.summary-card:hover{transform:translateY(-2px);border-color:var(--danger);box-shadow:0 8px 24px rgba(248,81,73,0.1);}.summary-count{font-size:32px;font-weight:700;margin-bottom:8px;font-variant-numeric:tabular-nums;}.summary-label{font-size:14px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;font-weight:500;}.malicious{color:var(--danger);}.suspicious{color:var(--warning);}.content{padding:0;}.table-container{background:var(--bg-secondary);overflow:hidden;}table{width:100%;border-collapse:collapse;}th{background:var(--bg-tertiary);color:var(--text-primary);padding:16px;text-align:left;font-weight:600;font-size:14px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--border-primary);font-family:'Inter',sans-serif;}td{padding:16px;border-bottom:1px solid var(--border-secondary);font-size:14px;color:var(--text-primary);}tr:hover{background:var(--bg-tertiary);}tr:last-child td{border-bottom:none;}.file-path{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace;font-size:12px;}.hash{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-secondary);}.verdict{font-weight:600;padding:6px 12px;border-radius:6px;text-align:center;font-size:12px;text-transform:uppercase;letter-spacing:.5px;font-family:'Inter',sans-serif;}.verdict.suspicious{background:var(--warning-subtle);color:var(--warning);border:1px solid rgba(210,153,34,.3);}.verdict.malicious{background:var(--danger-subtle);color:var(--danger);border:1px solid rgba(248,81,73,.3);}.footer{padding:30px;text-align:center;background:var(--bg-tertiary);color:var(--text-secondary);font-size:14px;border-top:1px solid var(--border-primary);}.details-btn{background:var(--accent-primary);color:var(--bg-primary);border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:600;transition:all .3s ease;font-family:'Inter',sans-serif;}.details-btn:hover{background:var(--accent-secondary);transform:translateY(-1px);box-shadow:0 4px 12px rgba(88,166,255,.3);}.modal{display:none;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(13,17,23,.9);backdrop-filter:blur(8px);}.modal-content{background:var(--bg-secondary);margin:5% auto;padding:0;width:90%;max-width:900px;border-radius:12px;overflow:hidden;box-shadow:0 24px 48px rgba(0,0,0,.9);border:1px solid var(--border-primary);animation:modalSlideIn .3s ease;}@keyframes modalSlideIn{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}.modal-header{background:var(--bg-tertiary);color:var(--text-primary);padding:24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border-primary);}.modal-title{font-size:20px;font-weight:600;}.close{color:var(--text-secondary);font-size:28px;font-weight:300;cursor:pointer;transition:color .3s ease;line-height:1;}.close:hover{color:var(--text-primary);}.modal-body{padding:24px;}.tabs{display:flex;border-bottom:1px solid var(--border-primary);margin-bottom:24px;}.tab{padding:12px 20px;cursor:pointer;background:none;border:none;font-size:14px;font-weight:500;color:var(--text-secondary);transition:all .3s ease;position:relative;font-family:'Inter',sans-serif;}.tab:hover{color:var(--text-primary);}.tab.active{color:var(--accent-primary);}.tab.active::after{content:'';position:absolute;bottom:-1px;left:0;width:100%;height:2px;background:var(--accent-primary);}.tab-content{display:none;}.tab-content.active{display:block;animation:fadeIn .3s ease;}@keyframes fadeIn{from{opacity:0}to{opacity:1}}.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin-bottom:24px;}.info-item{background:var(--bg-tertiary);padding:16px;border-radius:8px;border:1px solid var(--border-primary);}.info-label{font-size:12px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:500;}.info-value{font-size:14px;font-weight:400;color:var(--text-primary);word-break:break-all;font-family:'JetBrains Mono',monospace;}.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:16px;margin-bottom:24px;}.stat-item{background:var(--bg-tertiary);padding:16px;border-radius:8px;text-align:center;border:1px solid var(--border-primary);}.stat-value{font-size:24px;font-weight:700;margin-bottom:4px;color:var(--text-primary);font-variant-numeric:tabular-nums;}.stat-label{font-size:12px;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.5px;font-weight:500;}.code-block{background:var(--bg-primary);border:1px solid var(--border-primary);border-radius:8px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap;max-height:300px;overflow-y:auto;color:var(--text-primary);}.section-table{width:100%;margin-top:16px;background:var(--bg-tertiary);border-radius:8px;overflow:hidden;border:1px solid var(--border-primary);}.section-table th{background:var(--bg-overlay);color:var(--text-primary);padding:12px;font-size:12px;border-bottom:1px solid var(--border-primary);}.section-table td{padding:12px;font-size:12px;border-bottom:1px solid var(--border-secondary);}.no-data{text-align:center;color:var(--text-tertiary);font-style:italic;padding:24px;}h3,h4{color:var(--text-primary);margin-bottom:16px;font-weight:600;}</style></head><body><div class="container"><div class="header"><div class="logo">{{ logo }}</div><h1 class="title">{{ title }}</h1><p class="subtitle">Generated on {{ timestamp }}</p></div><div class="summary"><h2>Threats Summary</h2><div class="summary-grid"><div class="summary-card"><div class="summary-count">{{ total_threats }}</div><div class="summary-label">Total Threats</div></div><div class="summary-card"><div class="summary-count malicious">{{ malicious_count }}</div><div class="summary-label">Malicious</div></div><div class="summary-card"><div class="summary-count suspicious">{{ suspicious_count }}</div><div class="summary-label">Suspicious</div></div></div></div><div class="content"><div class="table-container"><table><thead><tr><th>File Name</th><th>Path</th><th>SHA256</th><th>Size</th><th>VT Detection</th><th>Verdict</th><th>Details</th></tr></thead><tbody>{% for result in results %}<tr><td><strong>{{ result.file_name }}</strong></td><td class="file-path" title="{{ result.file_path }}">{{ result.file_path }}</td><td class="hash">{{ result.sha256[:16] }}...</td><td>{{ format_bytes(result.file_size) }}</td><td>{{ result.vt_result }}</td><td><div class="verdict {{ result.verdict.lower() }}">{{ result.verdict }}</div></td><td><button class="details-btn" onclick="showDetails({{ loop.index0 }})">View</button></td></tr>{% endfor %}</tbody></table></div></div><div class="footer"><p>Threats report generated by Professional VirusTotal Scanner</p><p style="margin-top:8px;font-size:12px;color:var(--text-tertiary);">© 2024 Security Analysis Tools</p></div></div><div id="detailsModal" class="modal"><div class="modal-content"><div class="modal-header"><h2 class="modal-title">File Details</h2><span class="close">&times;</span></div><div class="modal-body"><div class="tabs"><button class="tab active" onclick="openTab(event,'general')">General</button><button class="tab" onclick="openTab(event,'vt')">VirusTotal</button><button class="tab" onclick="openTab(event,'pe')">PE Analysis</button></div><div id="general" class="tab-content active"><div class="info-grid"><div class="info-item"><div class="info-label">File Name</div><div class="info-value" id="detail-filename"></div></div><div class="info-item"><div class="info-label">File Path</div><div class="info-value" id="detail-path"></div></div><div class="info-item"><div class="info-label">File Size</div><div class="info-value" id="detail-size"></div></div><div class="info-item"><div class="info-label">SHA256</div><div class="info-value" id="detail-sha256"></div></div><div class="info-item"><div class="info-label">MD5</div><div class="info-value" id="detail-md5"></div></div><div class="info-item"><div class="info-label">Scan Time</div><div class="info-value" id="detail-time"></div></div><div class="info-item"><div class="info-label">Verdict</div><div class="info-value" id="detail-verdict"></div></div><div class="info-item"><div class="info-label">Status</div><div class="info-value" id="detail-status"></div></div></div></div><div id="vt" class="tab-content"><h3>VirusTotal Analysis</h3><div id="vt-content"></div></div><div id="pe" class="tab-content"><h3>PE Analysis</h3><div id="pe-content"></div></div></div></div></div></div><script>const resultsData={{ results_json }};const modal=document.getElementById("detailsModal");const span=document.getElementsByClassName("close")[0];span.onclick=function(){modal.style.display="none"};window.onclick=function(event){if(event.target==modal){modal.style.display="none"}};function showDetails(index){const result=resultsData[index];document.getElementById("detail-filename").textContent=result.file_name;document.getElementById("detail-path").textContent=result.file_path;document.getElementById("detail-size").textContent=formatBytes(result.file_size);document.getElementById("detail-sha256").textContent=result.sha256;document.getElementById("detail-md5").textContent=result.md5;document.getElementById("detail-time").textContent=result.scan_time;const verdictEl=document.getElementById("detail-verdict");verdictEl.textContent=result.verdict;verdictEl.className=`info-value verdict-${result.verdict.toLowerCase()}`;document.getElementById("detail-status").textContent=result.uploaded?"Uploaded to VT":"Found in VT";let vtContent=`<div class="info-item" style="margin-bottom:20px;"><div class="info-label">VT Result</div><div class="info-value">${result.vt_result}</div></div>`;if(result.vt_stats&&Object.keys(result.vt_stats).length>0){vtContent+='<div class="stats-grid">';for(const[key,value]of Object.entries(result.vt_stats)){vtContent+=`<div class="stat-item"><div class="stat-value">${value}</div><div class="stat-label">${key}</div></div>`}vtContent+='</div>'}document.getElementById("vt-content").innerHTML=vtContent;let peContent='';if(result.pe_info){if(result.pe_info.has_signature!==null){peContent+=`<div class="info-item" style="margin-bottom:20px;"><div class="info-label">Digital Signature</div><div class="info-value">${result.pe_info.has_signature?'✓ Present':'✗ Not Present'}</div></div>`}if(result.pe_info.imports&&result.pe_info.imports.length>0){peContent+='<h4>Imports</h4><div class="section-table"><table><thead><tr><th>DLL</th><th>Functions</th></tr></thead><tbody>';result.pe_info.imports.forEach(imp=>{peContent+=`<tr><td><strong>${imp.dll}</strong></td><td>${imp.functions.join(', ')}</td></tr>`});peContent+='</tbody></table></div>'}if(result.pe_info.sections&&result.pe_info.sections.length>0){peContent+='<h4 style="margin-top:20px;">Sections</h4><div class="section-table"><table><thead><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr></thead><tbody>';result.pe_info.sections.forEach(sec=>{peContent+=`<tr><td>${sec.name}</td><td>${sec.virtual_size}</td><td>${sec.raw_size}</td><td>${sec.entropy?sec.entropy.toFixed(2):'N/A'}</td></tr>`});peContent+='</tbody></table></div>'}if(result.pe_info.strings&&result.pe_info.strings.length>0){peContent+='<h4 style="margin-top:20px;">Strings</h4><div class="code-block">';result.pe_info.strings.forEach(str=>{peContent+=`${str}\n`});peContent+='</div>'}if(result.pe_info.error){peContent+=`<div class="info-item" style="margin-top:20px;"><div class="info-label">Error</div><div class="info-value" style="color:var(--danger);">${result.pe_info.error}</div></div>`}}else{peContent='<div class="no-data">No PE analysis available</div>'}document.getElementById("pe-content").innerHTML=peContent;modal.style.display="block"}function openTab(evt,tabName){const tabContents=document.getElementsByClassName("tab-content");for(let i=0;i<tabContents.length;i++){tabContents[i].classList.remove("active")}const tabs=document.getElementsByClassName("tab");for(let i=0;i<tabs.length;i++){tabs[i].classList.remove("active")}document.getElementById(tabName).classList.add("active");evt.currentTarget.classList.add("active")}function formatBytes(bytes,decimals=2){if(bytes===0)return'0 Bytes';const k=1024;const dm=decimals<0?0:decimals;const sizes=['Bytes','KB','MB','GB','TB'];const i=Math.floor(Math.log(bytes)/Math.log(k));return parseFloat((bytes/Math.pow(k,i)).toFixed(dm))+' '+sizes[i]}</script></body></html>
        """

    def generate_threats_json_report(self):
        """Generate a JSON format threats report."""
        threats = [r for r in self.results if r.is_threat]
        malicious = sum(1 for r in threats if r.verdict == "Malicious")
        suspicious = sum(1 for r in threats if r.verdict == "Suspicious")
        
        report_data = {
            "report_info": { "tool": "Golden-Scan", "version": "5.0 Premium Edition", "report_type": "Threats", "timestamp": datetime.now().isoformat(), "total_threats": len(threats) },
            "summary": { "malicious": malicious, "suspicious": suspicious },
            "threats": [result.to_dict() for result in threats]
        }
        
        with open(config.threats_json, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        if logger:
            logger.info(f"Threats JSON report generated: {config.threats_json}")


class GUILogHandler(logging.Handler):
    """Custom log handler that writes to a GUI text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    
    def emit(self, record):
        """Emit a log record to the text widget."""
        try:
            msg = self.format(record)
            
            # Append to text widget
            self.text_widget.config(state=tk.NORMAL)
            self.text_widget.insert(tk.END, msg + "\n", record.levelname)
            self.text_widget.config(state=tk.DISABLED)
            
            # Auto-scroll to bottom
            self.text_widget.see(tk.END)
        except Exception:
            self.handleError(record)

# ======================= MAIN FUNCTION =======================
def main():
    """Main function to run the GUI."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Golden-Scan - Professional Security Scanner")
    parser.add_argument("--api-key", help="VirusTotal API key")
    args = parser.parse_args()
    
    # Update configuration with command line arguments
    if args.api_key:
        config.api_key = args.api_key
    
    # Setup logging after config is initialized
        # Setup logging after config is initialized
    setup_logging()
    
    # Create and run GUI
    root = tk.Tk()
    app = VirusTotalScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
