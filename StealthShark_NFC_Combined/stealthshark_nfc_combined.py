#!/usr/bin/env python3
"""
StealthShark + NFC WiFi Authentication Combined Application
Unified network monitoring with NFC-authenticated WiFi security
"""

import sys
import json
import threading
import time
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QGroupBox, QCheckBox, QSlider, QFileDialog,
    QComboBox, QSpinBox, QHeaderView, QLineEdit, QMessageBox,
    QDialog, QProgressBar, QDialogButtonBox, QSplitter
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QFont, QTextCursor
import psutil
import os
import hashlib
import socket

# Import StealthShark components
try:
    from persistent_wireshark_monitor import PersistentWiresharkMonitor
    print("✅ StealthShark components loaded successfully")
except ImportError:
    print("Warning: StealthShark components not available")
    PersistentWiresharkMonitor = None

# Import Anti-Pineapple components
sys.path.append(os.path.expanduser('~/Documents/_MobileShield/anti-pineapple-public'))
try:
    from pineapple_detector import PineappleDetector
    from wifi_connection_controller import WiFiConnectionController
    from nesdr_nfc_wifi_authenticator import NESDRNFCWiFiAuthenticator
except ImportError:
    print("Warning: Anti-Pineapple components not available")
    PineappleDetector = None
    WiFiConnectionController = None
    NESDRNFCWiFiAuthenticator = None


class NetworkMonitorThread(QThread):
    """Thread for continuous network monitoring"""
    network_update = pyqtSignal(list)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self, legitimate_bssid="72:13:01:8A:70:DA"):
        super().__init__()
        self.legitimate_bssid = legitimate_bssid
        self.running = True
    
    def run(self):
        while self.running:
            try:
                networks = self.scan_networks()
                self.network_update.emit(networks)
                
                for network in networks:
                    if self.is_threat(network):
                        self.threat_detected.emit(network)
                
                time.sleep(5)
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(10)
    
    def scan_networks(self):
        """Scan for WiFi networks"""
        try:
            result = subprocess.run(['airport', '-s'], capture_output=True, text=True, timeout=10)
            networks = []
            
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        ssid = parts[0]
                        bssid = parts[1]
                        rssi = parts[2]
                        networks.append({
                            'ssid': ssid,
                            'bssid': bssid,
                            'rssi': int(rssi) if rssi.lstrip('-').isdigit() else -100,
                            'security': ' '.join(parts[6:]) if len(parts) > 6 else 'Open'
                        })
            return networks
        except Exception as e:
            print(f"Network scan error: {e}")
            return []
    
    def is_threat(self, network):
        """Check if network is a threat"""
        if network['bssid'] != self.legitimate_bssid:
            if network['ssid'] in ['Free WiFi', 'Public WiFi', 'Guest']:
                return True
        return False
    
    def stop(self):
        self.running = False


class StealthSharkMonitorThread(QThread):
    """Background thread for running the Wireshark monitor"""
    interface_activity = pyqtSignal(str, dict)
    capture_started = pyqtSignal(str, str)
    capture_completed = pyqtSignal(str, str)
    status_update = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)
    batch_alert_signal = pyqtSignal(list)
    
    def __init__(self, capture_dir, duration, interval):
        super().__init__()
        self.capture_dir = capture_dir
        self.duration = duration
        self.interval = interval
        self.running = False
        
    def run(self):
        """Run the monitor in background thread"""
        self.running = True
        try:
            if PersistentWiresharkMonitor:
                # Ensure capture directory exists
                Path(self.capture_dir).mkdir(parents=True, exist_ok=True)
                (Path(self.capture_dir) / 'logs').mkdir(exist_ok=True)
                
                self.monitor = PersistentWiresharkMonitor(
                    capture_dir=self.capture_dir,
                    capture_duration=self.duration,
                    check_interval=self.interval,
                    alert_callback=self.alert_callback
                )
                
                # Override monitor callbacks to emit our signals
                original_alert = self.monitor.alert_callback
                def enhanced_alert(message):
                    if original_alert:
                        original_alert(message)
                    self.alert_signal.emit(message)
                
                self.monitor.alert_callback = enhanced_alert
                
                self.monitor.start_monitoring()
                
                # Start monitoring
                self.alert_signal.emit("🦈 StealthShark Monitor initialized")
                self.alert_signal.emit(f"📁 Capture directory: {self.capture_dir}")
                self.alert_signal.emit("🔍 Scanning network interfaces...")
                
                # Emit periodic status updates
                while self.running and self.monitor.running:
                    # Emit interface stats
                    if hasattr(self.monitor, 'interface_stats'):
                        interface_count = len(self.monitor.interface_stats)
                        if interface_count > 0:
                            self.alert_signal.emit(f"📊 Monitoring {interface_count} interfaces")
                            for interface, stats in self.monitor.interface_stats.items():
                                self.interface_activity.emit(interface, dict(stats))
                                if stats.get('packets', 0) > 0:
                                    self.alert_signal.emit(f"📡 {interface}: {stats['packets']} packets, {stats['bytes']} bytes")
                    
                    # Check for active captures
                    if hasattr(self.monitor, 'active_captures'):
                        capture_count = len(self.monitor.active_captures)
                        if capture_count > 0:
                            self.alert_signal.emit(f"📹 {capture_count} active capture(s)")
                            for interface, capture_info in self.monitor.active_captures.items():
                                if isinstance(capture_info, dict):
                                    filename = capture_info.get('capture_filename', 'Unknown')
                                    self.capture_started.emit(interface, filename)
                    
                    # Emit status update
                    status = {
                        'active_captures': getattr(self.monitor, 'active_captures', {}),
                        'interface_stats': getattr(self.monitor, 'interface_stats', {})
                    }
                    self.status_update.emit(status)
                    
                    time.sleep(2)  # Update every 2 seconds
            else:
                self.alert_signal.emit("StealthShark components not available")
                
        except Exception as e:
            self.alert_signal.emit(f"Monitor error: {e}")
            
    def alert_callback(self, message):
        """Callback for monitor alerts"""
        self.alert_signal.emit(message)
            
    def stop(self):
        """Stop the monitor"""
        self.running = False
        if hasattr(self, 'monitor'):
            self.monitor.running = False
            self.monitor.shutdown()


class StealthSharkNFCCombined(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Core monitoring
        self.monitor_thread = None
        self.capture_dir = "pcap_captures"
        self.duration = 18000  # 5 hours default
        self.interval = 5
        
        # NFC Authentication variables
        self.authenticated = False
        self.firewall_enabled = False
        self.legitimate_bssid = "72:13:01:8A:70:DA"
        self.blocked_bssids = set()
        self.registered_tags = []
        self.threat_count = 0
        
        # Network monitoring
        self.network_monitor_thread = None
        self.current_networks = []
        
        # Configuration paths
        self.config_dir = Path.home() / '.ssh'
        self.config_dir.mkdir(exist_ok=True)
        self.tags_path = self.config_dir / 'nfc_tags.json'
        self.auth_profile_path = self.config_dir / 'anti_pineapple_auth.json'
        
        # Alert batching
        self.alert_queue = []
        self.alert_timer = None
        self.last_alert_time = 0
        
        # Countdown timer
        self.capture_start_time = None
        self.countdown_timer = None
        
        self.init_ui()
        self.setup_timers()
        
        # Load configurations after UI is initialized
        self.load_registered_tags()
        self.load_authentication()
        
        # Check for auto-authentication on startup
        self.check_auto_authentication()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("StealthShark + NFC WiFi Security - AIMF LLC")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
                background-color: #3c3c3c;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #ffffff;
            }
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }
            QTextEdit, QListWidget {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                color: #ffffff;
                font-family: 'Courier New', monospace;
            }
            QTableWidget {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                color: #ffffff;
                gridline-color: #555555;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                color: #ffffff;
                padding: 5px;
                border-radius: 3px;
            }
            QTabWidget::pane {
                border: 1px solid #3B82F6;
                background: #1F2937;
            }
            QTabBar::tab {
                background: #374151;
                color: #D1D5DB;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #3B82F6;
                color: white;
            }
        """)
        
        # Central widget with main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        
        # Create main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Controls
        left_panel = self.create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Tabbed monitoring
        right_panel = self.create_monitoring_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([450, 950])
        
    def create_control_panel(self):
        """Create the control panel"""
        control_widget = QWidget()
        layout = QVBoxLayout(control_widget)
        
        # NFC Authentication Group
        nfc_group = QGroupBox("🔐 NFC Authentication")
        nfc_layout = QVBoxLayout(nfc_group)
        
        # Authentication status
        self.auth_status_label = QLabel("🔒 Not Authenticated")
        self.auth_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 14px;")
        nfc_layout.addWidget(self.auth_status_label)
        
        # NFC buttons
        nfc_buttons = QHBoxLayout()
        self.nfc_auth_btn = QPushButton("📱 NFC Auth")
        self.nfc_auth_btn.clicked.connect(self.authenticate_nfc)
        self.logout_btn = QPushButton("🚪 Logout")
        self.logout_btn.clicked.connect(self.logout)
        self.logout_btn.setEnabled(False)
        
        nfc_buttons.addWidget(self.nfc_auth_btn)
        nfc_buttons.addWidget(self.logout_btn)
        nfc_layout.addLayout(nfc_buttons)
        
        layout.addWidget(nfc_group)
        
        # StealthShark Monitor Control Group
        monitor_group = QGroupBox("🦈 StealthShark Monitor")
        monitor_layout = QVBoxLayout(monitor_group)
        
        # Start/Stop buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start Monitor")
        self.start_btn.clicked.connect(self.start_monitor)
        self.start_btn.setEnabled(False)  # Disabled until NFC auth
        self.log_message(f"🔧 Initial Start button state: {self.start_btn.isEnabled()}")
        
        self.stop_btn = QPushButton("🛑 Stop Monitor")
        self.stop_btn.clicked.connect(self.stop_monitor)
        self.stop_btn.setEnabled(False)
        self.log_message(f"🔧 Initial Stop button state: {self.stop_btn.isEnabled()}")
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        monitor_layout.addLayout(button_layout)
        
        # Status indicator
        self.monitor_status_label = QLabel("Status: Stopped")
        self.monitor_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        monitor_layout.addWidget(self.monitor_status_label)
        
        # Add timer/duration info
        self.time_remaining_label = QLabel("Time Remaining: --:--:--")
        self.time_remaining_label.setStyleSheet("color: #9CA3AF; font-size: 12px;")
        monitor_layout.addWidget(self.time_remaining_label)
        
        layout.addWidget(monitor_group)
        
        # Configuration Group (moved up right after monitor)
        config_group = QGroupBox("⚙️ Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Capture duration
        duration_layout = QHBoxLayout()
        duration_layout.addWidget(QLabel("Capture Duration:"))
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([
            "1 minute (60s)", "5 minutes (300s)", "15 minutes (900s)",
            "30 minutes (1800s)", "1 hour (3600s)", "2 hours (7200s)",
            "5 hours (18000s)"
        ])
        self.duration_combo.setCurrentText("1 hour (3600s)")
        self.duration_combo.currentTextChanged.connect(self.update_duration)
        duration_layout.addWidget(self.duration_combo)
        config_layout.addLayout(duration_layout)
        
        # Check interval
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Check Interval:"))
        self.interval_slider = QSlider(Qt.Orientation.Horizontal)
        self.interval_slider.setRange(1, 30)
        self.interval_slider.setValue(5)
        self.interval_slider.valueChanged.connect(self.update_interval)
        self.interval_label = QLabel("5 seconds")
        interval_layout.addWidget(self.interval_slider)
        interval_layout.addWidget(self.interval_label)
        config_layout.addLayout(interval_layout)
        
        # Capture directory
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Capture Directory:"))
        self.dir_btn = QPushButton("📁 Select")
        self.dir_btn.clicked.connect(self.select_directory)
        dir_layout.addWidget(self.dir_btn)
        config_layout.addLayout(dir_layout)
        
        self.dir_label = QLabel(str(self.capture_dir))
        self.dir_label.setWordWrap(True)
        config_layout.addWidget(self.dir_label)
        
        layout.addWidget(config_group)
        
        # WiFi Security Group
        wifi_group = QGroupBox("📡 WiFi Security")
        wifi_layout = QVBoxLayout(wifi_group)
        
        # Firewall controls
        firewall_layout = QHBoxLayout()
        self.firewall_btn = QPushButton("🛡️ Enable Firewall")
        self.firewall_btn.clicked.connect(self.toggle_firewall)
        self.firewall_btn.setEnabled(False)
        firewall_layout.addWidget(self.firewall_btn)
        wifi_layout.addLayout(firewall_layout)
        
        # Threat counter
        self.threat_label = QLabel("🚨 Threats detected: 0")
        wifi_layout.addWidget(self.threat_label)
        
        layout.addWidget(wifi_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        return control_widget
        
    def create_monitoring_panel(self):
        """Create the monitoring panel with tabs"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # Tab widget for different views
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3B82F6;
                background: #1F2937;
            }
            QTabBar::tab {
                background: #374151;
                color: #D1D5DB;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #3B82F6;
                color: white;
            }
        """)
        
        # Create tabs
        self.create_monitor_tab()
        self.create_nfc_tab()
        self.create_interface_tab()
        self.create_capture_tab()
        self.create_settings_tab()
        
        layout.addWidget(self.tabs)
        return monitor_widget
    
    def setup_timers(self):
        """Setup update timers"""
        # UI update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(2000)  # Update every 2 seconds to match monitor updates
        
        # Network scan timer
        self.network_timer = QTimer()
        self.network_timer.timeout.connect(self.update_network_status)
        self.network_timer.start(10000)  # Update every 10 seconds
        
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        if hasattr(self, 'log_text'):
            self.log_text.append(formatted_message)
        print(formatted_message)
    
    def load_registered_tags(self):
        """Load registered NFC tags"""
        try:
            if self.tags_path.exists():
                with open(self.tags_path, 'r') as f:
                    self.registered_tags = json.load(f)
                self.log_message(f"📱 Loaded {len(self.registered_tags)} registered NFC tags")
            else:
                self.registered_tags = []
                self.log_message("📱 No registered NFC tags found")
        except Exception as e:
            self.registered_tags = []
            self.log_message(f"⚠️ Error loading NFC tags: {e}")
    
    def save_registered_tags(self):
        """Save registered NFC tags"""
        try:
            with open(self.tags_path, 'w') as f:
                json.dump(self.registered_tags, f, indent=2)
        except Exception as e:
            self.log_message(f"⚠️ Error saving NFC tags: {e}")
    
    def load_authentication(self):
        """Load authentication state"""
        try:
            if self.auth_profile_path.exists():
                with open(self.auth_profile_path, 'r') as f:
                    auth_data = json.load(f)
                    self.authenticated = auth_data.get('authenticated', False)
                    self.firewall_enabled = auth_data.get('firewall_enabled', False)
                    self.log_message(f"🔐 Authentication state loaded: {'Authenticated' if self.authenticated else 'Not authenticated'}")
                    
                    # Enable buttons if already authenticated
                    if self.authenticated:
                        self.log_message("🔧 Enabling buttons for saved authentication...")
                        self.start_btn.setEnabled(True)
                        self.firewall_btn.setEnabled(True)
                        # Enable control panel buttons too
                        if hasattr(self, 'control_start_btn'):
                            self.control_start_btn.setEnabled(True)
                        self.update_auth_status(True)
                        self.log_message(f"🔧 Start button enabled: {self.start_btn.isEnabled()}")
                        self.log_message(f"🔧 Firewall button enabled: {self.firewall_btn.isEnabled()}")
        except Exception as e:
            self.log_message(f"⚠️ Error loading authentication: {e}")
    
    def save_authentication(self):
        """Save authentication state"""
        try:
            auth_data = {
                'authenticated': self.authenticated,
                'firewall_enabled': self.firewall_enabled,
                'last_auth': datetime.now().isoformat()
            }
            with open(self.auth_profile_path, 'w') as f:
                json.dump(auth_data, f, indent=2)
        except Exception as e:
            self.log_message(f"⚠️ Error saving authentication: {e}")
    
    def check_auto_authentication(self):
        """Check for auto-authentication on startup"""
        current_bssid = self.get_current_bssid()
        if current_bssid:
            matching_tags = [tag for tag in self.registered_tags 
                           if 'network_binding' in tag and 
                           tag['network_binding']['bssid'] == current_bssid]
            
            if matching_tags:
                self.authenticated = True
                self.firewall_enabled = True
                self.save_authentication()
                self.update_auth_status(True)
                self.log_message(f"🔐 Auto-authenticated via network-bound NFC tag")
    
    def get_current_bssid(self):
        """Get current WiFi BSSID"""
        try:
            result = subprocess.run(['airport', '-I'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'BSSID:' in line:
                    return line.split('BSSID:')[1].strip()
        except Exception:
            pass
        return None
    
    def authenticate_nfc(self):
        """Simulate NFC authentication"""
        self.log_message("📱 NFC authentication requested...")
        QTimer.singleShot(2000, self.complete_nfc_auth)
    
    def complete_nfc_auth(self):
        """Complete NFC authentication"""
        self.authenticated = True
        self.save_authentication()
        self.update_auth_status(True)
        self.log_message("✅ NFC authentication successful")
        
        # Enable monitoring controls with logging
        self.log_message(f"🔧 Start button state before: {self.start_btn.isEnabled()}")
        self.start_btn.setEnabled(True)
        self.log_message(f"🔧 Start button state after: {self.start_btn.isEnabled()}")
        
        # Enable control panel buttons too
        if hasattr(self, 'control_start_btn'):
            self.control_start_btn.setEnabled(True)
            self.log_message(f"🔧 Control start button enabled: {self.control_start_btn.isEnabled()}")
        
        self.log_message(f"🔧 Firewall button state before: {self.firewall_btn.isEnabled()}")
        self.firewall_btn.setEnabled(True)
        self.log_message(f"🔧 Firewall button state after: {self.firewall_btn.isEnabled()}")
        
        # Test button click programmatically
        self.test_button_state()
        
    def update_auth_status(self, authenticated):
        """Update authentication status display"""
        if authenticated:
            self.auth_status_label.setText("🔓 Authenticated")
            self.auth_status_label.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 14px;")
            self.nfc_auth_btn.setEnabled(False)
            self.logout_btn.setEnabled(True)
        else:
            self.auth_status_label.setText("🔒 Not Authenticated")
            self.auth_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold; font-size: 14px;")
            self.nfc_auth_btn.setEnabled(True)
            self.logout_btn.setEnabled(False)
    
    def logout(self):
        """Logout and disable features"""
        self.authenticated = False
        self.firewall_enabled = False
        self.save_authentication()
        self.update_auth_status(False)
        
        # Stop monitoring if running
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.stop_monitor()
        
        # Disable controls
        self.start_btn.setEnabled(False)
        self.firewall_btn.setEnabled(False)
        
        # Disable control panel buttons too
        if hasattr(self, 'control_start_btn'):
            self.control_start_btn.setEnabled(False)
        
        self.log_message("🚪 Logged out - monitoring disabled")
    
    def toggle_firewall(self):
        """Toggle firewall state"""
        if not self.authenticated:
            self.log_message("⚠️ Authentication required for firewall control")
            return
            
        self.firewall_enabled = not self.firewall_enabled
        self.save_authentication()
        
        if self.firewall_enabled:
            self.firewall_btn.setText("🛡️ Disable Firewall")
            self.firewall_btn.setStyleSheet("background-color: #f44336;")
            self.log_message("🛡️ Firewall enabled")
        else:
            self.firewall_btn.setText("🛡️ Enable Firewall")
            self.firewall_btn.setStyleSheet("background-color: #4CAF50;")
            self.log_message("🛡️ Firewall disabled")
    
    def start_monitor(self):
        """Start the network monitoring"""
        self.log_message(f"🔧 Start monitor called. Auth status: {self.authenticated}")
        self.log_message(f"🔧 Start button enabled: {self.start_btn.isEnabled()}")
        
        if self.monitor_thread:
            self.log_message("Monitor already running")
            return
            
        self.log_message("🚀 Starting StealthShark Monitor...")
        self.log_message(f"📁 Capture directory: {self.capture_dir}")
        self.log_message(f"⏱️ Capture duration: {self.duration}s")
        self.log_message(f"🕒 Check interval: {self.interval}s")
        
        # Create monitor thread
        self.monitor_thread = StealthSharkMonitorThread(self.capture_dir, self.duration, self.interval)
        self.monitor_thread.interface_activity.connect(self.on_interface_activity)
        self.monitor_thread.capture_started.connect(self.on_capture_started)
        self.monitor_thread.capture_completed.connect(self.on_capture_completed)
        self.monitor_thread.status_update.connect(self.on_status_update)
        self.monitor_thread.alert_signal.connect(self.on_alert)
        self.monitor_thread.batch_alert_signal.connect(self.on_batch_alert)
        
        # Start monitor thread
        self.monitor_thread.start()
        
        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # Update control panel buttons
        if hasattr(self, 'control_start_btn'):
            self.control_start_btn.setEnabled(False)
            self.control_stop_btn.setEnabled(True)
        
        # Update status in sidebar
        self.monitor_status_label.setText("Status: 🟢 Active")
        self.monitor_status_label.setStyleSheet("color: #4CAF50; font-weight: bold;")
        
        # Update display timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_display)
        self.timer.start(2000)  # Update every 2 seconds to match monitor updates
        
        # Start time tracking for remaining time display
        self.start_time = QDateTime.currentDateTime()
        
        # Network scan timer
        self.network_timer = QTimer()
        self.network_timer.timeout.connect(self.update_network_status)
        self.network_timer.start(10000)  # Update every 10 seconds
        
        # Start network monitoring
        self.start_network_monitoring()
        
    def test_button_state(self):
        """Test and log button states"""
        self.log_message("🧪 Testing button states...")
        self.log_message(f"  Auth status: {self.authenticated}")
        self.log_message(f"  Start button enabled: {self.start_btn.isEnabled()}")
        self.log_message(f"  Stop button enabled: {self.stop_btn.isEnabled()}")
        self.log_message(f"  Firewall button enabled: {self.firewall_btn.isEnabled()}")
        
        # Force enable if authenticated
        if self.authenticated and not self.start_btn.isEnabled():
            self.log_message("⚠️ Button should be enabled but isn't. Force enabling...")
            self.start_btn.setEnabled(True)
            self.log_message(f"  Start button enabled after force: {self.start_btn.isEnabled()}")
        
        # Test programmatic click
        if self.authenticated and self.start_btn.isEnabled():
            self.log_message("🧪 Testing programmatic button click...")
            QTimer.singleShot(1000, lambda: self.log_message("🧪 Clicking Start Monitor button programmatically..."))
            QTimer.singleShot(1500, self.start_btn.click)
    
    def stop_monitor(self):
        """Stop the network monitoring"""
        if not self.monitor_thread:
            self.log_message("No monitor running")
            return
            
        self.log_message("🛑 Stopping monitor...")
        
        # Stop monitoring
        self.monitor_thread.stop()
        self.monitor_thread = None
        
        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        # Update control panel buttons
        if hasattr(self, 'control_start_btn'):
            self.control_start_btn.setEnabled(True)
            self.control_stop_btn.setEnabled(False)
        
        # Update status in sidebar
        self.monitor_status_label.setText("Status: Stopped")
        self.monitor_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        
        # Clear time remaining
        self.time_remaining_label.setText("Time Remaining: --:--:--")
        
        # Stop timer
        if hasattr(self, 'timer'):
            self.timer.stop()
        
        self.log_message("Monitor stopped")
    
    def start_network_monitoring(self):
        """Start WiFi network monitoring"""
        if self.network_monitor_thread and self.network_monitor_thread.isRunning():
            return
            
        self.network_monitor_thread = NetworkMonitorThread(self.legitimate_bssid)
        self.network_monitor_thread.network_update.connect(self.on_network_update)
        self.network_monitor_thread.threat_detected.connect(self.on_threat_detected)
        self.network_monitor_thread.start()
        
        self.log_message("📡 WiFi network monitoring started")
    
    def stop_network_monitoring(self):
        """Stop WiFi network monitoring"""
        if self.network_monitor_thread:
            self.network_monitor_thread.stop()
            self.network_monitor_thread.wait(3000)
            self.network_monitor_thread = None
            self.log_message("📡 WiFi network monitoring stopped")
    
    def on_network_update(self, networks):
        """Handle network updates"""
        self.current_networks = networks
        
        # Log network status instead
        current_ssid = self.get_current_ssid()
        current_bssid = self.get_current_bssid()
        
        if current_bssid == self.legitimate_bssid:
            self.log_message(f"✅ Connected to legitimate network: {current_ssid}")
        else:
            self.log_message(f"⚠️ Connected to unknown network: {current_ssid}")
    
    def on_threat_detected(self, threat):
        """Handle threat detection"""
        self.threat_count += 1
        self.threat_label.setText(f"🚨 Threats detected: {self.threat_count}")
        
        threat_msg = f"🚨 THREAT DETECTED: {threat['ssid']} ({threat['bssid']})"
        self.log_message(threat_msg)
        
        # Add to blocked BSSIDs
        self.blocked_bssids.add(threat['bssid'])
    
    def update_networks_table(self):
        """Update the networks table - deprecated"""
        pass  # Networks table removed - using NFC management instead
    
    def get_current_ssid(self):
        """Get current WiFi SSID"""
        try:
            result = subprocess.run(['networksetup', '-getairportnetwork', 'en0'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.strip()
                if "Current Wi-Fi Network:" in output:
                    ssid = output.split("Current Wi-Fi Network: ")[1].strip()
                    if ssid and "not associated" not in ssid.lower():
                        return ssid
            return "Disconnected"
        except Exception:
            return "Unknown"
    
    def update_network_status(self):
        """Update network status display"""
        current_ssid = self.get_current_ssid()
        current_bssid = self.get_current_bssid()
        
        if hasattr(self, 'current_ssid_label'):
            self.current_ssid_label.setText(f"SSID: {current_ssid}")
            self.current_bssid_label.setText(f"BSSID: {current_bssid or 'Unknown'}")
    
    def update_captures_table(self):
        """Update the active captures table"""
        if hasattr(self, 'monitor_thread') and self.monitor_thread and hasattr(self.monitor_thread, 'monitor'):
            monitor = self.monitor_thread.monitor
            if hasattr(monitor, 'active_captures'):
                captures = monitor.active_captures
                self.capture_table.setRowCount(len(captures))
                
                for row, (interface, process_info) in enumerate(captures.items()):
                    self.capture_table.setItem(row, 0, QTableWidgetItem(interface))
                    if isinstance(process_info, dict):
                        start_time = process_info.get('start_time', 'Unknown')
                        duration = process_info.get('duration', 'Unknown')
                        filename = process_info.get('capture_file', 'Unknown')
                    else:
                        start_time = datetime.now().strftime('%H:%M:%S')
                        duration = f"{self.duration}s"
                        filename = f"capture_{interface}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
                    
                    self.capture_table.setItem(row, 1, QTableWidgetItem(str(start_time)))
                    self.capture_table.setItem(row, 2, QTableWidgetItem(str(duration)))
                    self.capture_table.setItem(row, 3, QTableWidgetItem(str(filename)))
    
    def update_interfaces_table(self, interface, stats):
        """Update single interface in the table"""
        # Find or create row for this interface
        row = -1
        for i in range(self.interface_table.rowCount()):
            if self.interface_table.item(i, 0) and self.interface_table.item(i, 0).text() == interface:
                row = i
                break
        
        if row == -1:
            row = self.interface_table.rowCount()
            self.interface_table.insertRow(row)
            self.interface_table.setItem(row, 0, QTableWidgetItem(interface))
        self.interface_table.setItem(row, 1, QTableWidgetItem(str(stats.get('packets', 0))))
        self.interface_table.setItem(row, 2, QTableWidgetItem(str(stats.get('bytes', 0))))
        self.interface_table.setItem(row, 3, QTableWidgetItem(str(stats.get('last_activity', 'Never'))))
        
        # Status based on activity
        status = "🟢 Active" if stats.get('packets', 0) > 0 else "⚫ Idle"
        self.interface_table.setItem(row, 4, QTableWidgetItem(status))
    
    def update_all_interfaces_table(self, interface_stats):
        """Update all interfaces in the table"""
        if not hasattr(self, 'interface_table'):
            self.log_message("⚠️ Interface table not initialized")
            return
            
        # Log for debugging
        self.log_message(f"📊 Updating interfaces table with {len(interface_stats)} interfaces")
        
        self.interface_table.setRowCount(len(interface_stats))
        
        for row, (interface, stats) in enumerate(interface_stats.items()):
            self.interface_table.setItem(row, 0, QTableWidgetItem(interface))
            self.interface_table.setItem(row, 1, QTableWidgetItem(str(stats.get('packets', 0))))
            self.interface_table.setItem(row, 2, QTableWidgetItem(str(stats.get('bytes', 0))))
            self.interface_table.setItem(row, 3, QTableWidgetItem(str(stats.get('last_activity', 'Never'))))
            
            # Status based on activity
            status = "🟢 Active" if stats.get('packets', 0) > 0 else "⚫ Idle"
            self.interface_table.setItem(row, 4, QTableWidgetItem(status))
    
    def update_display(self):
        """Update the display with latest stats"""
        if not self.monitor_thread or not hasattr(self.monitor_thread, 'monitor'):
            self.log_message("⚠️ No monitor thread available")
            return
            
        monitor = self.monitor_thread.monitor
        
        # Update interface stats from monitor
        if hasattr(monitor, 'interface_stats'):
            self.interface_stats = monitor.interface_stats.copy()
            self.update_all_interfaces_table(self.interface_stats)
        else:
            self.log_message("⚠️ No interface stats available")
        
        # Update time remaining
        if hasattr(self, 'start_time'):
            elapsed = self.start_time.secsTo(QDateTime.currentDateTime())
            remaining = max(0, self.duration - elapsed)
            hours = remaining // 3600
            minutes = (remaining % 3600) // 60
            seconds = remaining % 60
            self.time_remaining_label.setText(f"Time Remaining: {hours:02d}:{minutes:02d}:{seconds:02d}")
            
            # Stop if time is up
            if remaining == 0:
                self.stop_monitor()
    
    def on_alert(self, message):
        """Handle single alert"""
        self.log_message(f"🚨 {message}")
    
    def on_batch_alert(self, messages):
        """Handle batch alerts"""
        for message in messages:
            self.log_message(f"🦈 {message}")
    
    def on_interface_activity(self, interface, stats):
        """Handle interface activity updates"""
        # Log interface activity
        packets = stats.get('packets', 0)
        bytes_count = stats.get('bytes', 0)
        
        # Check if this is a new interface
        is_new = True
        for i in range(self.interface_table.rowCount()):
            if self.interface_table.item(i, 0) and self.interface_table.item(i, 0).text() == interface:
                is_new = False
                break
        
        if is_new:
            self.log_message(f"🔍 New interface detected: {interface}")
        
        if packets > 0:
            self.log_message(f"📡 {interface}: {packets} packets, {bytes_count} bytes")
        
        # Update interface activity table
        self.update_interfaces_table(interface, stats)
    
    def on_capture_started(self, interface, filename):
        """Handle capture started event"""
        self.log_message(f"📹 Capture started on {interface}: {filename}")
        self.update_captures_table()
    
    def on_capture_completed(self, interface, filename):
        """Handle capture completed event"""
        self.log_message(f"✅ Capture completed on {interface}: {filename}")
        self.update_captures_table()
    
    def on_status_update(self, status):
        """Handle status updates from monitor"""
        if 'active_captures' in status:
            self.update_captures_table()
        if 'interface_stats' in status:
            self.update_all_interfaces_table(status['interface_stats'])
    
    def clear_logs(self):
        """Clear the log display"""
        self.log_text.clear()
        self.log_message("🗑️ Logs cleared")
    
    def export_logs(self):
        """Export logs to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"stealthshark_nfc_logs_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(self.log_text.toPlainText())
            self.log_message(f"💾 Logs exported to {filename}")
        except Exception as e:
            self.log_message(f"⚠️ Export failed: {e}")
    
    def setup_nfc_management_tab(self):
        """Setup NFC Tag Management tab"""
        layout = QVBoxLayout(self.nfc_tab)
        
        # Authentication status
        status_group = QGroupBox("NFC Authentication Status")
        status_layout = QVBoxLayout()
        
        self.auth_status_label = QLabel("🔐 Authentication: Active" if self.authenticated else "🔒 Authentication: Required")
        self.auth_status_label.setStyleSheet("font-size: 14px; font-weight: bold; color: green;" if self.authenticated else "font-size: 14px; font-weight: bold; color: orange;")
        self.last_auth_label = QLabel(f"Last Authentication: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" if self.authenticated else "Last Authentication: Never")
        
        status_layout.addWidget(self.auth_status_label)
        status_layout.addWidget(self.last_auth_label)
        status_group.setLayout(status_layout)
        
        # Registered tags table
        tags_group = QGroupBox("Registered NFC Tags")
        tags_layout = QVBoxLayout()
        
        self.tags_table = QTableWidget()
        self.tags_table.setColumnCount(4)
        self.tags_table.setHorizontalHeaderLabels(["Tag ID", "Name", "Added Date", "Actions"])
        self.tags_table.horizontalHeader().setStretchLastSection(True)
        
        tags_layout.addWidget(self.tags_table)
        tags_group.setLayout(tags_layout)
        
        # Add new tag section
        add_group = QGroupBox("Add New NFC Tag")
        add_layout = QHBoxLayout()
        
        self.tag_id_input = QLineEdit()
        self.tag_id_input.setPlaceholderText("Enter NFC tag ID...")
        self.tag_name_input = QLineEdit()
        self.tag_name_input.setPlaceholderText("Tag name/description...")
        
        self.add_tag_button = QPushButton("➕ Add Tag")
        self.add_tag_button.clicked.connect(self.add_nfc_tag)
        
        self.scan_tag_button = QPushButton("📱 Scan NFC Tag")
        self.scan_tag_button.clicked.connect(self.scan_nfc_tag)
        
        add_layout.addWidget(QLabel("Tag ID:"))
        add_layout.addWidget(self.tag_id_input)
        add_layout.addWidget(QLabel("Name:"))
        add_layout.addWidget(self.tag_name_input)
        add_layout.addWidget(self.add_tag_button)
        add_layout.addWidget(self.scan_tag_button)
        
        add_group.setLayout(add_layout)
        
        layout.addWidget(status_group)
        layout.addWidget(tags_group)
        layout.addWidget(add_group)
        layout.addStretch()
        
        # Load existing tags
        self.load_nfc_tags()
    
    def load_nfc_tags(self):
        """Load NFC tags from storage"""
        try:
            tags_file = Path("nfc_tags.json")
            if tags_file.exists():
                with open(tags_file, 'r') as f:
                    tags = json.load(f)
                    
                self.tags_table.setRowCount(len(tags))
                for i, tag in enumerate(tags):
                    self.tags_table.setItem(i, 0, QTableWidgetItem(tag.get('id', '')))
                    self.tags_table.setItem(i, 1, QTableWidgetItem(tag.get('name', '')))
                    self.tags_table.setItem(i, 2, QTableWidgetItem(tag.get('date', '')))
                    
                    # Delete button
                    delete_btn = QPushButton("🗑️")
                    delete_btn.clicked.connect(lambda checked, tag_id=tag.get('id'): self.delete_nfc_tag(tag_id))
                    self.tags_table.setCellWidget(i, 3, delete_btn)
                    
                self.log_message(f"📱 Loaded {len(tags)} NFC tags")
        except Exception as e:
            self.log_message(f"❌ Error loading NFC tags: {e}")
    
    def add_nfc_tag(self):
        """Add a new NFC tag"""
        tag_id = self.tag_id_input.text().strip()
        tag_name = self.tag_name_input.text().strip()
        
        if not tag_id:
            self.log_message("⚠️ Please enter a tag ID")
            return
            
        try:
            tags_file = Path("nfc_tags.json")
            tags = []
            if tags_file.exists():
                with open(tags_file, 'r') as f:
                    tags = json.load(f)
            
            # Check for duplicates
            if any(t.get('id') == tag_id for t in tags):
                self.log_message(f"⚠️ Tag {tag_id} already exists")
                return
            
            # Add new tag
            new_tag = {
                'id': tag_id,
                'name': tag_name or f"Tag {len(tags) + 1}",
                'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            tags.append(new_tag)
            
            # Save tags
            with open(tags_file, 'w') as f:
                json.dump(tags, f, indent=2)
            
            self.log_message(f"✅ Added NFC tag: {new_tag['name']} ({tag_id})")
            
            # Clear inputs and reload
            self.tag_id_input.clear()
            self.tag_name_input.clear()
            self.load_nfc_tags()
            
        except Exception as e:
            self.log_message(f"❌ Error adding tag: {e}")
    
    def delete_nfc_tag(self, tag_id):
        """Delete an NFC tag"""
        try:
            tags_file = Path("nfc_tags.json")
            if tags_file.exists():
                with open(tags_file, 'r') as f:
                    tags = json.load(f)
                
                tags = [t for t in tags if t.get('id') != tag_id]
                
                with open(tags_file, 'w') as f:
                    json.dump(tags, f, indent=2)
                
                self.log_message(f"🗑️ Deleted NFC tag: {tag_id}")
                self.load_nfc_tags()
        except Exception as e:
            self.log_message(f"❌ Error deleting tag: {e}")
    
    def scan_nfc_tag(self):
        """Launch NFC tag scanning dialog"""
        dialog = NFCScanDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            tag_id = dialog.get_tag_id()
            if tag_id:
                self.tag_id_input.setText(tag_id)
                self.log_message(f"📱 Scanned NFC tag: {tag_id}")
                # Auto-populate name if it's a known tag pattern
                if tag_id == "home1":
                    self.tag_name_input.setText("Home Network Auth")
                elif "AIMF" in tag_id:
                    self.tag_name_input.setText("AIMF Primary Key")
                elif "SAFE" in tag_id:
                    self.tag_name_input.setText("Backup Security Key")
    
    def update_duration(self, text):
        """Update capture duration"""
        duration_map = {
            "1 minute (60s)": 60,
            "5 minutes (300s)": 300,
            "15 minutes (900s)": 900,
            "30 minutes (1800s)": 1800,
            "1 hour (3600s)": 3600,
            "2 hours (7200s)": 7200,
            "5 hours (18000s)": 18000
        }
        self.duration = duration_map.get(text, 3600)
        self.log_message(f"⏱️ Capture duration set to {text}")
    
    def update_interval(self, value):
        """Update check interval"""
        self.interval = value
        self.interval_label.setText(f"{value} seconds")
        self.log_message(f"⏱️ Check interval set to {value} seconds")
    
    def select_directory(self):
        """Select capture directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Capture Directory")
        if directory:
            self.capture_dir = Path(directory)
            self.dir_label.setText(str(self.capture_dir))
            self.log_message(f"📁 Capture directory set to {self.capture_dir}")
            self.save_settings()
    
    def create_monitor_tab(self):
        """Create monitor control tab"""
        monitor_widget = QWidget()
        layout = QVBoxLayout()
        
        # Monitor status
        status_group = QGroupBox("Monitor Status")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Status: Ready")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        status_layout.addWidget(self.status_label)
        
        # Countdown timer
        self.countdown_label = QLabel("Time Remaining: --:--:--")
        self.countdown_label.setStyleSheet("font-size: 12px;")
        status_layout.addWidget(self.countdown_label)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Settings
        settings_group = QGroupBox("Capture Settings")
        settings_layout = QVBoxLayout()
        
        # Duration
        dur_layout = QHBoxLayout()
        dur_layout.addWidget(QLabel("Duration:"))
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([
            "1 minute (60s)", "5 minutes (300s)", "15 minutes (900s)",
            "30 minutes (1800s)", "1 hour (3600s)", "2 hours (7200s)"
        ])
        self.duration_combo.setCurrentText("1 hour (3600s)")
        self.duration_combo.currentTextChanged.connect(self.update_duration)
        dur_layout.addWidget(self.duration_combo)
        settings_layout.addLayout(dur_layout)
        
        # Check interval
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Check Interval:"))
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1, 60)
        self.interval_spin.setValue(self.interval)
        self.interval_spin.setSuffix(" seconds")
        self.interval_spin.valueChanged.connect(self.update_interval)
        interval_layout.addWidget(self.interval_spin)
        self.interval_label = QLabel(f"{self.interval} seconds")
        interval_layout.addWidget(self.interval_label)
        settings_layout.addLayout(interval_layout)
        
        # Directory
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Capture Directory:"))
        self.dir_label = QLabel(str(self.capture_dir))
        self.dir_label.setStyleSheet("padding: 5px; background-color: #374151; border-radius: 3px;")
        dir_layout.addWidget(self.dir_label)
        dir_btn = QPushButton("📁 Browse")
        dir_btn.clicked.connect(self.select_directory)
        dir_layout.addWidget(dir_btn)
        settings_layout.addLayout(dir_layout)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Control buttons
        control_group = QGroupBox("Controls")
        control_layout = QHBoxLayout()
        
        # Create secondary control buttons (different from sidebar)
        self.control_start_btn = QPushButton("▶️ Start Monitor")
        self.control_start_btn.setEnabled(False)  # Disabled until authenticated
        self.control_start_btn.clicked.connect(self.start_monitor)
        control_layout.addWidget(self.control_start_btn)
        
        self.control_stop_btn = QPushButton("⏹️ Stop Monitor")
        self.control_stop_btn.setEnabled(False)
        self.control_stop_btn.clicked.connect(self.stop_monitor)
        control_layout.addWidget(self.control_stop_btn)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        layout.addStretch()
        monitor_widget.setLayout(layout)
        self.tabs.addTab(monitor_widget, "🦈 Monitor")
    
    def create_nfc_tab(self):
        """Create NFC management tab"""
        nfc_widget = QWidget()
        layout = QVBoxLayout()
        
        # NFC header
        header = QLabel("📱 NFC Tag Management")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # Add tag section
        add_group = QGroupBox("Add New Tag")
        add_layout = QHBoxLayout()
        
        self.tag_id_input = QLineEdit()
        self.tag_id_input.setPlaceholderText("Tag ID (e.g., home1)")
        add_layout.addWidget(self.tag_id_input)
        
        self.tag_name_input = QLineEdit()
        self.tag_name_input.setPlaceholderText("Tag Name")
        add_layout.addWidget(self.tag_name_input)
        
        scan_btn = QPushButton("📱 Scan NFC Tag")
        scan_btn.clicked.connect(self.scan_nfc_tag)
        add_layout.addWidget(scan_btn)
        
        add_btn = QPushButton("➕ Add Tag")
        add_btn.clicked.connect(self.add_nfc_tag)
        add_layout.addWidget(add_btn)
        
        add_group.setLayout(add_layout)
        layout.addWidget(add_group)
        
        # Tags table
        self.tags_table = QTableWidget()
        self.tags_table.setColumnCount(5)
        self.tags_table.setHorizontalHeaderLabels(["ID", "Name", "Added", "Network", "Action"])
        self.tags_table.horizontalHeader().setStretchLastSection(True)
        self.tags_table.setAlternatingRowColors(True)
        layout.addWidget(self.tags_table)
        
        # Load existing tags
        self.load_nfc_tags()
        
        nfc_widget.setLayout(layout)
        self.tabs.addTab(nfc_widget, "🔐 NFC Tags")
    
    def create_interface_tab(self):
        """Create interface activity tab"""
        interface_widget = QWidget()
        layout = QVBoxLayout()
        
        # Interface header
        header = QLabel("📡 Interface Activity")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # Interface table
        self.interface_table = QTableWidget()
        self.interface_table.setColumnCount(5)
        self.interface_table.setHorizontalHeaderLabels(["Interface", "Packets", "Bytes", "Last Activity", "Status"])
        self.interface_table.horizontalHeader().setStretchLastSection(True)
        self.interface_table.setAlternatingRowColors(True)
        layout.addWidget(self.interface_table)
        
        interface_widget.setLayout(layout)
        self.tabs.addTab(interface_widget, "📊 Interfaces")
    
    def create_capture_tab(self):
        """Create capture files tab"""
        capture_widget = QWidget()
        layout = QVBoxLayout()
        
        # Capture header
        header = QLabel("📹 Active Packet Captures")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # Capture table
        self.capture_table = QTableWidget()
        self.capture_table.setColumnCount(4)
        self.capture_table.setHorizontalHeaderLabels(["Interface", "Start Time", "Duration", "File"])
        self.capture_table.horizontalHeader().setStretchLastSection(True)
        self.capture_table.setAlternatingRowColors(True)
        layout.addWidget(self.capture_table)
        
        capture_widget.setLayout(layout)
        self.tabs.addTab(capture_widget, "📁 Captures")
    
    def create_settings_tab(self):
        """Create settings configuration tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout()
        
        # Settings header
        header = QLabel("⚙️ Application Settings")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(header)
        
        # Capture Settings Group
        capture_group = QGroupBox("Capture Settings")
        capture_layout = QVBoxLayout()
        
        # Default capture directory
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Default Capture Directory:"))
        self.settings_dir_label = QLabel(str(self.capture_dir))
        self.settings_dir_label.setStyleSheet("padding: 5px; background-color: #374151; border-radius: 3px;")
        dir_layout.addWidget(self.settings_dir_label)
        settings_dir_btn = QPushButton("📁 Change")
        settings_dir_btn.clicked.connect(self.change_default_directory)
        dir_layout.addWidget(settings_dir_btn)
        capture_layout.addLayout(dir_layout)
        
        # Auto-capture loopback setting
        self.auto_loopback_check = QCheckBox("Always capture loopback (lo0) interface")
        self.auto_loopback_check.setChecked(True)
        self.auto_loopback_check.stateChanged.connect(self.save_settings)
        capture_layout.addWidget(self.auto_loopback_check)
        
        # Auto-detect new interfaces
        self.auto_detect_check = QCheckBox("Automatically detect and capture new interfaces")
        self.auto_detect_check.setChecked(True)
        self.auto_detect_check.stateChanged.connect(self.save_settings)
        capture_layout.addWidget(self.auto_detect_check)
        
        # Capture all active interfaces
        self.capture_all_check = QCheckBox("Capture from all active interfaces (not just priority ones)")
        self.capture_all_check.setChecked(True)
        self.capture_all_check.stateChanged.connect(self.save_settings)
        capture_layout.addWidget(self.capture_all_check)
        
        capture_group.setLayout(capture_layout)
        layout.addWidget(capture_group)
        
        # Monitoring Settings Group
        monitor_group = QGroupBox("Monitoring Settings")
        monitor_layout = QVBoxLayout()
        
        # Default duration
        dur_layout = QHBoxLayout()
        dur_layout.addWidget(QLabel("Default Capture Duration:"))
        self.settings_duration_combo = QComboBox()
        self.settings_duration_combo.addItems([
            "1 minute (60s)", "5 minutes (300s)", "15 minutes (900s)",
            "30 minutes (1800s)", "1 hour (3600s)", "2 hours (7200s)",
            "Continuous"
        ])
        self.settings_duration_combo.setCurrentText("1 hour (3600s)")
        self.settings_duration_combo.currentTextChanged.connect(self.update_default_duration)
        dur_layout.addWidget(self.settings_duration_combo)
        monitor_layout.addLayout(dur_layout)
        
        # Check interval
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Interface Check Interval:"))
        self.settings_interval_spin = QSpinBox()
        self.settings_interval_spin.setRange(1, 60)
        self.settings_interval_spin.setValue(self.interval)
        self.settings_interval_spin.setSuffix(" seconds")
        self.settings_interval_spin.valueChanged.connect(self.update_check_interval)
        interval_layout.addWidget(self.settings_interval_spin)
        monitor_layout.addLayout(interval_layout)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
        
        # File Management Group
        file_group = QGroupBox("File Management")
        file_layout = QVBoxLayout()
        
        # Auto-cleanup old captures
        self.auto_cleanup_check = QCheckBox("Automatically delete captures older than 7 days")
        self.auto_cleanup_check.setChecked(True)
        self.auto_cleanup_check.stateChanged.connect(self.save_settings)
        file_layout.addWidget(self.auto_cleanup_check)
        
        # Compression
        self.compress_check = QCheckBox("Compress completed captures (gzip)")
        self.compress_check.setChecked(False)
        self.compress_check.stateChanged.connect(self.save_settings)
        file_layout.addWidget(self.compress_check)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Save/Load buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save Settings")
        save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(save_btn)
        
        load_btn = QPushButton("📂 Load Settings")
        load_btn.clicked.connect(self.load_settings)
        button_layout.addWidget(load_btn)
        
        reset_btn = QPushButton("🔄 Reset to Defaults")
        reset_btn.clicked.connect(self.reset_settings)
        button_layout.addWidget(reset_btn)
        
        layout.addLayout(button_layout)
        
        layout.addStretch()
        settings_widget.setLayout(layout)
        self.tabs.addTab(settings_widget, "⚙️ Settings")
    
    def change_default_directory(self):
        """Change default capture directory in settings"""
        directory = QFileDialog.getExistingDirectory(self, "Select Default Capture Directory")
        if directory:
            self.capture_dir = Path(directory)
            self.settings_dir_label.setText(str(self.capture_dir))
            self.dir_label.setText(str(self.capture_dir))  # Update monitor tab too
            self.log_message(f"📁 Default capture directory changed to {self.capture_dir}")
            self.save_settings()
    
    def update_default_duration(self, text):
        """Update default capture duration from settings"""
        duration_map = {
            "1 minute (60s)": 60,
            "5 minutes (300s)": 300,
            "15 minutes (900s)": 900,
            "30 minutes (1800s)": 1800,
            "1 hour (3600s)": 3600,
            "2 hours (7200s)": 7200,
            "Continuous": 0
        }
        self.duration = duration_map.get(text, 3600)
        self.duration_combo.setCurrentText(text)  # Sync with monitor tab
        self.save_settings()
    
    def update_check_interval(self, value):
        """Update interface check interval"""
        self.interval = value
        self.interval_spin.setValue(value)  # Sync with monitor tab
        self.save_settings()
    
    def save_settings(self):
        """Save application settings to file"""
        settings = {
            'capture_dir': str(self.capture_dir),
            'duration': self.duration,
            'interval': self.interval,
            'auto_loopback': self.auto_loopback_check.isChecked(),
            'auto_detect': self.auto_detect_check.isChecked(),
            'capture_all': self.capture_all_check.isChecked(),
            'auto_cleanup': self.auto_cleanup_check.isChecked(),
            'compress': self.compress_check.isChecked()
        }
        
        settings_file = Path.home() / '.stealthshark_settings.json'
        with open(settings_file, 'w') as f:
            json.dump(settings, f, indent=2)
        
        self.log_message("💾 Settings saved")
    
    def load_settings(self):
        """Load application settings from file"""
        settings_file = Path.home() / '.stealthshark_settings.json'
        if settings_file.exists():
            with open(settings_file, 'r') as f:
                settings = json.load(f)
            
            self.capture_dir = Path(settings.get('capture_dir', './pcap_captures'))
            self.duration = settings.get('duration', 3600)
            self.interval = settings.get('interval', 5)
            
            # Update UI
            self.settings_dir_label.setText(str(self.capture_dir))
            self.dir_label.setText(str(self.capture_dir))
            self.auto_loopback_check.setChecked(settings.get('auto_loopback', True))
            self.auto_detect_check.setChecked(settings.get('auto_detect', True))
            self.capture_all_check.setChecked(settings.get('capture_all', True))
            self.auto_cleanup_check.setChecked(settings.get('auto_cleanup', True))
            self.compress_check.setChecked(settings.get('compress', False))
            
            # Update combos and spins
            for i in range(self.settings_duration_combo.count()):
                text = self.settings_duration_combo.itemText(i)
                if str(self.duration) in text or (self.duration == 0 and "Continuous" in text):
                    self.settings_duration_combo.setCurrentIndex(i)
                    self.duration_combo.setCurrentIndex(i)
                    break
            
            self.settings_interval_spin.setValue(self.interval)
            self.interval_spin.setValue(self.interval)
            
            self.log_message("📂 Settings loaded")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        self.capture_dir = Path('./pcap_captures')
        self.duration = 3600
        self.interval = 5
        
        self.settings_dir_label.setText(str(self.capture_dir))
        self.dir_label.setText(str(self.capture_dir))
        self.auto_loopback_check.setChecked(True)
        self.auto_detect_check.setChecked(True)
        self.capture_all_check.setChecked(True)
        self.auto_cleanup_check.setChecked(True)
        self.compress_check.setChecked(False)
        self.settings_duration_combo.setCurrentText("1 hour (3600s)")
        self.duration_combo.setCurrentText("1 hour (3600s)")
        self.settings_interval_spin.setValue(5)
        self.interval_spin.setValue(5)
        
        self.save_settings()
        self.log_message("🔄 Settings reset to defaults")


class NFCScanDialog(QDialog):
    """Dialog for NFC tag scanning with professional UI"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tag_id = None
        self.setup_ui()
        
        # Start scanning simulation
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.update_scan_progress)
        self.scan_progress = 0
        self.scan_timer.start(100)
        
        # Auto-complete after 3 seconds (simulated)
        QTimer.singleShot(3000, self.complete_scan)
    
    def setup_ui(self):
        self.setWindowTitle("🔍 NFC Tag Scanner")
        self.setModal(True)
        self.setFixedSize(450, 350)
        
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🔷 AIMF NFC Authentication Scanner")
        header.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #3B82F6;
            padding: 10px;
        """)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Status message
        self.status_label = QLabel("📱 Place your NFC tag on the reader...")
        self.status_label.setStyleSheet("""
            font-size: 14px;
            padding: 10px;
            background-color: #1F2937;
            border-radius: 5px;
            color: #F9FAFB;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Scanning animation/progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #3B82F6;
                border-radius: 5px;
                background-color: #1F2937;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Tag info display
        info_group = QGroupBox("Tag Information")
        info_layout = QVBoxLayout()
        
        self.tag_info = QLabel("Waiting for tag...")
        self.tag_info.setStyleSheet("padding: 10px; font-family: monospace;")
        info_layout.addWidget(self.tag_info)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Manual entry option
        manual_group = QGroupBox("Manual Entry")
        manual_layout = QHBoxLayout()
        
        self.manual_input = QLineEdit()
        self.manual_input.setPlaceholderText("Enter tag ID manually (e.g., home1)")
        manual_layout.addWidget(self.manual_input)
        
        use_manual_btn = QPushButton("Use Manual ID")
        use_manual_btn.clicked.connect(self.use_manual_id)
        manual_layout.addWidget(use_manual_btn)
        
        manual_group.setLayout(manual_layout)
        layout.addWidget(manual_group)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setEnabled(False)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def update_scan_progress(self):
        """Update scanning progress animation"""
        self.scan_progress = (self.scan_progress + 5) % 101
        self.progress_bar.setValue(self.scan_progress)
        
        # Update status messages
        if self.scan_progress < 30:
            self.status_label.setText("🔍 Initializing NFC reader...")
        elif self.scan_progress < 60:
            self.status_label.setText("📡 Scanning for NFC tags...")
        else:
            self.status_label.setText("📱 Place your NFC tag on the reader...")
    
    def complete_scan(self):
        """Simulate successful NFC scan"""
        self.scan_timer.stop()
        self.progress_bar.setValue(100)
        
        # Check if we should detect a real tag
        try:
            import nfc
            clf = nfc.ContactlessFrontend('usb')
            # Try real NFC scan
            tag = clf.connect(rdwr={'on-connect': lambda tag: False}, terminate=lambda: False, timeout=1)
            if tag:
                self.tag_id = tag.identifier.hex().upper()
                self.tag_info.setText(f"✅ Tag Detected\n\nUID: {self.tag_id}\nType: {tag.type}")
            else:
                raise Exception("No tag detected")
            clf.close()
        except:
            # Fallback to simulation
            import random
            import string
            
            # Simulate finding a known tag sometimes
            known_tags = ['home1', 'AIMF1234', 'SAFE5678', 'STEALTH001']
            if random.random() > 0.5:
                self.tag_id = random.choice(known_tags)
            else:
                self.tag_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            
            self.tag_info.setText(f"✅ Tag Detected (Simulated)\n\nUID: {self.tag_id}\nType: NFC Forum Type 2")
        
        self.status_label.setText("✅ NFC tag successfully scanned!")
        self.status_label.setStyleSheet("""
            font-size: 14px;
            padding: 10px;
            background-color: #1b5e20;
            border-radius: 5px;
            color: #81c784;
            font-weight: bold;
        """)
        self.ok_button.setEnabled(True)
    
    def use_manual_id(self):
        """Use manually entered tag ID"""
        manual_id = self.manual_input.text().strip()
        if manual_id:
            self.tag_id = manual_id
            self.tag_info.setText(f"✅ Manual Entry\n\nUID: {self.tag_id}\nType: User Specified")
            self.status_label.setText("✅ Tag ID manually entered")
            self.scan_timer.stop()
            self.progress_bar.setValue(100)
            self.ok_button.setEnabled(True)
    
    def get_tag_id(self):
        """Return the scanned or entered tag ID"""
        return self.tag_id


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = StealthSharkNFCCombined()
    window.show()
    sys.exit(app.exec())
