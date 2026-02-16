#!/usr/bin/env python3
"""
Multi-Interface Shark GUI - Enhanced Network Monitor
PyQt6-based interface for monitoring ALL network interfaces with pattern recognition
Enhanced version of LoopbackShark for comprehensive network monitoring
"""

import sys
import os
import json
import signal
import psutil
import threading
import time
import subprocess
import traceback
import logging
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLabel, QTextEdit, QSpinBox, 
                             QCheckBox, QComboBox, QProgressBar, QTabWidget,
                             QGroupBox, QTableWidget, QTableWidgetItem, QListWidget,
                             QListWidgetItem, QSplitter, QGridLayout, QTreeWidget, 
                             QTreeWidgetItem, QLineEdit, QFileDialog, QMessageBox, 
                             QStatusBar, QScrollArea, QFrame, QSystemTrayIcon,
                             QMenu, QWizard, QWizardPage, QRadioButton,
                             QTextBrowser)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt, QSize
from PyQt6.QtGui import QFont, QBrush, QColor, QPalette, QPixmap, QIcon, QAction
import plistlib

def _get_app_data_dir():
    """Get a writable data directory that works both from source and .app bundle"""
    # Check if we're running inside a .app bundle (frozen by PyInstaller)
    if getattr(sys, 'frozen', False):
        # Running as .app — use macOS standard Application Support dir
        app_data = Path.home() / "Library" / "Application Support" / "StealthShark"
    else:
        # Running from source — use the script's own directory
        app_data = Path(__file__).resolve().parent
    app_data.mkdir(parents=True, exist_ok=True)
    return app_data

APP_DATA_DIR = _get_app_data_dir()

def _get_icon_path():
    """Get the shark logo path — works from source and from .app bundle"""
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).resolve().parent
    icon_path = base / "stealth-shark-logo.png"
    return str(icon_path) if icon_path.exists() else None

SHARK_ICON_PATH = _get_icon_path()

# Import monitoring components
from persistent_wireshark_monitor import PersistentWiresharkMonitor
import subprocess
import socket

class MultiInterfaceMonitorThread(QThread):
    """Enhanced thread for monitoring all network interfaces"""
    status_update = pyqtSignal(str)
    interface_data = pyqtSignal(dict)  # interface -> data
    interfaces_discovered = pyqtSignal(list)  # list of all discovered interfaces
    capture_started = pyqtSignal(str, str)  # interface, filename
    capture_finished = pyqtSignal(str, str)  # interface, filename
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, capture_dir=None, duration=3600):
        super().__init__()
        self.logger = logging.getLogger("MultiInterfaceThread")
        self.capture_dir = Path(capture_dir) if capture_dir else APP_DATA_DIR / "pcap_captures"
        self.duration = duration
        self.running = False
        self.monitor = None
        self.interface_stats = {}
        
    def run(self):
        """Run multi-interface monitoring"""
        try:
            self.running = True
            self.status_update.emit("🦈 Starting Multi-Interface Network Monitor...")
            
            # Create enhanced monitor with callback
            self.monitor = PersistentWiresharkMonitor(
                capture_dir=str(self.capture_dir),
                capture_duration=self.duration,
                alert_callback=self.handle_alert
            )
            
            self.status_update.emit("✅ Monitor initialized - Discovering interfaces...")
            
            # Discover interfaces first
            self.monitor.discover_interfaces()
            
            # Emit discovered interfaces for GUI initialization
            discovered = list(self.monitor.monitored_interfaces)
            self.interfaces_discovered.emit(discovered)
            self.status_update.emit(f"📡 Discovered {len(discovered)} interfaces: {', '.join(sorted(discovered))}")
            
            # Don't call monitor.run() as it blocks - instead do our own monitoring loop
            self.status_update.emit("🚀 Starting interface statistics monitoring...")
            
            # Monitor loop with stats updates
            iteration = 0
            while self.running:
                iteration += 1
                self.update_interface_stats()
                
                # Check for interface activity and start captures if needed
                if hasattr(self.monitor, 'detect_interface_activity'):
                    try:
                        active_interfaces = self.monitor.detect_interface_activity()
                        if active_interfaces:
                            self.status_update.emit(f"📊 Activity detected on: {', '.join(sorted(active_interfaces))}")
                            
                            # Start captures on active interfaces that aren't already capturing
                            for iface in active_interfaces:
                                if iface not in self.monitor.active_captures:
                                    self.monitor.start_capture(iface)
                                    capture_info = self.monitor.active_captures.get(iface, {})
                                    self.capture_started.emit(iface, capture_info.get('capture_filename', ''))
                    except Exception as e:
                        self.logger.debug(f"Activity detection error: {e}")
                
                # Fix #3: Retry interface discovery every ~60s if in fallback mode
                if hasattr(self.monitor, 'retry_interface_discovery'):
                    try:
                        self.monitor.retry_interface_discovery()
                    except Exception as e:
                        self.logger.debug(f"Discovery retry error: {e}")
                
                # Periodically archive old sessions and clean up (~every 3 minutes at 2s interval)
                if iteration % 100 == 0:
                    try:
                        if hasattr(self.monitor, 'archive_old_sessions'):
                            self.monitor.archive_old_sessions()
                        if hasattr(self.monitor, 'cleanup_old_captures'):
                            self.monitor.cleanup_old_captures()
                    except Exception as e:
                        self.logger.debug(f"Archive/cleanup error: {e}")
                
                time.sleep(2)  # Update every 2 seconds
                
        except Exception as e:
            self.logger.error(f"Monitor thread error: {e}")
            self.error_signal.emit(f"Monitor error: {str(e)}")
        finally:
            self.finished_signal.emit()
    
    def update_interface_stats(self):
        """Update statistics for all interfaces"""
        try:
            # Get current network stats
            net_io = psutil.net_io_counters(pernic=True)
            net_addrs = psutil.net_if_addrs()
            net_stats = psutil.net_if_stats()
            
            interface_data = {}
            
            # Get all interfaces (including those from monitor if available)
            all_interfaces = set(net_io.keys())
            if self.monitor and hasattr(self.monitor, 'monitored_interfaces'):
                all_interfaces.update(self.monitor.monitored_interfaces)
            
            for iface in all_interfaces:
                # Skip interfaces that don't have IO stats (like virtual/dump interfaces)
                if iface not in net_io:
                    continue
                    
                io_stats = net_io[iface]
                
                # Calculate rates if we have previous data
                if iface in self.interface_stats:
                    prev_stats = self.interface_stats[iface]
                    time_diff = time.time() - prev_stats['timestamp']
                    
                    if time_diff > 0:
                        bytes_sent_rate = (io_stats.bytes_sent - prev_stats['bytes_sent']) / time_diff
                        bytes_recv_rate = (io_stats.bytes_recv - prev_stats['bytes_recv']) / time_diff
                        packets_sent_rate = (io_stats.packets_sent - prev_stats['packets_sent']) / time_diff
                        packets_recv_rate = (io_stats.packets_recv - prev_stats['packets_recv']) / time_diff
                    else:
                        bytes_sent_rate = bytes_recv_rate = packets_sent_rate = packets_recv_rate = 0
                else:
                    bytes_sent_rate = bytes_recv_rate = packets_sent_rate = packets_recv_rate = 0
                
                # Get IP addresses
                ip_addresses = []
                if iface in net_addrs:
                    for addr in net_addrs[iface]:
                        if addr.family.name == 'AF_INET':
                            ip_addresses.append(addr.address)
                
                # Get interface status - check if interface exists and is up
                is_up = False
                if iface in net_stats:
                    is_up = net_stats[iface].isup
                elif iface in net_addrs:
                    # If we have addresses, assume it's up
                    is_up = len(ip_addresses) > 0
                
                interface_data[iface] = {
                    'bytes_sent': io_stats.bytes_sent,
                    'bytes_recv': io_stats.bytes_recv,
                    'packets_sent': io_stats.packets_sent,
                    'packets_recv': io_stats.packets_recv,
                    'bytes_sent_rate': bytes_sent_rate,
                    'bytes_recv_rate': bytes_recv_rate,
                    'packets_sent_rate': packets_sent_rate,
                    'packets_recv_rate': packets_recv_rate,
                    'ip_addresses': ip_addresses,
                    'is_up': is_up,
                    'has_activity': bytes_sent_rate > 0 or bytes_recv_rate > 0
                }
                
                # Store current stats for next calculation
                self.interface_stats[iface] = {
                    'bytes_sent': io_stats.bytes_sent,
                    'bytes_recv': io_stats.bytes_recv,
                    'packets_sent': io_stats.packets_sent,
                    'packets_recv': io_stats.packets_recv,
                    'timestamp': time.time()
                }
            
            # Emit interface data
            self.interface_data.emit(interface_data)
            
            # Debug logging
            active_count = sum(1 for data in interface_data.values() if data['is_up'])
            traffic_count = sum(1 for data in interface_data.values() if data['has_activity'])
            if len(interface_data) > 0:
                # Fix #6: Show fallback mode indicator in stats
                fallback_tag = ""
                if self.monitor and getattr(self.monitor, 'using_fallback', False):
                    monitored = len(self.monitor.monitored_interfaces) if self.monitor else '?'
                    fallback_tag = f" (⚠️ fallback mode, {monitored} monitored)"
                self.status_update.emit(f"📊 Stats: {len(interface_data)} interfaces, {active_count} up, {traffic_count} active{fallback_tag}")
            
        except Exception as e:
            self.logger.error(f"Stats update error: {e}")
    
    def handle_alert(self, message):
        """Handle monitoring alerts"""
        self.status_update.emit(f"🚨 ALERT: {message}")
    
    def stop_monitoring(self):
        """Stop monitoring gracefully"""
        self.running = False
        if self.monitor:
            self.monitor.shutdown()

class InterfaceMonitorWidget(QWidget):
    """Enhanced interface monitoring widget for all interfaces"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.interface_widgets = {}
        
    def setup_ui(self):
        """Setup the interface monitoring UI"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🌐 Network Interface Monitor")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_layout.addWidget(title)
        
        # Refresh button
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_interfaces)
        header_layout.addWidget(self.refresh_btn)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Scroll area for interfaces
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        self.interfaces_widget = QWidget()
        self.interfaces_layout = QVBoxLayout()
        self.interfaces_widget.setLayout(self.interfaces_layout)
        scroll.setWidget(self.interfaces_widget)
        
        layout.addWidget(scroll)
        self.setLayout(layout)
        
    def update_interface_data(self, interface_data):
        """Update interface data display"""
        # Get all known interfaces (including inactive ones)
        all_interfaces = set(interface_data.keys())
        
        # Add any missing interface widgets
        for iface in all_interfaces:
            if iface not in self.interface_widgets:
                self.create_interface_widget(iface)
        
        # Update all widgets with current data
        for iface, data in interface_data.items():
            widget = self.interface_widgets[iface]
            self.update_interface_widget(widget, iface, data)
        
        # Sort and reorder interfaces by activity status
        self.sort_interfaces_by_activity(interface_data)
    
    def initialize_all_interfaces(self, discovered_interfaces):
        """Initialize widgets for all discovered interfaces"""
        for iface in discovered_interfaces:
            if iface not in self.interface_widgets:
                self.create_interface_widget(iface)
                # Set initial inactive state
                default_data = {
                    'bytes_sent': 0, 'bytes_recv': 0,
                    'packets_sent': 0, 'packets_recv': 0,
                    'bytes_sent_rate': 0, 'bytes_recv_rate': 0,
                    'packets_sent_rate': 0, 'packets_recv_rate': 0,
                    'ip_addresses': [], 'is_up': False, 'has_activity': False
                }
                self.update_interface_widget(self.interface_widgets[iface], iface, default_data)
    
    def sort_interfaces_by_activity(self, interface_data):
        """Sort interfaces by activity status: Green (active) -> Yellow (idle) -> Red (down)"""
        try:
            # Create list of (interface_name, priority, widget) tuples
            interface_list = []
            
            for iface, widget in self.interface_widgets.items():
                # Get data for this interface (use default if not available)
                data = interface_data.get(iface, {
                    'is_up': False, 'has_activity': False
                })
                
                # Assign priority: 0 = Green (active), 1 = Yellow (idle), 2 = Red (down)
                if data.get('is_up', False) and data.get('has_activity', False):
                    priority = 0  # Green - Active
                elif data.get('is_up', False):
                    priority = 1  # Yellow - Idle
                else:
                    priority = 2  # Red - Down
                
                interface_list.append((iface, priority, widget))
            
            # Sort by priority, then by interface name for consistency
            interface_list.sort(key=lambda x: (x[1], x[0]))
            
            # Remove all widgets from layout
            for i in reversed(range(self.interfaces_layout.count())):
                child = self.interfaces_layout.itemAt(i).widget()
                if child:
                    self.interfaces_layout.removeWidget(child)
            
            # Re-add widgets in sorted order
            for iface, priority, widget in interface_list:
                self.interfaces_layout.addWidget(widget)
                
        except Exception as e:
            print(f"Error sorting interfaces: {e}")
    
    def create_interface_widget(self, interface_name):
        """Create widget for a specific interface"""
        # Main frame
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.Box)
        frame.setLineWidth(1)
        
        layout = QVBoxLayout()
        
        # Header with interface name and status
        header_layout = QHBoxLayout()
        
        name_label = QLabel(f"📡 {interface_name}")
        name_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        header_layout.addWidget(name_label)
        
        status_label = QLabel("●")
        status_label.setObjectName("status_indicator")
        header_layout.addWidget(status_label)
        
        header_layout.addStretch()
        
        # Activity indicator
        activity_label = QLabel("💤")
        activity_label.setObjectName("activity_indicator")
        header_layout.addWidget(activity_label)
        
        layout.addLayout(header_layout)
        
        # Stats grid
        stats_layout = QGridLayout()
        
        # IP Addresses
        ip_label = QLabel("IP:")
        ip_value = QLabel("N/A")
        ip_value.setObjectName("ip_addresses")
        stats_layout.addWidget(ip_label, 0, 0)
        stats_layout.addWidget(ip_value, 0, 1)
        
        # Bytes sent/received
        bytes_sent_label = QLabel("Sent:")
        bytes_sent_value = QLabel("0 B")
        bytes_sent_value.setObjectName("bytes_sent")
        stats_layout.addWidget(bytes_sent_label, 1, 0)
        stats_layout.addWidget(bytes_sent_value, 1, 1)
        
        bytes_recv_label = QLabel("Received:")
        bytes_recv_value = QLabel("0 B")
        bytes_recv_value.setObjectName("bytes_recv")
        stats_layout.addWidget(bytes_recv_label, 1, 2)
        stats_layout.addWidget(bytes_recv_value, 1, 3)
        
        # Packets sent/received
        packets_sent_label = QLabel("Packets Sent:")
        packets_sent_value = QLabel("0")
        packets_sent_value.setObjectName("packets_sent")
        stats_layout.addWidget(packets_sent_label, 2, 0)
        stats_layout.addWidget(packets_sent_value, 2, 1)
        
        packets_recv_label = QLabel("Packets Recv:")
        packets_recv_value = QLabel("0")
        packets_recv_value.setObjectName("packets_recv")
        stats_layout.addWidget(packets_recv_label, 2, 2)
        stats_layout.addWidget(packets_recv_value, 2, 3)
        
        # Rates
        rate_sent_label = QLabel("Send Rate:")
        rate_sent_value = QLabel("0 B/s")
        rate_sent_value.setObjectName("rate_sent")
        stats_layout.addWidget(rate_sent_label, 3, 0)
        stats_layout.addWidget(rate_sent_value, 3, 1)
        
        rate_recv_label = QLabel("Recv Rate:")
        rate_recv_value = QLabel("0 B/s")
        rate_recv_value.setObjectName("rate_recv")
        stats_layout.addWidget(rate_recv_label, 3, 2)
        stats_layout.addWidget(rate_recv_value, 3, 3)
        
        layout.addLayout(stats_layout)
        frame.setLayout(layout)
        
        # Store widget reference
        self.interface_widgets[interface_name] = frame
        self.interfaces_layout.addWidget(frame)
        
    def update_interface_widget(self, widget, interface_name, data):
        """Update specific interface widget with new data"""
        # Status indicator with enhanced color coding
        status_indicator = widget.findChild(QLabel, "status_indicator")
        if status_indicator:
            if data['is_up'] and data['has_activity']:
                status_indicator.setText("🟢")
                status_indicator.setToolTip("Interface UP - ACTIVE")
                status_indicator.setStyleSheet("color: #00ff00; font-weight: bold;")
            elif data['is_up']:
                status_indicator.setText("🟡")
                status_indicator.setToolTip("Interface UP - IDLE")
                status_indicator.setStyleSheet("color: #ffff00; font-weight: bold;")
            else:
                status_indicator.setText("🔴")
                status_indicator.setToolTip("Interface DOWN")
                status_indicator.setStyleSheet("color: #ff0000; font-weight: bold;")
        
        # Activity indicator
        activity_indicator = widget.findChild(QLabel, "activity_indicator")
        if activity_indicator:
            if data['has_activity']:
                activity_indicator.setText("📡")
                activity_indicator.setToolTip("Active traffic")
            else:
                activity_indicator.setText("💤")
                activity_indicator.setToolTip("No activity")
        
        # IP addresses
        ip_label = widget.findChild(QLabel, "ip_addresses")
        if ip_label:
            if data['ip_addresses']:
                ip_label.setText(", ".join(data['ip_addresses']))
            else:
                ip_label.setText("N/A")
        
        # Bytes
        bytes_sent_label = widget.findChild(QLabel, "bytes_sent")
        if bytes_sent_label:
            bytes_sent_label.setText(self.format_bytes(data['bytes_sent']))
            
        bytes_recv_label = widget.findChild(QLabel, "bytes_recv")
        if bytes_recv_label:
            bytes_recv_label.setText(self.format_bytes(data['bytes_recv']))
        
        # Packets
        packets_sent_label = widget.findChild(QLabel, "packets_sent")
        if packets_sent_label:
            packets_sent_label.setText(f"{data['packets_sent']:,}")
            
        packets_recv_label = widget.findChild(QLabel, "packets_recv")
        if packets_recv_label:
            packets_recv_label.setText(f"{data['packets_recv']:,}")
        
        # Rates
        rate_sent_label = widget.findChild(QLabel, "rate_sent")
        if rate_sent_label:
            rate_sent_label.setText(f"{self.format_bytes(data['bytes_sent_rate'])}/s")
            
        rate_recv_label = widget.findChild(QLabel, "rate_recv")
        if rate_recv_label:
            rate_recv_label.setText(f"{self.format_bytes(data['bytes_recv_rate'])}/s")
    
    def format_bytes(self, bytes_value):
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def refresh_interfaces(self):
        """Refresh interface list"""
        # Clear existing widgets
        for widget in self.interface_widgets.values():
            widget.setParent(None)
        self.interface_widgets.clear()

class OnboardingWizard(QWizard):
    """First-run onboarding wizard for beginners"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome to StealthShark")
        self.setFixedSize(660, 580)
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        
        if SHARK_ICON_PATH:
            self.setWindowIcon(QIcon(SHARK_ICON_PATH))
        
        self.addPage(self._welcome_page())
        self.addPage(self._permissions_page())
        self.addPage(self._settings_page())
        self.addPage(self._terms_page())
        self.addPage(self._finish_page())
        
        self.setStyleSheet("""
            QWizard { background-color: #1a1d27; }
            QWizardPage { background-color: #1a1d27; color: #e2e4f0; }
            QLabel { color: #e2e4f0; }
            QPushButton { background-color: #00d4ff; color: #0b0d14; border: none;
                          padding: 8px 20px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background-color: #33dfff; }
            QRadioButton { color: #e2e4f0; spacing: 8px; }
            QRadioButton::indicator { width: 16px; height: 16px; }
            QCheckBox { color: #e2e4f0; spacing: 8px; }
            QCheckBox::indicator { width: 16px; height: 16px; }
        """)
    
    def _welcome_page(self):
        page = QWizardPage()
        page.setTitle("Welcome to StealthShark")
        layout = QVBoxLayout()
        
        if SHARK_ICON_PATH:
            logo_pixmap = QPixmap(SHARK_ICON_PATH).scaled(
                120, 120, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
            icon = QLabel()
            icon.setPixmap(logo_pixmap)
        else:
            icon = QLabel("🦈")
            icon.setFont(QFont("Arial", 48))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)
        
        title = QLabel("Silent Network Monitoring")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #00d4ff; margin-bottom: 12px;")
        layout.addWidget(title)
        
        desc = QLabel(
            "StealthShark monitors your network in the background with\n"
            "near-zero resource usage. Captures are compressed in real-time\n"
            "and organized automatically.\n\n"
            "This wizard will help you set everything up in under a minute."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color: #8b8fa8; font-size: 14px; line-height: 1.6;")
        layout.addWidget(desc)
        
        layout.addStretch()
        page.setLayout(layout)
        return page
    
    def _permissions_page(self):
        page = QWizardPage()
        page.setTitle("Capture Permissions")
        layout = QVBoxLayout()
        
        info = QLabel(
            "StealthShark needs permission to capture network traffic.\n"
            "This uses the same method as Wireshark (BPF device access)."
        )
        info.setStyleSheet("color: #8b8fa8; font-size: 13px; margin-bottom: 12px;")
        info.setWordWrap(True)
        layout.addWidget(info)
        
        # Disclosure box — explain exactly what will happen
        disclosure = QLabel(
            "What this does:\n"
            "• Creates an 'access_bpf' group (if it doesn't exist)\n"
            "• Adds your user account to that group\n"
            "• Sets group-read permission on /dev/bpf* devices\n"
            "• Only members of this group can capture packets\n"
            "• No data leaves your machine — this is local only\n"
            "• Permissions reset on reboot (macOS security feature)"
        )
        disclosure.setStyleSheet(
            "color: #8b8fa8; font-size: 12px; padding: 12px; "
            "background-color: rgba(0,212,255,0.05); border: 1px solid rgba(0,212,255,0.15); "
            "border-radius: 8px; margin-bottom: 12px;")
        disclosure.setWordWrap(True)
        layout.addWidget(disclosure)
        
        # Permission status
        self.perm_status = QLabel()
        self.perm_status.setStyleSheet("font-size: 14px; padding: 12px; border-radius: 8px;")
        layout.addWidget(self.perm_status)
        
        self.grant_btn = QPushButton("🔐 Grant Capture Permission")
        self.grant_btn.setFixedHeight(44)
        self.grant_btn.clicked.connect(self._grant_permissions)
        layout.addWidget(self.grant_btn)
        
        note = QLabel(
            "You will see a macOS password prompt. This is required to modify\n"
            "device permissions. StealthShark never stores your password."
        )
        note.setStyleSheet("color: #6a7080; font-size: 12px; margin-top: 8px;")
        note.setWordWrap(True)
        layout.addWidget(note)
        
        layout.addStretch()
        page.setLayout(layout)
        
        # Check permissions on page show
        QTimer.singleShot(100, self._check_permissions)
        return page
    
    def _check_permissions(self):
        """Check if tcpdump capture works without sudo"""
        try:
            result = subprocess.run(
                ['tcpdump', '-i', 'en0', '-c', '0'],
                capture_output=True, timeout=3
            )
            if result.returncode == 0:
                self.perm_status.setText("✅ Permissions already granted — you're all set!")
                self.perm_status.setStyleSheet(
                    "font-size: 14px; padding: 12px; border-radius: 8px; "
                    "background-color: rgba(0,230,118,0.1); color: #00e676;")
                self.grant_btn.setText("✅ Already Configured")
                self.grant_btn.setEnabled(False)
            else:
                self._show_needs_permission()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._show_needs_permission()
    
    def _show_needs_permission(self):
        self.perm_status.setText("⚠️ Capture permission needed — click the button below")
        self.perm_status.setStyleSheet(
            "font-size: 14px; padding: 12px; border-radius: 8px; "
            "background-color: rgba(255,171,64,0.1); color: #ffab40;")
    
    def _grant_permissions(self):
        """Grant BPF capture permissions using the access_bpf group method (same as Wireshark ChmodBPF)"""
        try:
            username = os.environ.get('USER', subprocess.check_output(['whoami']).decode().strip())
            # Sanitize username to prevent shell injection in osascript
            if not re.match(r'^[a-zA-Z0-9._-]+$', username):
                self.perm_status.setText("⚠️ Invalid username detected — cannot set permissions automatically.")
                self.perm_status.setStyleSheet(
                    "font-size: 14px; padding: 12px; border-radius: 8px; "
                    "background-color: rgba(255,82,82,0.1); color: #ff5252;")
                return
            
            # Secure approach: create access_bpf group, add user, set group-read on BPF devices
            # This is the same method Wireshark's ChmodBPF installer uses
            commands = (
                # Create access_bpf group if it doesn't exist
                '/usr/sbin/dseditgroup -o read access_bpf 2>/dev/null || '
                '/usr/sbin/dseditgroup -o create access_bpf; '
                # Add current user to the group
                f'/usr/sbin/dseditgroup -o edit -a {username} -t user access_bpf; '
                # Set BPF devices to group access_bpf with group-read (not world-read)
                'chgrp access_bpf /dev/bpf*; '
                'chmod g+r /dev/bpf*'
            )
            
            # Use osascript for a native macOS admin password prompt
            script = (
                'do shell script '
                f'"{commands}" '
                'with administrator privileges'
            )
            
            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True, timeout=60
            )
            
            if result.returncode == 0:
                # Log the permission grant for audit trail
                log_dir = APP_DATA_DIR / "gui_logs"
                log_dir.mkdir(parents=True, exist_ok=True)
                audit_file = log_dir / "permission_audit.log"
                with open(audit_file, 'a') as f:
                    f.write(f"{datetime.now().isoformat()} | GRANTED | "
                            f"user={username} | method=access_bpf_group | "
                            f"action=chgrp+chmod_g+r_/dev/bpf*\n")
                
                self.perm_status.setText("✅ Permissions granted! You're in the access_bpf group.")
                self.perm_status.setStyleSheet(
                    "font-size: 14px; padding: 12px; border-radius: 8px; "
                    "background-color: rgba(0,230,118,0.1); color: #00e676;")
                self.grant_btn.setText("✅ Done")
                self.grant_btn.setEnabled(False)
            else:
                stderr = result.stderr.decode().strip() if result.stderr else ''
                # Log the denial
                log_dir = APP_DATA_DIR / "gui_logs"
                log_dir.mkdir(parents=True, exist_ok=True)
                audit_file = log_dir / "permission_audit.log"
                with open(audit_file, 'a') as f:
                    f.write(f"{datetime.now().isoformat()} | DENIED | "
                            f"user={username} | error={stderr[:100]}\n")
                
                self.perm_status.setText("❌ Permission was denied. You can still run with sudo later.")
                self.perm_status.setStyleSheet(
                    "font-size: 14px; padding: 12px; border-radius: 8px; "
                    "background-color: rgba(255,82,82,0.1); color: #ff5252;")
        except subprocess.TimeoutExpired:
            self.perm_status.setText("⏱️ Timed out — you can grant permissions later.")
            self.perm_status.setStyleSheet(
                "font-size: 14px; padding: 12px; border-radius: 8px; "
                "background-color: rgba(255,171,64,0.1); color: #ffab40;")
        except Exception as e:
            self.perm_status.setText(f"⚠️ Could not set permissions: {str(e)[:60]}")
    
    def _settings_page(self):
        page = QWizardPage()
        page.setTitle("Quick Settings")
        layout = QVBoxLayout()
        
        info = QLabel("Choose how StealthShark should run:")
        info.setStyleSheet("color: #8b8fa8; font-size: 13px; margin-bottom: 20px;")
        layout.addWidget(info)
        
        # Auto-start checkbox
        self.autostart_check = QCheckBox("Start StealthShark when I log in")
        self.autostart_check.setStyleSheet("font-size: 14px; padding: 8px;")
        self.autostart_check.setChecked(True)
        layout.addWidget(self.autostart_check)
        
        autostart_note = QLabel("    Runs silently in the menu bar — no window pops up")
        autostart_note.setStyleSheet("color: #6a7080; font-size: 12px; margin-bottom: 16px;")
        layout.addWidget(autostart_note)
        
        # Minimize to tray checkbox
        self.tray_check = QCheckBox("Minimize to menu bar when I close the window")
        self.tray_check.setStyleSheet("font-size: 14px; padding: 8px;")
        self.tray_check.setChecked(True)
        layout.addWidget(self.tray_check)
        
        tray_note = QLabel("    StealthShark keeps capturing in the background")
        tray_note.setStyleSheet("color: #6a7080; font-size: 12px; margin-bottom: 16px;")
        layout.addWidget(tray_note)
        
        # Auto-capture checkbox
        self.autocapture_check = QCheckBox("Automatically start capturing when launched")
        self.autocapture_check.setStyleSheet("font-size: 14px; padding: 8px;")
        self.autocapture_check.setChecked(True)
        layout.addWidget(self.autocapture_check)
        
        autocapture_note = QLabel("    Begin monitoring all interfaces immediately — no clicks needed")
        autocapture_note.setStyleSheet("color: #6a7080; font-size: 12px;")
        layout.addWidget(autocapture_note)
        
        layout.addStretch()
        page.setLayout(layout)
        return page
    
    def _terms_page(self):
        page = QWizardPage()
        page.setTitle("Terms of Use & Legal")
        layout = QVBoxLayout()
        
        intro = QLabel("Please review and accept the terms before continuing:")
        intro.setStyleSheet("color: #8b8fa8; font-size: 13px; margin-bottom: 8px;")
        layout.addWidget(intro)
        
        terms_text = QTextBrowser()
        terms_text.setOpenExternalLinks(True)
        terms_text.setStyleSheet(
            "background-color: #12141c; color: #c0c4d8; border: 1px solid #2a2d3a; "
            "border-radius: 6px; padding: 10px; font-size: 12px;")
        terms_text.setHtml("""
        <h3 style="color:#00d4ff;">StealthShark — Terms of Use</h3>
        <p style="color:#8b8fa8;"><b>Effective Date:</b> February 2026 &nbsp;|&nbsp; <b>Version:</b> 2.1.0</p>
        <hr style="border-color:#2a2d3a;">

        <h4 style="color:#e2e4f0;">1. Open Source License</h4>
        <p>StealthShark is open-source software distributed under the
        <b>GNU General Public License v3.0 (GPL-3.0)</b>. You are free to use,
        study, modify, and distribute this software under the terms of the GPL-3.0.
        Any derivative works must also be distributed under the same license.
        The full license text is available at
        <a href="https://github.com/aimarketingflow/stealthshark/blob/main/LICENSE" style="color:#00d4ff;">our GitHub repository</a>.</p>

        <h4 style="color:#e2e4f0;">2. Disclaimer of Warranty</h4>
        <p>THE SOFTWARE IS PROVIDED <b>"AS IS"</b>, WITHOUT WARRANTY OF ANY KIND,
        EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        The authors and copyright holders make no guarantees regarding the
        accuracy, reliability, completeness, or suitability of this software
        for any particular purpose.</p>

        <h4 style="color:#e2e4f0;">3. Limitation of Liability</h4>
        <p>IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS
        BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN
        ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN
        CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
        SOFTWARE. This includes but is not limited to:</p>
        <ul>
            <li>Data loss or corruption</li>
            <li>Security breaches or unauthorized access</li>
            <li>System performance degradation</li>
            <li>Network disruption or interference</li>
            <li>Any indirect, incidental, special, or consequential damages</li>
        </ul>

        <h4 style="color:#e2e4f0;">4. Lawful Use Only</h4>
        <p>You agree to use StealthShark <b>only on networks and devices you own
        or have explicit authorization to monitor</b>. Unauthorized interception
        of network traffic may violate federal and state laws, including but not
        limited to the <b>Computer Fraud and Abuse Act (CFAA)</b>, the
        <b>Wiretap Act (18 U.S.C. &sect; 2511)</b>, and equivalent laws in your
        jurisdiction. <b>You are solely responsible</b> for ensuring your use of
        this software complies with all applicable laws and regulations.</p>

        <h4 style="color:#e2e4f0;">5. No Professional Advice</h4>
        <p>StealthShark is a network monitoring tool and does not constitute
        professional security, legal, or compliance advice. Consult qualified
        professionals for security audits, legal compliance, or regulatory
        requirements.</p>

        <h4 style="color:#e2e4f0;">6. Data Responsibility</h4>
        <p>All captured network data is stored <b>locally on your device</b>.
        StealthShark does not transmit any data to external servers. You are
        solely responsible for the security, storage, handling, and lawful
        use of any captured data. You should ensure captured data is stored
        securely and disposed of in accordance with applicable data protection
        laws (e.g., GDPR, CCPA).</p>

        <h4 style="color:#e2e4f0;">7. Indemnification</h4>
        <p>You agree to indemnify, defend, and hold harmless the authors,
        contributors, and AI Marketing Flow from and against any claims,
        liabilities, damages, losses, and expenses (including reasonable
        attorney fees) arising out of or in any way connected with your
        use or misuse of this software.</p>

        <h4 style="color:#e2e4f0;">8. Modifications</h4>
        <p>These terms may be updated with new versions of the software.
        Continued use after updates constitutes acceptance of revised terms.</p>

        <p style="color:#6a7080; margin-top: 16px;"><em>&copy; 2026 AI Marketing Flow.
        All rights reserved.</em></p>
        """)
        layout.addWidget(terms_text)
        
        # Accept checkbox — required to proceed
        self.accept_check = QCheckBox("I have read and agree to the Terms of Use")
        self.accept_check.setStyleSheet("font-size: 13px; padding: 8px; color: #e2e4f0;")
        self.accept_check.toggled.connect(lambda checked: page.completeChanged.emit())
        layout.addWidget(self.accept_check)
        
        page.setLayout(layout)
        page.isComplete = lambda: self.accept_check.isChecked()
        return page
    
    def _finish_page(self):
        page = QWizardPage()
        page.setTitle("You're All Set!")
        layout = QVBoxLayout()
        
        icon = QLabel("🎉")
        icon.setFont(QFont("Arial", 48))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)
        
        title = QLabel("StealthShark is Ready")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #00e676; margin-bottom: 16px;")
        layout.addWidget(title)
        
        desc = QLabel(
            "Click Finish to start monitoring.\n\n"
            "🦈  Look for the shark icon in your menu bar\n"
            "📊  Click it anytime to see stats and captures\n"
            "🗜️  All captures are compressed automatically\n"
            "📦  Old sessions are archived and cleaned up\n\n"
            "StealthShark runs silently — you don't need to do anything else."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color: #8b8fa8; font-size: 14px; line-height: 1.7;")
        layout.addWidget(desc)
        
        layout.addStretch()
        page.setLayout(layout)
        return page
    
    def get_settings(self):
        """Return the user's chosen settings"""
        return {
            'autostart': self.autostart_check.isChecked(),
            'minimize_to_tray': self.tray_check.isChecked(),
            'auto_capture': self.autocapture_check.isChecked(),
        }


class MultiInterfaceSharkGUI(QMainWindow):
    """Main Multi-Interface Shark GUI"""
    
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.auto_save_timer = None
        self.tray_icon = None
        self.minimize_to_tray = True
        self.auto_capture = True
        self.session_state_file = APP_DATA_DIR / "gui_logs" / "session_state.json"
        self.prefs_file = APP_DATA_DIR / "gui_logs" / "stealthshark_prefs.json"
        self.setup_logging()
        self._load_prefs()
        self._run_onboarding_if_needed()
        self.setup_ui()
        self._setup_system_tray()
        self.apply_dark_theme()
        self.setup_auto_save()
        self.setup_crash_protection()
        
        # Auto-start capture if enabled
        if self.auto_capture:
            QTimer.singleShot(500, self.start_monitoring)
        
    def setup_logging(self):
        """Setup verbose logging"""
        log_dir = APP_DATA_DIR / "gui_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"multi_interface_gui_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("MultiInterfaceGUI")
        self.logger.info("Multi-Interface Shark GUI logging initialized")
    
    def _load_prefs(self):
        """Load user preferences from disk"""
        try:
            if self.prefs_file.exists():
                with open(self.prefs_file, 'r') as f:
                    prefs = json.load(f)
                self.minimize_to_tray = prefs.get('minimize_to_tray', True)
                self.auto_capture = prefs.get('auto_capture', True)
                self.logger.info("Preferences loaded")
        except Exception as e:
            self.logger.warning(f"Could not load prefs: {e}")
    
    def _save_prefs(self, prefs):
        """Save user preferences to disk"""
        try:
            self.prefs_file.parent.mkdir(exist_ok=True)
            with open(self.prefs_file, 'w') as f:
                json.dump(prefs, f, indent=2)
            self.logger.info("Preferences saved")
        except Exception as e:
            self.logger.warning(f"Could not save prefs: {e}")
    
    def _run_onboarding_if_needed(self):
        """Show the onboarding wizard on first run"""
        if self.prefs_file.exists():
            return  # Already onboarded
        
        self.logger.info("First run detected — launching onboarding wizard")
        wizard = OnboardingWizard()
        result = wizard.exec()
        
        if result == QWizard.DialogCode.Accepted:
            settings = wizard.get_settings()
            self.minimize_to_tray = settings['minimize_to_tray']
            self.auto_capture = settings['auto_capture']
            
            # Save preferences
            self._save_prefs(settings)
            
            # Setup auto-start on login if requested
            if settings['autostart']:
                self._install_login_item()
            
            self.logger.info(f"Onboarding complete: {settings}")
        else:
            # User cancelled — save defaults so wizard doesn't show again
            self._save_prefs({
                'minimize_to_tray': True,
                'auto_capture': False,
                'autostart': False,
            })
            self.auto_capture = False
    
    def _setup_system_tray(self):
        """Setup the system tray / menu bar icon"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.logger.warning("System tray not available")
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        
        # Use shark logo for tray icon, blue square as fallback
        if SHARK_ICON_PATH:
            self.tray_icon.setIcon(QIcon(SHARK_ICON_PATH))
        else:
            pixmap = QPixmap(32, 32)
            pixmap.fill(QColor(0, 212, 255))
            self.tray_icon.setIcon(QIcon(pixmap))
        self.tray_icon.setToolTip("StealthShark — Network Monitor")
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("🦈 Show StealthShark", self)
        show_action.triggered.connect(self._show_window)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        self.tray_status_action = QAction("⏸️ Not monitoring", self)
        self.tray_status_action.setEnabled(False)
        tray_menu.addAction(self.tray_status_action)
        
        tray_menu.addSeparator()
        
        start_action = QAction("▶️ Start Monitoring", self)
        start_action.triggered.connect(self.start_monitoring)
        tray_menu.addAction(start_action)
        
        stop_action = QAction("⏹️ Stop Monitoring", self)
        stop_action.triggered.connect(self.stop_monitoring)
        tray_menu.addAction(stop_action)
        
        tray_menu.addSeparator()
        
        integrity_action = QAction("🔒 Verify Integrity", self)
        integrity_action.triggered.connect(self._verify_integrity)
        tray_menu.addAction(integrity_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("❌ Quit StealthShark", self)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._tray_activated)
        self.tray_icon.show()
        
        self.logger.info("System tray icon initialized")
    
    def _tray_activated(self, reason):
        """Handle tray icon click"""
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._toggle_window()
    
    def _toggle_window(self):
        """Toggle main window visibility"""
        if self.isVisible():
            self.hide()
        else:
            self._show_window()
    
    def _show_window(self):
        """Show and raise the main window"""
        self.show()
        self.raise_()
        self.activateWindow()
    
    def _verify_integrity(self):
        """Verify SHA-256 hashes of source files against the bundled manifest"""
        try:
            # Locate the manifest inside the bundle or source dir
            if getattr(sys, 'frozen', False):
                base = Path(sys._MEIPASS)
            else:
                base = Path(__file__).resolve().parent
            manifest = base / "INTEGRITY_HASHES.sha256"
            
            if not manifest.exists():
                QMessageBox.warning(self, "Integrity Check",
                    "⚠️ Hash manifest not found.\nCannot verify integrity.")
                return
            
            total = 0
            passed = 0
            failed = 0
            missing = 0
            tampered = []
            
            self.logger.info("🔒 Starting integrity verification...")
            self.statusBar().showMessage("🔒 Verifying file integrity...")
            
            for line in manifest.read_text().splitlines():
                line = line.strip()
                if not line or 'git commit' in line:
                    continue
                parts = line.split('  ', 1)
                if len(parts) != 2 or len(parts[0]) != 64:
                    continue
                
                expected_hash, file_path = parts
                total += 1
                target = base / file_path
                
                if not target.exists():
                    # Some files won't be in the bundle — skip non-critical ones
                    if file_path.endswith(('.py', '.sh')):
                        # Core files that should be present
                        if target.name in ('multi_interface_shark_gui.py',
                                          'persistent_wireshark_monitor.py'):
                            missing += 1
                            tampered.append(f"⚠️ MISSING: {file_path}")
                    # Non-core files (docs, tests) are expected to be absent in bundle
                    continue
                
                sha256 = hashlib.sha256()
                sha256.update(target.read_bytes())
                actual_hash = sha256.hexdigest()
                
                if actual_hash == expected_hash:
                    passed += 1
                else:
                    failed += 1
                    tampered.append(f"🚨 TAMPERED: {file_path}")
                    self.logger.warning(f"Integrity mismatch: {file_path}")
            
            # Build result message
            if failed == 0 and missing == 0:
                icon = QMessageBox.Icon.Information
                title = "✅ Integrity Check Passed"
                msg = (f"All {passed} verifiable files match their expected hashes.\n\n"
                       f"No tampering detected.\n"
                       f"Total in manifest: {total}")
                self.logger.info(f"✅ Integrity check passed: {passed}/{total} verified")
            else:
                icon = QMessageBox.Icon.Critical
                title = "🚨 Integrity Check FAILED"
                details = "\n".join(tampered)
                msg = (f"Tampering detected!\n\n"
                       f"Passed: {passed}\n"
                       f"Failed: {failed}\n"
                       f"Missing: {missing}\n\n"
                       f"{details}")
                self.logger.error(f"🚨 Integrity check FAILED: {failed} tampered, {missing} missing")
            
            self.statusBar().showMessage(f"Integrity: {passed} passed, {failed} failed, {missing} missing")
            
            box = QMessageBox(self)
            box.setIcon(icon)
            box.setWindowTitle(title)
            box.setText(msg)
            box.exec()
            
        except Exception as e:
            self.logger.error(f"Integrity check error: {e}")
            QMessageBox.critical(self, "Integrity Check Error",
                f"Error during verification:\n{e}")
    
    def _quit_app(self):
        """Actually quit the application (not just minimize)"""
        self.minimize_to_tray = False  # Prevent closeEvent from hiding
        self.close()
        QApplication.quit()
    
    def _install_login_item(self):
        """Install a macOS Launch Agent so StealthShark starts on login"""
        try:
            launch_agents_dir = Path.home() / "Library" / "LaunchAgents"
            launch_agents_dir.mkdir(parents=True, exist_ok=True)
            plist_path = launch_agents_dir / "com.aimf.stealthshark.plist"
            
            # Determine the executable path
            app_path = Path("/Applications/StealthShark.app/Contents/MacOS/StealthShark")
            if not app_path.exists():
                # Fallback to source launch
                app_path = None
            
            if app_path:
                program_args = [str(app_path)]
            else:
                python_path = sys.executable
                script_path = str(Path(__file__).resolve())
                program_args = [python_path, script_path]
            
            plist_data = {
                'Label': 'com.aimf.stealthshark',
                'ProgramArguments': program_args,
                'RunAtLoad': True,
                'KeepAlive': False,
                'ProcessType': 'Interactive',
                'StandardOutPath': str(Path.home() / 'Library' / 'Logs' / 'stealthshark_stdout.log'),
                'StandardErrorPath': str(Path.home() / 'Library' / 'Logs' / 'stealthshark_stderr.log'),
            }
            
            with open(plist_path, 'wb') as f:
                plistlib.dump(plist_data, f)
            
            self.logger.info(f"Login item installed: {plist_path}")
        except Exception as e:
            self.logger.warning(f"Could not install login item: {e}")
    
    def _remove_login_item(self):
        """Remove the macOS Launch Agent"""
        try:
            plist_path = Path.home() / "Library" / "LaunchAgents" / "com.aimf.stealthshark.plist"
            if plist_path.exists():
                plist_path.unlink()
                self.logger.info("Login item removed")
        except Exception as e:
            self.logger.warning(f"Could not remove login item: {e}")
        
    def setup_auto_save(self):
        """Setup automatic session state saving"""
        self.auto_save_timer = QTimer()
        self.auto_save_timer.timeout.connect(self.save_session_state)
        self.auto_save_timer.start(30000)  # Save every 30 seconds
        self.logger.info("Auto-save enabled: saving session state every 30 seconds")
        
    def setup_crash_protection(self):
        """Setup crash protection and recovery"""
        # Check for previous session recovery
        if self.session_state_file.exists():
            try:
                with open(self.session_state_file, 'r') as f:
                    previous_state = json.load(f)
                
                if previous_state.get('was_monitoring', False):
                    reply = QMessageBox.question(
                        self, "Session Recovery",
                        "Previous monitoring session detected. Would you like to restore settings?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    
                    if reply == QMessageBox.StandardButton.Yes:
                        self.restore_session_state(previous_state)
                        
            except Exception as e:
                self.logger.error(f"Failed to load previous session: {e}")
        
        # Setup signal handlers for graceful shutdown
        import signal
        signal.signal(signal.SIGINT, self.emergency_shutdown)
        signal.signal(signal.SIGTERM, self.emergency_shutdown)
        
    def save_session_state(self):
        """Save current session state for crash recovery"""
        try:
            state = {
                'timestamp': datetime.now().isoformat(),
                'was_monitoring': self.monitor_thread is not None and self.monitor_thread.isRunning(),
                'capture_directory': self.dir_edit.text(),
                'duration_hours': self.hours_spin.value(),
                'duration_minutes': self.minutes_spin.value(),
                'window_geometry': {
                    'x': self.x(),
                    'y': self.y(),
                    'width': self.width(),
                    'height': self.height()
                }
            }
            
            # Ensure directory exists
            self.session_state_file.parent.mkdir(exist_ok=True)
            
            with open(self.session_state_file, 'w') as f:
                json.dump(state, f, indent=2)
                
            self.logger.debug("Session state saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save session state: {e}")
            
    def restore_session_state(self, state):
        """Restore session state from previous session"""
        try:
            # Restore settings
            if 'capture_directory' in state:
                self.dir_edit.setText(state['capture_directory'])
            if 'duration_hours' in state:
                self.hours_spin.setValue(state['duration_hours'])
            if 'duration_minutes' in state:
                self.minutes_spin.setValue(state['duration_minutes'])
                
            # Restore window geometry
            if 'window_geometry' in state:
                geom = state['window_geometry']
                self.setGeometry(geom['x'], geom['y'], geom['width'], geom['height'])
                
            self.log_message("🔄 Session restored from previous crash/shutdown")
            self.logger.info("Session state restored successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to restore session state: {e}")
            
    def emergency_shutdown(self, signum=None, frame=None):
        """Handle emergency shutdown signals"""
        self.logger.warning(f"Emergency shutdown triggered (signal: {signum})")
        self.save_session_state()
        
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.logger.info("Stopping monitoring thread for emergency shutdown...")
            self.stop_monitoring()
            
        # Force save one more time
        self.save_session_state()
        self.logger.info("Emergency shutdown complete")
        
        if signum:
            sys.exit(0)
        
    def setup_ui(self):
        """Setup the main user interface"""
        self.setWindowTitle("🦈 Multi-Interface Shark - All Network Monitoring")
        if SHARK_ICON_PATH:
            self.setWindowIcon(QIcon(SHARK_ICON_PATH))
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Interface monitoring tab
        self.interface_widget = InterfaceMonitorWidget()
        self.tab_widget.addTab(self.interface_widget, "🌐 All Interfaces")
        
        # Log tab
        log_widget = QWidget()
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 10))
        log_layout.addWidget(self.log_text)
        log_widget.setLayout(log_layout)
        self.tab_widget.addTab(log_widget, "📋 Monitor Log")
        
        # Capture files tab
        files_widget = QWidget()
        files_layout = QVBoxLayout()
        self.files_list = QListWidget()
        files_layout.addWidget(QLabel("📁 Captured Files:"))
        files_layout.addWidget(self.files_list)
        refresh_btn = QPushButton("🔄 Refresh Files")
        refresh_btn.clicked.connect(self.refresh_capture_files)
        files_layout.addWidget(refresh_btn)
        files_widget.setLayout(files_layout)
        self.tab_widget.addTab(files_widget, "📁 Captures")
        
        main_layout.addWidget(self.tab_widget)
        
        # Status bar
        self.statusBar().showMessage("Ready - Multi-Interface Network Monitor")
        
    def create_control_panel(self):
        """Create the control panel"""
        panel = QGroupBox("🎛️ Monitor Controls")
        layout = QHBoxLayout()
        
        # Start/Stop buttons
        self.start_btn = QPushButton("🚀 Start All Interface Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn = QPushButton("⏹️ Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        
        # Duration setting - Hours and Minutes
        duration_group = QHBoxLayout()
        duration_group.addWidget(QLabel("Duration:"))
        
        # Hours
        self.hours_spin = QSpinBox()
        self.hours_spin.setRange(0, 24)  # 0 to 24 hours
        self.hours_spin.setValue(6)  # Default 6 hours
        self.hours_spin.setSuffix(" hrs")
        duration_group.addWidget(self.hours_spin)
        
        # Minutes
        self.minutes_spin = QSpinBox()
        self.minutes_spin.setRange(0, 59)  # 0 to 59 minutes
        self.minutes_spin.setValue(0)  # Default 0 minutes
        self.minutes_spin.setSuffix(" min")
        duration_group.addWidget(self.minutes_spin)
        
        layout.addLayout(duration_group)
        
        # Capture directory
        layout.addWidget(QLabel("Capture Dir:"))
        self.dir_edit = QLineEdit(str(APP_DATA_DIR / "pcap_captures"))
        layout.addWidget(self.dir_edit)
        
        dir_btn = QPushButton("📂 Browse")
        dir_btn.clicked.connect(self.browse_directory)
        layout.addWidget(dir_btn)
        
        layout.addStretch()
        
        panel.setLayout(layout)
        return panel
        
    def start_monitoring(self):
        """Start multi-interface monitoring"""
        try:
            self.log_message("🦈 Starting Multi-Interface Network Monitor...")
            
            # Create directories
            capture_dir = Path(self.dir_edit.text())
            capture_dir.mkdir(parents=True, exist_ok=True)
            (capture_dir / "logs").mkdir(exist_ok=True)
            
            # Calculate total duration in seconds from hours and minutes
            total_hours = self.hours_spin.value()
            total_minutes = self.minutes_spin.value()
            duration_seconds = (total_hours * 3600) + (total_minutes * 60)
            
            # Minimum duration check
            if duration_seconds < 60:
                duration_seconds = 60  # Minimum 1 minute
                
            self.monitor_thread = MultiInterfaceMonitorThread(
                capture_dir=str(capture_dir),
                duration=duration_seconds
            )
            
            self.log_message(f"📅 Monitoring duration set to: {total_hours}h {total_minutes}m ({duration_seconds}s)")
            
            # Connect signals
            self.monitor_thread.status_update.connect(self.log_message)
            self.monitor_thread.interface_data.connect(self.interface_widget.update_interface_data)
            self.monitor_thread.interfaces_discovered.connect(self.interface_widget.initialize_all_interfaces)
            self.monitor_thread.error_signal.connect(self.handle_error)
            self.monitor_thread.finished_signal.connect(self.monitoring_finished)
            
            # Start thread
            self.monitor_thread.start()
            
            # Update UI
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.statusBar().showMessage("🟢 Monitoring ALL Network Interfaces")
            
            # Update tray icon status
            if self.tray_icon and hasattr(self, 'tray_status_action'):
                self.tray_status_action.setText("🟢 Monitoring active")
                self.tray_icon.setToolTip("StealthShark — Monitoring active")
            
            self.log_message("✅ Multi-interface monitoring started successfully!")
            
        except Exception as e:
            self.handle_error(f"Failed to start monitoring: {str(e)}")
            
    def stop_monitoring(self):
        """Stop monitoring"""
        if self.monitor_thread:
            self.log_message("⏹️ Stopping multi-interface monitor...")
            self.monitor_thread.stop_monitoring()
            self.monitor_thread.quit()
            self.monitor_thread.wait()
            
        self.monitoring_finished()
        
    def monitoring_finished(self):
        """Handle monitoring finished"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("⏸️ Monitoring Stopped")
        
        # Update tray icon status
        if self.tray_icon and hasattr(self, 'tray_status_action'):
            self.tray_status_action.setText("⏸️ Not monitoring")
            self.tray_icon.setToolTip("StealthShark — Stopped")
        
        self.log_message("🛑 Multi-interface monitoring stopped.")
        
    def log_message(self, message):
        """Add message to log display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.append(formatted_message)
        self.logger.info(message)
        
    def handle_error(self, error_message):
        """Handle error messages"""
        self.log_message(f"❌ ERROR: {error_message}")
        QMessageBox.critical(self, "Error", error_message)
        
    def browse_directory(self):
        """Browse for capture directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Capture Directory")
        if directory:
            self.dir_edit.setText(directory)
            
    def refresh_capture_files(self):
        """Refresh capture files list with detailed information"""
        self.files_list.clear()
        capture_dir = Path(self.dir_edit.text())
        
        if capture_dir.exists():
            # Get all PCAP files and organize by session
            sessions = {}
            total_size = 0
            
            for pcap_file in list(capture_dir.rglob("*.pcap")) + list(capture_dir.rglob("*.pcap.gz")):
                file_size = pcap_file.stat().st_size
                total_size += file_size
                
                # Extract session info from path
                parts = pcap_file.parts
                if 'session_' in str(pcap_file):
                    # Find session directory
                    session_name = None
                    interface_group = None
                    for part in parts:
                        if part.startswith('session_'):
                            session_name = part
                        elif session_name and part != pcap_file.name:
                            interface_group = part
                    
                    if session_name:
                        if session_name not in sessions:
                            sessions[session_name] = []
                        sessions[session_name].append({
                            'file': pcap_file,
                            'size': file_size,
                            'group': interface_group or 'unknown',
                            'name': pcap_file.name
                        })
                else:
                    # Standalone file
                    if 'standalone' not in sessions:
                        sessions['standalone'] = []
                    sessions['standalone'].append({
                        'file': pcap_file,
                        'size': file_size,
                        'group': 'standalone',
                        'name': pcap_file.name
                    })
            
            # Add summary
            all_pcaps = list(capture_dir.rglob('*.pcap')) + list(capture_dir.rglob('*.pcap.gz'))
            self.files_list.addItem(f"📊 TOTAL: {len(all_pcaps)} files, {total_size / (1024*1024):.1f} MB")
            
            # Show archived sessions
            archives = list(capture_dir.glob('session_*.tar.gz'))
            if archives:
                archive_total = sum(a.stat().st_size for a in archives)
                self.files_list.addItem(f"📦 ARCHIVES: {len(archives)} archived sessions, {archive_total / (1024*1024):.1f} MB")
            self.files_list.addItem("")
            
            # Add sessions
            for session_name, files in sorted(sessions.items()):
                session_size = sum(f['size'] for f in files)
                self.files_list.addItem(f"📁 {session_name.upper()} ({len(files)} files, {session_size // (1024*1024):.1f} MB)")
                
                # Group by interface type
                groups = {}
                for file_info in files:
                    group = file_info['group']
                    if group not in groups:
                        groups[group] = []
                    groups[group].append(file_info)
                
                for group_name, group_files in sorted(groups.items()):
                    group_size = sum(f['size'] for f in group_files)
                    self.files_list.addItem(f"  📡 {group_name}: {len(group_files)} files, {group_size // 1024} KB")
                    
                    for file_info in sorted(group_files, key=lambda x: x['name']):
                        size_kb = file_info['size'] // 1024
                        timestamp = file_info['name'].split('-')[0] if '-' in file_info['name'] else 'unknown'
                        self.files_list.addItem(f"    📄 {file_info['name']} ({size_kb} KB)")
                
                self.files_list.addItem("")  # Separator
                
    def apply_dark_theme(self):
        """Apply dark theme"""
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
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #404040;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QPushButton:pressed {
                background-color: #353535;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #666666;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                color: #ffffff;
            }
            QListWidget {
                background-color: #1e1e1e;
                border: 1px solid #555555;
                color: #ffffff;
            }
            QFrame {
                background-color: #353535;
                border: 1px solid #555555;
                border-radius: 5px;
                margin: 2px;
                padding: 5px;
            }
        """)

    def closeEvent(self, event):
        """Handle window close — minimize to tray if monitoring, otherwise quit"""
        self.logger.info("Close event triggered")
        self.save_session_state()
        
        # If tray is available and minimize_to_tray is on, hide instead of quit
        if self.minimize_to_tray and self.tray_icon and self.tray_icon.isVisible():
            is_monitoring = self.monitor_thread and self.monitor_thread.isRunning()
            if is_monitoring:
                self.tray_icon.showMessage(
                    "StealthShark",
                    "Still monitoring in the background. Click the menu bar icon to reopen.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000
                )
            self.hide()
            event.ignore()
            self.logger.info("Minimized to system tray")
            return
        
        # Actually quitting — stop monitoring first
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.stop_monitoring()
            if self.monitor_thread:
                self.monitor_thread.wait(3000)
        
        # Stop auto-save timer
        if self.auto_save_timer:
            self.auto_save_timer.stop()
        
        # Hide tray icon
        if self.tray_icon:
            self.tray_icon.hide()
            
        # Mark clean shutdown
        try:
            if self.session_state_file.exists():
                with open(self.session_state_file, 'r') as f:
                    state = json.load(f)
                state['was_monitoring'] = False
                state['clean_shutdown'] = True
                with open(self.session_state_file, 'w') as f:
                    json.dump(state, f, indent=2)
        except:
            pass
            
        self.logger.info("Application closed cleanly")
        event.accept()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Multi-Interface Shark Monitor")
    
    # Create and show main window
    window = MultiInterfaceSharkGUI()
    window.show()
    
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())
