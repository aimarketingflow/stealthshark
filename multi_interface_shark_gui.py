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
from datetime import datetime, timedelta
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLabel, QTextEdit, QSpinBox, 
                             QCheckBox, QComboBox, QProgressBar, QTabWidget,
                             QGroupBox, QTableWidget, QTableWidgetItem, QListWidget,
                             QListWidgetItem, QSplitter, QGridLayout, QTreeWidget, 
                             QTreeWidgetItem, QLineEdit, QFileDialog, QMessageBox, 
                             QStatusBar, QScrollArea, QFrame)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt, QSize
from PyQt6.QtGui import QFont, QBrush, QColor, QPalette, QPixmap, QIcon

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
    
    def __init__(self, capture_dir="./pcap_captures", duration=3600):
        super().__init__()
        self.logger = logging.getLogger("MultiInterfaceThread")
        self.capture_dir = Path(capture_dir)
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
                self.status_update.emit(f"📊 Stats: {len(interface_data)} interfaces, {active_count} up, {traffic_count} active")
            
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

class MultiInterfaceSharkGUI(QMainWindow):
    """Main Multi-Interface Shark GUI"""
    
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.auto_save_timer = None
        self.session_state_file = Path("./gui_logs/session_state.json")
        self.setup_logging()
        self.setup_ui()
        self.apply_dark_theme()
        self.setup_auto_save()
        self.setup_crash_protection()
        
    def setup_logging(self):
        """Setup verbose logging"""
        log_dir = Path("./gui_logs")
        log_dir.mkdir(exist_ok=True)
        
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
        self.dir_edit = QLineEdit("./pcap_captures")
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
        """Handle window close event with auto-save"""
        self.logger.info("Application closing - saving session state")
        
        # Save current state
        self.save_session_state()
        
        if self.monitor_thread and self.monitor_thread.isRunning():
            reply = QMessageBox.question(
                self, "Confirm Exit",
                "Monitoring is active. Stop monitoring and exit?\n\n"
                "Note: Session state has been saved and can be restored on next startup.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_monitoring()
                # Wait a moment for cleanup
                if self.monitor_thread:
                    self.monitor_thread.wait(3000)  # Wait up to 3 seconds
                event.accept()
            else:
                event.ignore()
                return
        
        # Stop auto-save timer
        if self.auto_save_timer:
            self.auto_save_timer.stop()
            
        # Clear session state file on clean exit
        try:
            if self.session_state_file.exists():
                # Mark as clean shutdown
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
