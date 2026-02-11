#!/usr/bin/env python3
"""
Persistent Wireshark Monitor
Advanced network interface monitoring with automatic packet capture
Monitors all network interfaces and triggers timed captures when traffic is detected
"""

import subprocess
import threading
import time
import os
import json
import logging
import signal
import sys
import tarfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import argparse
from collections import defaultdict, deque

class PersistentWiresharkMonitor:
    def __init__(self, capture_dir="./pcap_captures", capture_duration=3600, 
                 check_interval=5, alert_callback=None):
        """
        Initialize the persistent Wireshark monitor
        
        Args:
            capture_dir: Directory to store PCAP files
            capture_duration: Duration of each capture session in seconds (1min-5hrs)
            check_interval: How often to check for interface activity (seconds)
            alert_callback: Function to call when new interface activity detected
        """
        self.capture_dir = Path(capture_dir)
        self.capture_duration = max(30, min(18000, capture_duration))  # 30s-5hrs
        self.check_interval = check_interval
        self.alert_callback = alert_callback
        
        # Interface monitoring
        self.monitored_interfaces = set()
        self.active_captures = {}  # interface -> capture process
        self.interface_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_activity': None})
        self.interface_history = defaultdict(lambda: deque(maxlen=10))
        
        # Default interfaces to always monitor
        self.default_interfaces = {'lo0', 'en0'}
        
        # Control flags
        self.running = True
        self.capture_processes = {}
        
        # Setup logging
        self.setup_logging()
        
        # Create session directory for this monitoring session
        self.session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = Path(self.capture_dir) / f"session_{self.session_timestamp}"
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # Signal handlers (only in main thread)
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            self.logger.info("Signal handlers registered successfully")
        except ValueError as e:
            self.logger.warning(f"Could not register signal handlers (not main thread): {e}")
            # This is expected when running in a thread
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = self.capture_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"wireshark_monitor_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Persistent Wireshark Monitor initialized")
        
    def discover_interfaces(self):
        """Discover all available network interfaces"""
        try:
            # Get interfaces using tshark
            result = subprocess.run(['tshark', '-D'], 
                                  capture_output=True, text=True, timeout=10)
            
            interfaces = set()
            for line in result.stdout.strip().split('\n'):
                if line and '.' in line:
                    # Parse tshark -D output: "1. en0 (Wi-Fi)"
                    parts = line.split('.', 1)
                    if len(parts) > 1:
                        iface_info = parts[1].strip()
                        iface_name = iface_info.split()[0]
                        interfaces.add(iface_name)
            
            # Also get from psutil as backup
            for iface in psutil.net_if_addrs().keys():
                interfaces.add(iface)
                
            self.monitored_interfaces = interfaces
            self.logger.info(f"Discovered interfaces: {sorted(interfaces)}")
            
            # Always monitor default interfaces
            for iface in self.default_interfaces:
                if iface in interfaces:
                    self.logger.info(f"Default interface {iface} will be monitored")
                    
        except Exception as e:
            self.logger.error(f"Failed to discover interfaces: {e}")
            # Fallback to common interfaces
            self.monitored_interfaces = {'lo0', 'en0', 'en1', 'awdl0'}
            
    def get_interface_stats(self, interface):
        """Get current packet/byte counts for an interface"""
        try:
            stats = psutil.net_io_counters(pernic=True)
            if interface in stats:
                iface_stats = stats[interface]
                return {
                    'packets': iface_stats.packets_sent + iface_stats.packets_recv,
                    'bytes': iface_stats.bytes_sent + iface_stats.bytes_recv
                }
        except Exception as e:
            self.logger.debug(f"Failed to get stats for {interface}: {e}")
        return {'packets': 0, 'bytes': 0}
        
    def detect_interface_activity(self):
        """Check all interfaces for new activity"""
        active_interfaces = set()
        
        for interface in self.monitored_interfaces:
            current_stats = self.get_interface_stats(interface)
            previous_stats = self.interface_stats[interface]
            
            # Check for activity (packet count increase)
            if current_stats['packets'] > previous_stats['packets']:
                active_interfaces.add(interface)
                self.interface_stats[interface] = current_stats
                self.interface_stats[interface]['last_activity'] = datetime.now()
                
                # Log activity
                packet_diff = current_stats['packets'] - previous_stats['packets']
                byte_diff = current_stats['bytes'] - previous_stats['bytes']
                
                self.logger.info(f"Activity detected on {interface}: "
                               f"+{packet_diff} packets, +{byte_diff} bytes")
                
                # Store in history
                self.interface_history[interface].append({
                    'timestamp': datetime.now(),
                    'packets': packet_diff,
                    'bytes': byte_diff
                })
                
        return active_interfaces
        
    def get_interface_group(self, interface):
        """Categorize interface into groups for organized file naming"""
        if interface == 'lo0':
            return 'loopback'
        elif interface.startswith('en'):
            return 'ethernet'
        elif interface.startswith('awdl'):
            return 'airdrop'
        elif interface.startswith('utun'):
            return 'vpn'
        elif interface.startswith('llw'):
            return 'lowlatency'
        elif interface.startswith('pflog'):
            return 'firewall'
        else:
            return 'other'
    
    def start_capture(self, interface):
        """Start packet capture on specified interface"""
        if interface in self.active_captures:
            self.logger.warning(f"Capture already active on {interface}")
            return
        
        # Sanitize interface name to prevent path traversal or command injection
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', interface):
            self.logger.error(f"Rejected invalid interface name: {repr(interface)}")
            return
        
        # Use session timestamp for consistent grouping
        interface_group = self.get_interface_group(interface)
        
        # Create organized directory structure using session directory
        if interface_group == 'loopback':
            output_dir = self.session_dir / "loopback"
        else:
            output_dir = self.session_dir / interface_group
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Starting capture session in: {output_dir}")
        
        # Create capture file with organized naming using session timestamp (compressed)
        if interface_group == 'loopback':
            capture_filename = f"{self.session_timestamp}-ch-loopback.pcap.gz"
        else:
            capture_filename = f"{self.session_timestamp}-ch-{interface}.pcap.gz"
        
        capture_file = output_dir / capture_filename
        capture_file_abs = capture_file.resolve()
        
        self.logger.info(f"📁 PCAP SAVE: {capture_filename}")
        self.logger.info(f"📂 FULL PATH: {capture_file_abs}")
        self.logger.info(f"🏷️  GROUP: {interface_group} | INTERFACE: {interface}")
        
        try:
            # Try multiple capture methods to avoid password prompts
            # Define capture method templates (file path inserted at runtime)
            capture_method_bases = [
                # Method 1: Direct tcpdump (works if ChmodBPF is installed)
                ['tcpdump'],
                # Method 2: Sudo tcpdump with NOPASSWD configured
                ['sudo', 'tcpdump'],
                # Method 3: Tcpdump wrapper
                ['/usr/local/bin/tcpdump_wrapper']
            ]
            
            cmd = None
            for method_base in capture_method_bases:
                try:
                    # Test if the command can capture on this interface (without -w to avoid touching the file)
                    test_cmd = method_base + ['-i', interface, '-c', '0']
                    test_process = subprocess.Popen(test_cmd, 
                                                  stdout=subprocess.PIPE, 
                                                  stderr=subprocess.PIPE)
                    test_process.wait(timeout=5)
                    if test_process.returncode == 0:
                        # Write to stdout (-w -) so we can pipe through gzip
                        cmd = method_base + ['-i', interface, '-w', '-', '-s', '0', '-q']
                        self.logger.info(f"Using capture method: {' '.join(method_base)}")
                        break
                except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
                    if 'test_process' in locals() and test_process.poll() is None:
                        test_process.kill()
                    continue
            
            if not cmd:
                # Fallback to sudo method
                cmd = ['sudo', 'tcpdump', '-i', interface, '-w', '-', '-s', '0', '-q']
                self.logger.warning("Using sudo fallback - may require password")
            
            # Pipe tcpdump stdout through gzip for real-time compression
            gzip_outfile = open(str(capture_file_abs), 'wb')
            tcpdump_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                               stderr=subprocess.PIPE)
            gzip_process = subprocess.Popen(['gzip', '-1'],
                                            stdin=tcpdump_process.stdout,
                                            stdout=gzip_outfile,
                                            stderr=subprocess.PIPE)
            # Allow tcpdump to receive SIGPIPE if gzip exits
            tcpdump_process.stdout.close()
            
            self.active_captures[interface] = {
                'process': tcpdump_process,
                'gzip_process': gzip_process,
                'gzip_outfile': gzip_outfile,
                'start_time': datetime.now(),
                'capture_file': capture_file,
                'capture_filename': capture_filename,
                'interface_group': interface_group,
                'duration': self.capture_duration
            }
            
            self.logger.info(f"✅ Started capture on {interface} -> {capture_filename}")
            
            # Send alert if callback provided
            if self.alert_callback:
                self.alert_callback(f"Started packet capture on {interface}")
                
            # Start monitoring thread for this capture
            monitor_thread = threading.Thread(
                target=self.monitor_capture, 
                args=(interface,),
                daemon=True
            )
            monitor_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start capture on {interface}: {e}")
            
    def monitor_capture(self, interface):
        """Monitor a specific capture process"""
        capture_info = self.active_captures.get(interface)
        if not capture_info:
            return
            
        process = capture_info['process']
        start_time = capture_info['start_time']
        duration = capture_info['duration']
        
        # Wait for process to complete or timeout
        try:
            process.wait(timeout=duration + 5)  # Small buffer for cleanup
        except subprocess.TimeoutExpired:
            self.logger.info(f"Capture on {interface} reached duration limit ({duration}s), terminating")
            process.terminate()
            try:
                process.wait(timeout=5)  # Wait for graceful termination
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Force killing capture process on {interface}")
                process.kill()
            
        # Clean up completed capture
        if interface in self.active_captures:
            capture_file = self.active_captures[interface]['capture_file']
            self.logger.info(f"🏁 Capture completed on {interface} after {duration}s")
            
            # Wait for gzip to finish flushing and close the output file
            gzip_proc = self.active_captures[interface].get('gzip_process')
            gzip_outfile = self.active_captures[interface].get('gzip_outfile')
            if gzip_proc:
                try:
                    gzip_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    gzip_proc.kill()
            if gzip_outfile:
                try:
                    gzip_outfile.close()
                except Exception:
                    pass
            
            # Remove from active captures
            del self.active_captures[interface]
            
            # Log file size if exists
            if capture_file.exists():
                file_size = capture_file.stat().st_size
                if file_size > 0:
                    self.logger.info(f"📊 Compressed PCAP size: {file_size} bytes - {capture_file.name}")
                else:
                    self.logger.warning(f"⚠️ PCAP file is empty (0 bytes): {capture_file.name}")
            else:
                self.logger.error(f"❌ PCAP file was NOT saved: {capture_file.name}")

    def check_new_interfaces(self):
        """Check for new interfaces that weren't previously monitored"""
        current_interfaces = set()
        
        try:
            # Re-discover interfaces
            for iface in psutil.net_if_addrs().keys():
                current_interfaces.add(iface)
                
            # Find new interfaces
            new_interfaces = current_interfaces - self.monitored_interfaces
            
            if new_interfaces:
                self.logger.warning(f"NEW INTERFACES DETECTED: {sorted(new_interfaces)}")
                
                # Send alert
                if self.alert_callback:
                    self.alert_callback(f"New network interfaces detected: {', '.join(new_interfaces)}")
                    
                # Add to monitoring
                self.monitored_interfaces.update(new_interfaces)
                
                # Check if they have immediate activity
                for interface in new_interfaces:
                    stats = self.get_interface_stats(interface)
                    if stats['packets'] > 0:
                        self.logger.warning(f"New interface {interface} has immediate activity!")
                        self.start_capture(interface)
                        
        except Exception as e:
            self.logger.error(f"Failed to check for new interfaces: {e}")
            
    def cleanup_old_captures(self):
        """Clean up old capture files and archives to prevent disk space issues"""
        try:
            # Remove archives older than 7 days
            cutoff_time = datetime.now() - timedelta(days=7)
            
            for archive_file in self.capture_dir.glob("session_*.tar.gz"):
                if archive_file.stat().st_mtime < cutoff_time.timestamp():
                    archive_file.unlink()
                    self.logger.info(f"Cleaned up old archive: {archive_file.name}")
            
            # Also clean completed dir if it exists
            completed_dir = self.capture_dir / "completed"
            if completed_dir.exists():
                for pcap_file in completed_dir.glob("*.pcap*"):
                    if pcap_file.stat().st_mtime < cutoff_time.timestamp():
                        pcap_file.unlink()
                        self.logger.info(f"Cleaned up old capture: {pcap_file.name}")
                    
        except Exception as e:
            self.logger.error(f"Failed to cleanup old captures: {e}")
    
    def archive_old_sessions(self):
        """Compress older session folders into .tar.gz archives to save disk space"""
        try:
            for session_dir in sorted(self.capture_dir.glob("session_*")):
                # Skip non-directories (already-archived .tar.gz files)
                if not session_dir.is_dir():
                    continue
                    
                # Never archive the current active session
                if session_dir.name == self.session_dir.name:
                    continue
                
                # Only archive sessions older than 1 hour
                try:
                    dir_mtime = datetime.fromtimestamp(session_dir.stat().st_mtime)
                    if datetime.now() - dir_mtime < timedelta(hours=1):
                        continue
                except Exception:
                    continue
                
                archive_path = self.capture_dir / f"{session_dir.name}.tar.gz"
                
                # Skip if already archived
                if archive_path.exists():
                    continue
                
                # Create compressed tar archive
                self.logger.info(f"📦 Archiving session: {session_dir.name} -> {archive_path.name}")
                try:
                    with tarfile.open(str(archive_path), 'w:gz') as tar:
                        tar.add(str(session_dir), arcname=session_dir.name)
                    
                    # Verify archive was created and has content
                    if archive_path.exists() and archive_path.stat().st_size > 0:
                        # Calculate space saved
                        original_size = sum(f.stat().st_size for f in session_dir.rglob('*') if f.is_file())
                        archive_size = archive_path.stat().st_size
                        saved_pct = (1 - archive_size / max(original_size, 1)) * 100
                        
                        # Remove original directory
                        shutil.rmtree(str(session_dir))
                        self.logger.info(f"✅ Archived {session_dir.name}: "
                                       f"{original_size} -> {archive_size} bytes "
                                       f"({saved_pct:.1f}% saved)")
                    else:
                        self.logger.warning(f"⚠️ Archive creation failed for {session_dir.name}, keeping original")
                        if archive_path.exists():
                            archive_path.unlink()
                            
                except Exception as e:
                    self.logger.error(f"Failed to archive {session_dir.name}: {e}")
                    # Clean up partial archive
                    if archive_path.exists():
                        try:
                            archive_path.unlink()
                        except Exception:
                            pass
                            
        except Exception as e:
            self.logger.error(f"Failed to archive old sessions: {e}")
            
    def generate_status_report(self):
        """Generate comprehensive status report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'monitored_interfaces': sorted(self.monitored_interfaces),
            'active_captures': len(self.active_captures),
            'capture_duration_minutes': self.capture_duration / 60,
            'interface_activity': {}
        }
        
        for interface in self.monitored_interfaces:
            stats = self.interface_stats[interface]
            recent_activity = list(self.interface_history[interface])
            
            report['interface_activity'][interface] = {
                'total_packets': stats['packets'],
                'total_bytes': stats['bytes'],
                'last_activity': stats['last_activity'].isoformat() if stats['last_activity'] else None,
                'recent_activity_count': len(recent_activity),
                'is_capturing': interface in self.active_captures
            }
            
        # Save report
        report_file = self.capture_dir / "logs" / f"status_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        return report
        
    def run(self):
        """Main monitoring loop"""
        self.logger.info("Starting Persistent Wireshark Monitor")
        self.logger.info(f"Capture directory: {self.capture_dir}")
        self.logger.info(f"Capture duration: {self.capture_duration} seconds")
        self.logger.info(f"Check interval: {self.check_interval} seconds")
        
        iteration = 0
        try:
            while self.running:
                iteration += 1
                
                # Check for active interfaces
                active_interfaces = self.detect_active_interfaces()
                
                if active_interfaces:
                    self.logger.info(f"Found {len(active_interfaces)} active interfaces")
                    
                    # Log currently monitored channels
                    if self.active_captures:
                        monitored_channels = []
                        for interface, capture_info in self.active_captures.items():
                            group = capture_info.get('interface_group', 'unknown')
                            monitored_channels.append(f"{interface}({group})")
                        self.logger.info(f"📡 ACTIVELY MONITORING: {', '.join(monitored_channels)}")
                    
                    for interface_info in active_interfaces:
                        interface = interface_info['interface']
                        
                        # Start capture if not already running
                        if interface not in self.active_captures:
                            self.start_capture(interface)
                
                # Cleanup, archiving, and reporting
                if iteration % 100 == 0:
                    self.archive_old_sessions()
                    self.cleanup_old_captures()
                    
                # Generate status report every 50 iterations
                if iteration % 50 == 0:
                    report = self.generate_status_report()
                    self.logger.info(f"Status: {len(self.active_captures)} active captures, "
                                   f"{len(self.monitored_interfaces)} monitored interfaces")
                
                # Sleep for check interval
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error in main loop: {e}")
        finally:
            self.cleanup()
        
    def stop_capture(self, interface):
        """Stop an active capture on the specified interface and finalize the pcap file"""
        capture_info = self.active_captures.get(interface)
        if not capture_info:
            self.logger.warning(f"No active capture to stop on {interface}")
            return
        
        process = capture_info['process']
        capture_file = capture_info['capture_file']
        gzip_proc = capture_info.get('gzip_process')
        gzip_outfile = capture_info.get('gzip_outfile')
        
        try:
            if process.poll() is None:  # Still running
                self.logger.info(f"Stopping capture on {interface}...")
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Force killing capture on {interface}")
                    process.kill()
                    process.wait(timeout=5)
            
            # Wait for gzip to finish flushing
            if gzip_proc:
                try:
                    gzip_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    gzip_proc.kill()
            if gzip_outfile:
                try:
                    gzip_outfile.close()
                except Exception:
                    pass
            
            # Log final file status
            if capture_file.exists():
                file_size = capture_file.stat().st_size
                if file_size > 0:
                    self.logger.info(f"📊 Saved compressed PCAP ({file_size} bytes): {capture_file.name}")
                else:
                    self.logger.warning(f"⚠️ PCAP file is empty: {capture_file.name}")
            else:
                self.logger.error(f"❌ PCAP file was NOT saved: {capture_file.name}")
                
        except Exception as e:
            self.logger.error(f"Error stopping capture on {interface}: {e}")
        finally:
            del self.active_captures[interface]
    
    def cleanup(self):
        """Clean up resources and terminate processes"""
        self.logger.info("Cleaning up resources...")
        self.running = False
        
        # Terminate all active captures
        for interface in list(self.active_captures.keys()):
            self.stop_capture(interface)
            
        self.logger.info("Cleanup completed")
        
    def detect_active_interfaces(self):
        """Detect network interfaces with recent activity"""
        active_interfaces = []
        
        try:
            # Get current network statistics
            current_stats = psutil.net_io_counters(pernic=True)
            current_time = datetime.now()
            
            for interface, stats in current_stats.items():
                # Skip virtual interfaces we don't want to monitor
                if interface.startswith(('vnic', 'bridge', 'ap')):
                    continue
                    
                # Get previous stats for this interface
                prev_stats = self.interface_stats.get(interface, {'packets': 0, 'bytes': 0})
                
                # Calculate differences
                packet_diff = stats.packets_sent + stats.packets_recv - prev_stats['packets']
                byte_diff = stats.bytes_sent + stats.bytes_recv - prev_stats['bytes']
                
                # Update stored stats
                self.interface_stats[interface] = {
                    'packets': stats.packets_sent + stats.packets_recv,
                    'bytes': stats.bytes_sent + stats.bytes_recv,
                    'last_activity': current_time if packet_diff > 0 else prev_stats.get('last_activity')
                }
                
                # Consider interface active if it has recent activity or is in default set
                if packet_diff > 0 or interface in self.default_interfaces:
                    active_interfaces.append({
                        'interface': interface,
                        'packets': packet_diff,
                        'bytes': byte_diff,
                        'total_packets': stats.packets_sent + stats.packets_recv,
                        'total_bytes': stats.bytes_sent + stats.bytes_recv
                    })
                    
                    # Store in history
                    self.interface_history[interface].append({
                        'timestamp': current_time,
                        'packets': packet_diff,
                        'bytes': byte_diff
                    })
                    
        except Exception as e:
            self.logger.error(f"Error detecting active interfaces: {e}")
            
        return active_interfaces

    def shutdown(self):
        """Gracefully shutdown all captures"""
        self.logger.info("Shutting down persistent Wireshark monitor...")
        self.running = False
        
        # Terminate all active captures using stop_capture for proper finalization
        for interface in list(self.active_captures.keys()):
            self.stop_capture(interface)
                
        # Generate final report
        final_report = self.generate_status_report()
        self.logger.info("Shutdown complete")
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False

def alert_notification(message):
    """Simple alert function - can be enhanced with desktop notifications"""
    print(f"\n🚨 ALERT: {message}")
    
    # Try to send macOS notification
    try:
        subprocess.run([
            'osascript', '-e', 
            f'display notification "{message}" with title "Wireshark Monitor Alert"'
        ], check=False)
    except:
        pass

def main():
    parser = argparse.ArgumentParser(description='Persistent Wireshark Network Monitor')
    parser.add_argument('--capture-dir', default='./pcap_captures',
                       help='Directory to store PCAP files')
    parser.add_argument('--duration', type=int, default=30,
                       help='Capture duration: 30 seconds (30-21600, default: 30)')
    parser.add_argument('--interval', type=int, default=5,
                       help='Check interval in seconds (default: 5)')
    parser.add_argument('--no-alerts', action='store_true',
                       help='Disable alert notifications')
    parser.add_argument('--status', action='store_true',
                       help='Show status and exit')
    
    args = parser.parse_args()
    
    # Validate duration (30 seconds to 6 hours)
    if not (30 <= args.duration <= 21600):
        print("Error: Duration must be between 30 seconds and 21600 seconds (6 hours)")
        sys.exit(1)
        
    alert_callback = None if args.no_alerts else alert_notification
    
    monitor = PersistentWiresharkMonitor(
        capture_dir=args.capture_dir,
        capture_duration=args.duration,
        check_interval=args.interval,
        alert_callback=alert_callback
    )
    
    if args.status:
        report = monitor.generate_status_report()
        print(json.dumps(report, indent=2))
        return
        
    try:
        monitor.run()
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
