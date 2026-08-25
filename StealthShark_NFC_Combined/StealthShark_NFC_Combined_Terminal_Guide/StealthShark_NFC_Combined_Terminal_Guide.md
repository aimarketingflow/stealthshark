# StealthShark NFC Combined Terminal Guide

**Last Updated:** 2025-09-02 02:01 AM PST

## Overview
Complete integration of StealthShark network monitoring with NFC WiFi authentication, providing packet capture, Bluetooth scanning, SSH security, and firewall controls.

## Prerequisites
```bash
# Install dependencies
pip3 install PyQt6 psutil

# Ensure tshark or tcpdump is available
which tshark tcpdump

# Check for sudo access (required for packet capture)
sudo -v
```

## Basic Usage

### Launch GUI Application
```bash
cd <PROJECT_DIR>
python3 stealthshark_nfc_combined.py
```

### Test Packet Capture
```bash
# Test monitor functionality
python3 test_monitor.py

# Test GUI with simulated authentication
python3 test_gui.py
```

## Service Management

### Install Auto-Start Service
```bash
./install_service.sh
```

### Check Service Status
```bash
launchctl list | grep com.aimf.stealthshark-nfc
```

### Stop Service
```bash
launchctl unload ~/Library/LaunchAgents/com.aimf.stealthshark-nfc.plist
```

### Start Service
```bash
launchctl load ~/Library/LaunchAgents/com.aimf.stealthshark-nfc.plist
```

### Uninstall Service
```bash
./uninstall_service.sh
```

## Monitoring Features

### View Capture Files
```bash
# List all captures
ls -la ./pcap_captures/session_*/

# Analyze specific capture
tcpdump -r ./pcap_captures/session_*/ethernet/*.pcap -nn | head -20
```

### View Logs
```bash
# Monitor logs
tail -f ./logs/stealthshark-nfc.log

# View error logs
tail -f ./logs/stealthshark-nfc.error.log

# Check monitor logs
ls -la ./pcap_captures/logs/
```

## Configuration

### Edit Settings
```bash
# Edit configuration
nano config.json
```

### Clear Authentication
```bash
# Remove saved authentication
rm auth_state.json
```

## Bluetooth Features

### View Device History
```bash
# Check saved Bluetooth devices
cat bluetooth_history.json | python3 -m json.tool
```

## Troubleshooting

### Permission Issues
```bash
# Grant capture permissions
sudo chmod +x /usr/sbin/tcpdump
```

### Clear All Data
```bash
# Remove all captures and logs
rm -rf pcap_captures/ logs/ bluetooth_history.json auth_state.json
```

## Development

### Run Tests
```bash
# Test capture system
python3 test_capture.py

# Test monitor
python3 test_monitor.py

# Test GUI
python3 test_gui.py
```

### Debug Mode
```bash
# Run with debug output
python3 -u stealthshark_nfc_combined.py 2>&1 | tee debug.log
```

## Key Files
- `stealthshark_nfc_combined.py` - Main application
- `persistent_wireshark_monitor.py` - Packet capture engine
- `stealthshark_nfc_methods.py` - Helper methods
- `config.json` - Configuration settings
- `com.aimf.stealthshark-nfc.plist` - LaunchAgent service

## Status Indicators
- 🦈 StealthShark monitoring active
- 🔑 NFC authentication required
- 📊 Interface monitoring statistics
- 📹 Active packet capture
- ✅ Operation successful
- 🚨 Security alert

Last Updated: 2025-09-01 23:56
