# StealthShark + NFC WiFi Authentication Combined Application

## Overview
Unified network monitoring application combining StealthShark packet capture with NFC-authenticated WiFi security controls.

## Features
- **NFC Authentication Gating** - Physical token required to access monitoring features
- **StealthShark Integration** - Full packet capture and network monitoring
- **WiFi Threat Detection** - Real-time network scanning and threat identification
- **Unified GUI** - Single interface for all security functions
- **Persistent Configuration** - Settings and authentication state saved

## Architecture
- `stealthshark_nfc_combined.py` - Main application with GUI framework
- `stealthshark_nfc_methods.py` - Core functionality methods (modular design)

## Security Model
1. **Authentication Required** - NFC tag authentication gates all monitoring functions
2. **Network Binding** - Auto-authentication when connected to registered networks
3. **Firewall Integration** - Toggle firewall controls with authentication checks
4. **Threat Correlation** - Cross-system event analysis and alerting

## Usage
```bash
cd <PROJECT_DIR>
python3 stealthshark_nfc_combined.py
```

## Dependencies
- PyQt6
- StealthShark components
- Anti-Pineapple NFC components
- macOS system tools (airport, networksetup)

## Configuration
- NFC tags: `~/.ssh/nfc_tags.json`
- Authentication state: `~/.ssh/anti_pineapple_auth.json`
- Capture directory: `./pcap_captures` (configurable)

## Integration Points
- Ready for Bluetooth scanner integration
- Expandable for additional security modules
- Cross-system correlation framework prepared
