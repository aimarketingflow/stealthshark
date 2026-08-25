import Foundation

// MARK: - Network Interface
struct NetworkInterface: Identifiable, Equatable {
    let id: String // interface name (en0, lo0, etc.)
    let name: String
    var isUp: Bool
    var ipAddresses: [String]
    var bytesSent: UInt64
    var bytesRecv: UInt64
    var packetsSent: UInt64
    var packetsRecv: UInt64
    var bytesSentRate: Double
    var bytesRecvRate: Double
    var packetsSentRate: Double
    var packetsRecvRate: Double
    var hasActivity: Bool

    var displayName: String {
        switch name {
        case "en0": return "Wi-Fi (en0)"
        case "en1": return "Ethernet (en1)"
        case "lo0": return "Loopback (lo0)"
        case "awdl0": return "AirDrop (awdl0)"
        case "bridge0": return "Bridge (bridge0)"
        case "utun0", "utun1", "utun2", "utun3":
            return "VPN Tunnel (\(name))"
        default:
            if name.hasPrefix("en") { return "Network (\(name))" }
            if name.hasPrefix("utun") { return "Tunnel (\(name))" }
            return name
        }
    }

    var statusIcon: String {
        if !isUp { return "circle.slash" }
        if hasActivity { return "bolt.circle.fill" }
        return "circle.fill"
    }

    var statusColor: String {
        if !isUp { return "gray" }
        if hasActivity { return "green" }
        return "yellow"
    }

    static func == (lhs: NetworkInterface, rhs: NetworkInterface) -> Bool {
        lhs.id == rhs.id
    }
}

// MARK: - Capture Stats
struct CaptureStats {
    var totalPackets: UInt64 = 0
    var totalBytes: UInt64 = 0
    var activeCaptureCount: Int = 0
    var captureFiles: [CaptureFile] = []
    var startTime: Date?
    var elapsedTime: TimeInterval {
        guard let start = startTime else { return 0 }
        return Date().timeIntervalSince(start)
    }

    var formattedElapsed: String {
        let hours = Int(elapsedTime) / 3600
        let minutes = (Int(elapsedTime) % 3600) / 60
        let seconds = Int(elapsedTime) % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
}

struct CaptureFile: Identifiable {
    let id = UUID()
    let filename: String
    let interface: String
    let startTime: Date
    var size: UInt64
    var packetCount: UInt64
}

// MARK: - Traffic Pattern
struct TrafficPattern: Identifiable {
    let id = UUID()
    let timestamp: Date
    let interface: String
    let patternType: PatternType
    let description: String
    let severity: Severity

    enum PatternType: String, CaseIterable {
        case highTraffic = "High Traffic"
        case newConnection = "New Connection"
        case portScan = "Port Scan"
        case dnsAnomaly = "DNS Anomaly"
        case dataExfiltration = "Data Exfiltration"
        case unusualProtocol = "Unusual Protocol"
    }

    enum Severity: String, CaseIterable {
        case info = "Info"
        case warning = "Warning"
        case critical = "Critical"

        var color: String {
            switch self {
            case .info: return "blue"
            case .warning: return "orange"
            case .critical: return "red"
            }
        }

        var icon: String {
            switch self {
            case .info: return "info.circle"
            case .warning: return "exclamationmark.triangle"
            case .critical: return "xmark.octagon"
            }
        }
    }
}

// MARK: - Activity Entry
struct ActivityEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let message: String
    let type: EntryType

    enum EntryType: String {
        case info = "info"
        case warning = "warning"
        case error = "error"
        case capture = "capture"
        case pattern = "pattern"

        var icon: String {
            switch self {
            case .info: return "info.circle.fill"
            case .warning: return "exclamationmark.triangle.fill"
            case .error: return "xmark.circle.fill"
            case .capture: return "internaldrive.fill"
            case .pattern: return "brain"
            }
        }

        var color: String {
            switch self {
            case .info: return "blue"
            case .warning: return "orange"
            case .error: return "red"
            case .capture: return "green"
            case .pattern: return "purple"
            }
        }
    }

    var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: timestamp)
    }
}

// MARK: - Session State (Codable for persistence)
struct SessionState: Codable {
    let isMonitoring: Bool
    let lastActive: Date
    let interfaceNames: [String]
    let activityLog: [ActivityEntry]

    init(isMonitoring: Bool, lastActive: Date, interfaceNames: [String], activityLog: [ActivityEntry]) {
        self.isMonitoring = isMonitoring
        self.lastActive = lastActive
        self.interfaceNames = interfaceNames
        self.activityLog = activityLog
    }
}

// Make ActivityEntry Codable
extension ActivityEntry: Codable {
    enum CodingKeys: String, CodingKey {
        case timestamp, message, type
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        message = try container.decode(String.self, forKey: .message)
        let typeRaw = try container.decode(String.self, forKey: .type)
        type = EntryType(rawValue: typeRaw) ?? .info
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(message, forKey: .message)
        try container.encode(type.rawValue, forKey: .type)
    }
}
