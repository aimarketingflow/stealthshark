import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var prefs = SessionManager.Preferences()
    @State private var showingSavedAlert = false

    var body: some View {
        Form {
            Section("General") {
                Toggle("Auto-start capture on launch", isOn: $prefs.autoStartCapture)
                Toggle("Minimize to menu bar on close", isOn: $prefs.minimizeToMenuBar)
            }

            Section("Capture") {
                Stepper("Rotation interval: \(prefs.captureRotationHours) hour(s)",
                        value: $prefs.captureRotationHours, in: 1...24)

                Stepper("Max disk usage: \(prefs.maxDiskUsageGB) GB",
                        value: $prefs.maxDiskUsageGB, in: 1...500)

                Stepper("Auto-cleanup after: \(prefs.cleanupAfterDays) days",
                        value: $prefs.cleanupAfterDays, in: 1...90)
            }

            Section("Auto-Restart") {
                Toggle("Auto-restart monitoring by duration", isOn: $prefs.autoRestartEnabled)

                HStack {
                    Stepper("\(prefs.autoRestartHours) hour(s)",
                            value: $prefs.autoRestartHours, in: 0...24)
                        .disabled(!prefs.autoRestartEnabled)

                    Stepper("\(prefs.autoRestartMinutes) minute(s)",
                            value: $prefs.autoRestartMinutes, in: 0...59)
                        .disabled(!prefs.autoRestartEnabled)
                }

                HStack {
                    Toggle("Restart at capture size", isOn: Binding(
                        get: { prefs.autoRestartCaptureGB > 0 },
                        set: { newValue in
                            prefs.autoRestartCaptureGB = newValue ? 10 : 0
                        }
                    ))
                    .labelsHidden()

                    Stepper("\(prefs.autoRestartCaptureGB) GB (0 = off)",
                            value: $prefs.autoRestartCaptureGB, in: 0...500)
                }

                Text("When enabled, StealthShark will stop, save state, and restart monitoring automatically. Default is every 4 hours or when captures exceed 2 GB.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Paths") {
                LabeledContent("App Support") {
                    Text(appState.appSupportDir.path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                LabeledContent("Captures") {
                    Text(appState.appSupportDir.appendingPathComponent("pcap_captures").path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }

                Button("Open in Finder") {
                    NSWorkspace.shared.open(appState.appSupportDir)
                }
            }

            Section("tshark") {
                LabeledContent("Status") {
                    if appState.captureEngine.isTSharkAvailable {
                        Label("Available", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Not Found", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.red)
                    }
                }

                if !appState.captureEngine.isTSharkAvailable {
                    Text("Install Wireshark via: brew install wireshark")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("About") {
                LabeledContent("Version") { Text("3.0.0") }
                LabeledContent("Build") { Text("Swift/SwiftUI Native") }
                LabeledContent("Platform") { Text("macOS \(ProcessInfo.processInfo.operatingSystemVersionString)") }
            }

            Section {
                HStack {
                    Spacer()
                    Button("Save Preferences") {
                        appState.sessionManager.savePreferences(prefs)
                        showingSavedAlert = true
                    }
                    .buttonStyle(.borderedProminent)
                    Spacer()
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .onAppear {
            prefs = appState.sessionManager.loadPreferences()
        }
        .alert("Saved", isPresented: $showingSavedAlert) {
            Button("OK") {}
        } message: {
            Text("Preferences saved successfully.")
        }
    }
}
