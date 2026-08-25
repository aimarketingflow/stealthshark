// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "StealthShark",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .executableTarget(
            name: "StealthShark",
            path: "Sources/StealthShark",
            resources: [
                .process("Resources")
            ]
        )
    ]
)
