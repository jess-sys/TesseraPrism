// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PrismKit",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "PrismKit", targets: ["PrismKit"])],
    targets: [
        .target(name: "PrismKit"),
        .testTarget(name: "PrismKitTests", dependencies: ["PrismKit"]),
    ]
)
