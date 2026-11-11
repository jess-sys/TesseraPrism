// swift-tools-version:5.9
import PackageDescription

// Links the Rust core. Sources/PrismFFI/PrismFFI.swift is a symlink to the UniFFI-generated file and
// PrismFFIBinary is the xcframework, both under ../../../crates/prism-ffi/out (see crates/prism-ffi/build-xcframework.sh).
let package = Package(
    name: "PrismFFIKit",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [.library(name: "PrismFFI", targets: ["PrismFFI"])],
    targets: [
        .binaryTarget(name: "PrismFFIBinary", path: "../../../crates/prism-ffi/out/PrismFFI.xcframework"),
        .target(name: "PrismFFI", dependencies: ["PrismFFIBinary"]),
        .testTarget(name: "PrismFFIKitTests", dependencies: ["PrismFFI"]),
    ]
)
