// swift-tools-version:5.5

import PackageDescription

let package = Package(
    name: "HdWalletKit",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "HdWalletKit",
            targets: ["HdWalletKit"]),
    ],
    dependencies: [
        .package(name: "OpenSSLKit", url: "https://github.com/horizontalsystems/OpenSSLKit.git", .upToNextMajor(from: "1.0.0")),
        .package(name: "secp256k1", url: "https://github.com/horizontalsystems/secp256k1.swift.git", .upToNextMajor(from: "0.3.5"))
    ],
    targets: [
        .target(
            name: "HdWalletKit",
            dependencies: ["OpenSSLKit", "secp256k1"]),
    ]
)
