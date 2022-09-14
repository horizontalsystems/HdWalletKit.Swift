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
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift.git", .upToNextMajor(from: "0.8.1")),
    ],
    targets: [
        .target(
            name: "HdWalletKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
            ]),
    ]
)
