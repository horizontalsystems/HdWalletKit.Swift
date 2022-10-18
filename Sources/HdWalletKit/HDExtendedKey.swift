import Foundation
import HsCryptoKit
import HsExtensions

public enum HDExtendedKey {
    static let length = 82

    case `private`(key: HDPrivateKey)
    case `public`(key: HDPublicKey)

    public init(extendedKey: String) throws {
        let version = try HDExtendedKey.version(extendedKey: extendedKey)
        // extended key length : 4 + 1 + 4 + 4 + 32 + (HARDENED! Private has zero-bite 1 + 32 || Public has 33) + 4
        let shift = version.isPublic ? 0 : 1

        let data = Base58.decode(extendedKey)
        guard data.count == HDExtendedKey.length else {
            throw ParsingError.wrongKeyLength
        }

        let derivedType = DerivedType(depth: data[4])
        guard derivedType != .bip32 else {
            throw ParsingError.wrongDerivedType
        }

        let checksum: Data = data[78..<82]
        guard Data(Crypto.doubleSha256(data[0..<78]).prefix(4)) == checksum else {
            throw ParsingError.invalidChecksum
        }

        let depth: UInt8 = data[4]
        let fingerprint: UInt32 = data[5..<9].hs.to(type: UInt32.self).bigEndian
        let childIndex: UInt32 = data[9..<13].hs.to(type: UInt32.self).bigEndian
        let chainCode: Data = data[13..<45]
        // for private 45 byte = 0

        let raw: Data = data[(45 + shift)..<78]

        if version.isPublic {
            self = .public(key:
                    HDPublicKey(
                            raw: raw,
                            chainCode: chainCode,
                            xPubKey: version.rawValue,
                            depth: depth,
                            fingerprint: fingerprint,
                            childIndex: childIndex)
            )
        } else {
            self = .private(key:
                    HDPrivateKey(
                            privateKey: raw,
                            chainCode: chainCode,
                            xPrivKey: version.rawValue,
                            depth: depth,
                            fingerprint: fingerprint,
                            childIndex: childIndex)
            )
        }
    }

    public var derivedType: DerivedType {
        switch self {
        case .private(let key): return DerivedType(depth: key.depth)
        case .public(let key): return DerivedType(depth: key.depth)
        }
    }

}

public extension HDExtendedKey {

    var serialized: Data {
        let type: UInt8
        switch self {
        case .private: type = 0
        case .public: type = 1
        }

        return Data([type]) + keyData
    }

    static func deserialize(data: Data) throws -> HDExtendedKey {
        let lastIndex = HDExtendedKey.length + 1
        guard data.count == lastIndex else {
            throw ParsingError.wrongKeyLength
        }

        switch data[0] {
        case 0: return try .private(key: HDPrivateKey(extendedKey: data[1..<lastIndex]))
        case 1: return try .public(key: HDPublicKey(extendedKey: data[1..<lastIndex]))
        default: throw ParsingError.wrongType
        }
    }

}

public extension HDExtendedKey {

    var keyData: Data {
        switch self {
        case .private(let key): return key.data
        case .public(let key): return key.data
        }
    }

    var info: KeyInfo {
        let xKey: UInt32
        let depth: UInt8

        switch self {
        case .private(let key):
            xKey = key.xPrivKey
            depth = key.depth
        case .public(let key):
            xKey = key.xPubKey
            depth = key.depth
        }

        let version = HDExtendedKeyVersion(rawValue: xKey) ?? .xprv
        return KeyInfo(mnemonicDerivation: version.mnemonicDerivation, coinType: version.coinType, derivedType: DerivedType(depth: depth))
    }

    static func version(extendedKey: String) throws -> HDExtendedKeyVersion {
        let version = String(extendedKey.prefix(4))
        guard let keyType = HDExtendedKeyVersion(string: version) else {
            throw ParsingError.wrongVersion
        }

        return keyType
    }

    static func isValid(_ extendedKey: Data, isPublic: Bool) throws {
        guard extendedKey.count == HDExtendedKey.length else {
            throw ParsingError.wrongKeyLength
        }

        guard let version = HDExtendedKeyVersion(rawValue: extendedKey.prefix(4).hs.to(type: UInt32.self).bigEndian),
            version.isPublic == isPublic else {
            throw ParsingError.wrongVersion
        }

        let checksum: Data = extendedKey[79..<83]
        guard Data(Crypto.doubleSha256(extendedKey.prefix(78)).prefix(4)) == checksum else {
            throw ParsingError.invalidChecksum
        }
    }

}

extension HDExtendedKey: Equatable, Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(serialized)
    }

    public static func ==(lhs: HDExtendedKey, rhs: HDExtendedKey) -> Bool {
        lhs.serialized == rhs.serialized
    }

}

public extension HDExtendedKey {

    //master key depth == 0, account depth = "m/purpose'/coin_type'/account'" = 3, all others is custom
    enum DerivedType {
        case bip32
        case master
        case account

        init(depth: UInt8) {
            switch depth {
            case 0: self = .master
            case 3: self = .account
            default: self = .bip32
            }
        }
    }

    struct KeyInfo {
        public let mnemonicDerivation: HDExtendedKeyVersion.MnemonicDerivation
        public let coinType: HDExtendedKeyVersion.ExtendedKeyCoinType
        public let derivedType: DerivedType
    }

    enum ParsingError: Error {
        case wrongVersion
        case wrongType
        case wrongKeyLength
        case wrongDerivedType
        case invalidChecksum
    }

}
