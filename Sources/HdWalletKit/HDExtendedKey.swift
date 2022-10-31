import Foundation
import HsCryptoKit
import HsExtensions

public enum HDExtendedKey {
    static let length = 82

    case `private`(key: HDPrivateKey)
    case `public`(key: HDPublicKey)

    public init(extendedKey: String) throws {
        let data = Base58.decode(extendedKey)
        try self.init(data: data)
    }

    public init(data: Data) throws  {
        guard data.count == HDExtendedKey.length else {
            throw ParsingError.wrongKeyLength
        }

        let version = try HDExtendedKey.version(extendedKey: data)

        let derivedType = DerivedType(depth: data[4])
        guard derivedType != .bip32 else {
            throw ParsingError.wrongDerivedType
        }

        if version.isPublic {
            self = .public(key: try HDPublicKey(extendedKey: data))
        } else {
            self = .private(key: try HDPrivateKey(extendedKey: data))
        }
    }

    var hdKey: HDKey {
        switch self {
        case .private(let key): return key
        case .public(let key): return key
        }
    }

}

public extension HDExtendedKey {

    var derivedType: DerivedType {
        DerivedType(depth: hdKey.depth)
    }

    var serialized: Data {
        hdKey.data()
    }

    static func deserialize(data: Data) throws -> HDExtendedKey {
        try HDExtendedKey(data: data)
    }

}

public extension HDExtendedKey {

    var info: KeyInfo {
        let version = HDExtendedKeyVersion(rawValue: hdKey.version) ?? .xprv
        return KeyInfo(purpose: version.purpose, coinType: version.coinType, derivedType: DerivedType(depth: hdKey.depth))
    }

    static func version(extendedKey: Data) throws -> HDExtendedKeyVersion {
        let version = extendedKey.prefix(4).hs.to(type: UInt32.self).bigEndian
        guard let keyType = HDExtendedKeyVersion(rawValue: version) else {
            throw ParsingError.wrongVersion
        }

        return keyType
    }

    static func isValid(_ extendedKey: Data, isPublic: Bool? = nil) throws {
        guard extendedKey.count == HDExtendedKey.length else {
            throw ParsingError.wrongKeyLength
        }

        let version = try version(extendedKey: extendedKey)
        if let isPublic = isPublic, version.isPublic != isPublic  {
            throw ParsingError.wrongVersion
        }

        let checksum: Data = extendedKey[78..<82]
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
        public let purpose: Purpose
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
