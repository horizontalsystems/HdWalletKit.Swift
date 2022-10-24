import Foundation
import HsCryptoKit

public class HDKey {
    public let version: UInt32
    public let depth: UInt8
    public let fingerprint: UInt32
    public let childIndex: UInt32

    let _raw: Data
    public let chainCode: Data

    open var raw: Data { _raw }

    public init(raw: Data, chainCode: Data, version: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.version = version
        self._raw = raw
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    public init(extendedKey: Data) throws {
        try HDExtendedKey.isValid(extendedKey)
        version = extendedKey.prefix(4).hs.to(type: UInt32.self).bigEndian

        depth = extendedKey[4]
        fingerprint = extendedKey[5..<9].hs.to(type: UInt32.self).bigEndian
        childIndex = extendedKey[9..<12].hs.to(type: UInt32.self).bigEndian
        chainCode = extendedKey[13..<45]
        _raw = extendedKey[45..<78]
    }

}

extension HDKey {

    var data: Data {
        var data = Data()
        data += version.bigEndian.data
        data += Data([depth])
        data += fingerprint.bigEndian.data
        data += childIndex.bigEndian.data
        data += chainCode
        data += _raw
        let checksum = Crypto.doubleSha256(data).prefix(4)
        return data + checksum
    }

}

public extension HDKey {

    func extended() -> String {
        Base58.encode(data)
    }

    var description: String {
        "\(raw.hs.hex) ::: \(chainCode.hs.hex) ::: depth: \(depth) - fingerprint: \(fingerprint) - childIndex: \(childIndex)"
    }

}