import Foundation
import HsCryptoKit
import HsExtensions
import secp256k1

public class HDPrivateKey {
    let xPrivKey: UInt32
    let depth: UInt8
    let fingerprint: UInt32
    let childIndex: UInt32

    public let raw: Data
    let chainCode: Data

    init(privateKey: Data, chainCode: Data, xPrivKey: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        let zeros = privateKey.count < 32 ? [UInt8](repeating: 0, count: 32 - privateKey.count) : []

        raw = Data(zeros) + privateKey
        self.chainCode = chainCode
        self.xPrivKey = xPrivKey
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    public convenience init(privateKey: Data, chainCode: Data, xPrivKey: UInt32) {
        self.init(privateKey: privateKey, chainCode: chainCode, xPrivKey: xPrivKey, depth: 0, fingerprint: 0, childIndex: 0)
    }

    public convenience init(seed: Data, xPrivKey: UInt32) {
        let hmac = Crypto.hmacSha512(seed)
        let privateKey = hmac[0..<32]
        let chainCode = hmac[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, xPrivKey: xPrivKey)
    }

    public init(extendedKey: Data) throws {
        try HDExtendedKey.isValid(extendedKey, isPublic: false)
        xPrivKey = extendedKey.prefix(4).hs.to(type: UInt32.self).bigEndian

        depth = extendedKey[5]
        fingerprint = extendedKey[6..<10].hs.to(type: UInt32.self)
        childIndex = extendedKey[10..<14].hs.to(type: UInt32.self)
        chainCode = extendedKey[14..<46]
        // 46 byte = 0
        raw = extendedKey[47..<79]
    }

    public func publicKey(compressed: Bool = true) -> HDPublicKey {
        HDPublicKey(privateKey: self, chainCode: chainCode, xPubKey: version.pubKey.rawValue, depth: depth, fingerprint: fingerprint, childIndex: childIndex, compressed: compressed)
    }

    var version: HDExtendedKeyVersion {
        HDExtendedKeyVersion(rawValue: xPrivKey) ?? .xprv  //created key successfully validated before creation, so fallback not using
    }

    var data: Data {
        var data = Data()
        data += xPrivKey.bigEndian.data
        data += Data([depth.littleEndian])
        data += fingerprint.littleEndian.data
        data += childIndex.littleEndian.data
        data += chainCode
        data += Data([0])
        data += raw
        let checksum = Crypto.doubleSha256(data).prefix(4)
        return data + checksum
    }

    func extended() -> String {
        Base58.encode(data)
    }

    public func derived(at index: UInt32, hardened: Bool) throws -> HDPrivateKey {
        let edge: UInt32 = 0x80000000
        guard (edge & index) == 0 else {
            throw DerivationError.invalidChildIndex
        }

        let publicKey = Crypto.publicKey(privateKey: raw, compressed: true)

        var data = Data()
        if hardened {
            data += Data([0])
            data += raw
        } else {
            data += publicKey
        }

        let derivingIndex = CFSwapInt32BigToHost(hardened ? (edge | index) : index)
        data += derivingIndex.data

        let digest = Crypto.hmacSha512(data, key: chainCode)
        let factor = digest[0..<32]

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var rawVariable = raw
        if rawVariable.withUnsafeMutableBytes ({ privateKeyBytes -> Int32 in
            factor.withUnsafeBytes { factorBytes -> Int32 in
                guard let factorPointer = factorBytes.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                guard let privateKeyPointer = privateKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                return secp256k1_ec_privkey_tweak_add(context, privateKeyPointer, factorPointer)
           }
        }) == 0 {
           throw DerivationError.invalidCombineTweak
        }

        let derivedPrivateKey = Data(rawVariable)
        let derivedChainCode = digest[32..<64]

        let hash = Crypto.ripeMd160Sha256(publicKey)
        let fingerprint: UInt32 = hash[0..<4].hs.to(type: UInt32.self)

        return HDPrivateKey(
                privateKey: derivedPrivateKey,
                chainCode: derivedChainCode,
                xPrivKey: xPrivKey,
                depth: depth + 1,
                fingerprint: fingerprint,
                childIndex: derivingIndex
        )
    }

    public func derivedNonHardenedPublicKeys(at indices: Range<UInt32>) throws -> [HDPublicKey] {
        guard let firstIndex = indices.first, let lastIndex = indices.last else {
            return []
        }

        if (0x80000000 & firstIndex) != 0 && (0x80000000 & lastIndex) != 0 {
            fatalError("invalid child index")
        }

        let hdPubKey = publicKey()
        var keys = [HDPublicKey]()

        try indices.forEach { int32 in
            keys.append(try hdPubKey.derived(at: int32))
        }

        return keys
    }
    
}

extension HDPrivateKey {

    public var description: String {
        "\(raw.hs.hex) ::: \(chainCode.hs.hex) ::: depth: \(depth) - fingerprint: \(fingerprint) - childIndex: \(childIndex)"
    }

}

public enum DerivationError: Error {
    case derivationFailed
    case invalidChildIndex
    case invalidHmacToPoint
    case invalidRawToPoint
    case invalidCombinePoints
    case invalidCombineTweak
}
