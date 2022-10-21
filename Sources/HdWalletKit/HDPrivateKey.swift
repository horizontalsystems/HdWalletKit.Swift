import Foundation
import HsCryptoKit
import HsExtensions
import secp256k1

public class HDPrivateKey: HDKey {

    var privateKey: Data {
        raw.suffix(32) // first byte is 0x00
    }

    var extendedVersion: HDExtendedKeyVersion {
        HDExtendedKeyVersion(rawValue: version) ?? .xprv  //created key successfully validated before creation, so fallback not using
    }

    override public init(raw: Data, chainCode: Data, version: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        super.init(raw: raw,
                chainCode: chainCode,
                version: version,
                depth: depth,
                fingerprint: fingerprint,
                childIndex: childIndex)
    }

    override init(extendedKey: Data) throws {
        try super.init(extendedKey: extendedKey)
    }

    public init(privateKey: Data, chainCode: Data, version: UInt32, depth: UInt8 = 0, fingerprint: UInt32 = 0, childIndex: UInt32 = 0) {
        let zeros = privateKey.count < 33 ? [UInt8](repeating: 0, count: 33 - privateKey.count) : []

        super.init(raw: Data(zeros) + privateKey,
                chainCode: chainCode,
                version: version,
                depth: depth,
                fingerprint: fingerprint,
                childIndex: childIndex)
    }

    public convenience init(seed: Data, xPrivKey: UInt32) {
        let hmac = Crypto.hmacSha512(seed)
        let privateKey = hmac[0..<32]
        let chainCode = hmac[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, version: xPrivKey)
    }

}

public extension HDPrivateKey {

    func derived(at index: UInt32, hardened: Bool) throws -> HDPrivateKey {
        let edge: UInt32 = 0x80000000
        guard (edge & index) == 0 else {
            throw DerivationError.invalidChildIndex
        }

        let publicKey = Crypto.publicKey(privateKey: privateKey, compressed: true)

        var data = Data()
        if hardened {
            data += Data([0])
            data += privateKey
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

        var rawVariable = privateKey
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
                version: version,
                depth: depth + 1,
                fingerprint: fingerprint.bigEndian,
                childIndex: derivingIndex.bigEndian
        )
    }

    func publicKey(compressed: Bool = true) -> HDPublicKey {
        HDPublicKey(raw: Crypto.publicKey(privateKey: privateKey, compressed: compressed),
                chainCode: chainCode,
                version: extendedVersion.pubKey.rawValue,
                depth: depth,
                fingerprint: fingerprint,
                childIndex: childIndex)
    }

    func derivedNonHardenedPublicKeys(at indices: Range<UInt32>) throws -> [HDPublicKey] {
        guard let firstIndex = indices.first, let lastIndex = indices.last else {
            return []
        }

        if (0x80000000 & firstIndex) != 0 && (0x80000000 & lastIndex) != 0 {
            throw DerivationError.invalidChildIndex
        }

        let hdPubKey = publicKey()
        var keys = [HDPublicKey]()

        try indices.forEach { int32 in
            keys.append(try hdPubKey.derived(at: int32))
        }

        return keys
    }


}

public enum DerivationError: Error {
    case derivationFailed
    case invalidChildIndex
    case invalidPath
    case invalidHmacToPoint
    case invalidRawToPoint
    case invalidCombinePoints
    case invalidCombineTweak
}
