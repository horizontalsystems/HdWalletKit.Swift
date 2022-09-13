import Foundation
import Crypto
import BigInt

public class HDPrivateKey {
    let xPrivKey: UInt32
    let xPubKey: UInt32
    let depth: UInt8
    let fingerprint: UInt32
    let childIndex: UInt32

    public let raw: Data
    let chainCode: Data

    init(privateKey: Data, chainCode: Data, xPrivKey: UInt32, xPubKey: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        let zeros = privateKey.count < 32 ? [UInt8](repeating: 0, count: 32 - privateKey.count) : []

        raw = Data(zeros) + privateKey
        self.chainCode = chainCode
        self.xPrivKey = xPrivKey
        self.xPubKey = xPubKey
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    public convenience init(privateKey: Data, chainCode: Data, xPrivKey: UInt32, xPubKey: UInt32) {
        self.init(privateKey: privateKey, chainCode: chainCode, xPrivKey: xPrivKey, xPubKey: xPubKey, depth: 0, fingerprint: 0, childIndex: 0)
    }

    convenience init(seed: Data, xPrivKey: UInt32, xPubKey: UInt32) {
        let hmac = Crypto.hmacSha512(seed)
        let privateKey = hmac[0..<32]
        let chainCode = hmac[32..<64]
        self.init(privateKey: privateKey, chainCode: chainCode, xPrivKey: xPrivKey, xPubKey: xPubKey)
    }

    public func publicKey(compressed: Bool = true) -> HDPublicKey {
        HDPublicKey(privateKey: self, chainCode: chainCode, xPubKey: xPubKey, depth: depth, fingerprint: fingerprint, childIndex: childIndex, compressed: compressed)
    }

    func extended() -> String {
        var data = Data()
        data += xPrivKey.bigEndian.data
        data += Data([depth.littleEndian])
        data += fingerprint.littleEndian.data
        data += childIndex.littleEndian.data
        data += chainCode
        data += Data([0])
        data += raw
        let checksum = Crypto.doubleSha256(data).prefix(4)
        return Base58.encode(data + checksum)
    }

    public func derived(at index: UInt32, hardened: Bool) -> HDPrivateKey {
        let edge: UInt32 = 0x80000000
        guard (edge & index) == 0 else { fatalError("Invalid child index") }

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
        let factor = BigUInt(digest[0..<32])

        let curveOrder = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
        let derivedPrivateKey = ((BigUInt(raw) + factor) % curveOrder).serialize()
        let derivedChainCode = digest[32..<64]

        let hash = Crypto.ripeMd160Sha256(publicKey)
        let fingerprint: UInt32 = hash[0..<4].uint32

        return HDPrivateKey(
                privateKey: derivedPrivateKey,
                chainCode: derivedChainCode,
                xPrivKey: xPrivKey,
                xPubKey: xPubKey,
                depth: depth + 1,
                fingerprint: fingerprint,
                childIndex: derivingIndex
        )
    }

    func derivedNonHardenedPublicKeys(at indices: Range<UInt32>) throws -> [HDPublicKey] {
        []
        //todo:
//        guard let firstIndex = indices.first, let lastIndex = indices.last else {
//            return []
//        }
//
//        if (0x80000000 & firstIndex) != 0 && (0x80000000 & lastIndex) != 0 {
//            fatalError("invalid child index")
//        }
//
//        let hdKey = HDKey(privateKey: nil, publicKey: publicKey().raw, chainCode: chainCode, depth: depth, fingerprint: fingerprint, childIndex: childIndex)
//
//        var keys = [HDPublicKey]()
//
//        for i in indices {
//            guard let key = Kit.derivedHDKey(hdKey: hdKey, at: i, hardened: false), let publicKey = key.publicKey else {
//                throw DerivationError.derivateionFailed
//            }
//
//            keys.append(HDPublicKey(raw: publicKey, chainCode: chainCode, xPubKey: xPubKey, depth: key.depth, fingerprint: key.fingerprint, childIndex: key.childIndex))
//        }
//
//        return keys
    }
    
}

enum DerivationError : Error {
    case derivationFailed
}
