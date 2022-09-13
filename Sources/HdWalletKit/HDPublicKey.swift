import Foundation
import CryptoKit
import secp256k1
import secp256k1_bindings

public class HDPublicKey {
    let xPubKey: UInt32
    let depth: UInt8
    let fingerprint: UInt32
    let childIndex: UInt32

    public let raw: Data
    let chainCode: Data

    init(privateKey: HDPrivateKey, xPubKey: UInt32, compressed: Bool = true) {
        self.xPubKey = xPubKey
        self.raw = HDPublicKey.from(privateKey: privateKey.raw, compression: compressed)
        self.chainCode = privateKey.chainCode
        self.depth = 0
        self.fingerprint = 0
        self.childIndex = 0
    }

    init(privateKey: HDPrivateKey, chainCode: Data, xPubKey: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32, compressed: Bool) {
        self.xPubKey = xPubKey
        self.raw = HDPublicKey.from(privateKey: privateKey.raw, compression: compressed)
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    init(raw: Data, chainCode: Data, xPubKey: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32) {
        self.xPubKey = xPubKey
        self.raw = raw
        self.chainCode = chainCode
        self.depth = depth
        self.fingerprint = fingerprint
        self.childIndex = childIndex
    }

    func extended() -> String {
        var data = Data()
        data += xPubKey.bigEndian.data
        data += Data([depth])
        data += fingerprint.littleEndian.data
        data += childIndex.littleEndian.data
        data += chainCode
        data += raw
        let checksum = Crypto.doubleSha256(data).prefix(4)
        return Base58.encode(data + checksum)
    }

    public func derived(at index: UInt32) -> HDPublicKey {
        let edge: UInt32 = 0x80000000
        guard (edge & index) == 0 else { fatalError("Invalid child index") }

        var data = Data()
        data += raw

        let derivingIndex = CFSwapInt32BigToHost(index)
        data += derivingIndex.data

        let digest = Crypto.hmacSha512(data, key: chainCode)
        let factor = digest[0..<32]

        print("==> ==> PublicKey : \(raw.hex)")
        let publicKey = try! secp256k1.KeyAgreement.PublicKey(rawRepresentation: raw, format: .compressed)
        print(publicKey.xonly.rawRepresentation.hex)

//        let curveOrder = BigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
//        let derivedPrivateKey = ((BigInt(raw) + factor) % curveOrder).serialize() //todo: Check endian style
        let derivedChainCode = digest[32..<64]

        let fingerprint = raw[0..<4].uint32

        return HDPublicKey(
                raw: factor,
                chainCode: derivedChainCode,
                xPubKey: xPubKey,
                depth: depth + 1,
                fingerprint: fingerprint,
                childIndex: derivingIndex
        )
    }

//    public func derived(at index: UInt32) throws -> HDPublicKey {
//        // As we use explicit parameter "hardened", do not allow higher bit set.
//        if ((0x80000000 & index) != 0) {
//            fatalError("invalid child index")
//        }
//
////        guard let derivedKey = Kit.derivedHDKey(hdKey: HDKey(privateKey: nil, publicKey: raw, chainCode: chainCode, depth: depth, fingerprint: fingerprint, childIndex: childIndex), at: index, hardened: false) else {
////            throw DerivationError.derivationFailed
////        }
//
//        return HDPublicKey(raw: Data(), chainCode: Data(), xPubKey: xPubKey, depth: 0, fingerprint: 0, childIndex: 0)
//    }

    static func from(privateKey raw: Data, compression: Bool = false) -> Data {
        Crypto.publicKey(privateKey: raw, compressed: compression)
    }

}
