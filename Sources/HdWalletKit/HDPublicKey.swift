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
        raw = HDPublicKey.from(privateKey: privateKey.raw, compression: compressed)
        chainCode = privateKey.chainCode
        depth = 0
        fingerprint = 0
        childIndex = 0
    }

    init(privateKey: HDPrivateKey, chainCode: Data, xPubKey: UInt32, depth: UInt8, fingerprint: UInt32, childIndex: UInt32, compressed: Bool) {
        self.xPubKey = xPubKey
        raw = HDPublicKey.from(privateKey: privateKey.raw, compression: compressed)
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

    public func derived(at index: UInt32) throws -> HDPublicKey {
        let edge: UInt32 = 0x80000000
        guard (edge & index) == 0 else {
            throw DerivationError.invalidChildIndex
        }

        var data = Data()
        data += raw

        let derivingIndex = CFSwapInt32BigToHost(index)
        data += derivingIndex.data

        // Get HMAC result for (Parent + Index) and ChainCode
        let digest = Crypto.hmacSha512(data, key: chainCode)

        let hmacPrivateKey = digest[0..<32]
        let derivedChainCode = digest[32..<64]

        let hash = Crypto.ripeMd160Sha256(raw)
        let fingerprint = hash[0..<4].uint32

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY))!

        // Convert HMAC left side to Point, and combine with Parent PublicKey(Parent Point).
        var hmacPoint = secp256k1_pubkey()
        if hmacPrivateKey.withUnsafeBytes({ (privateKeyPointer: UnsafePointer<UInt8>) -> Int32 in
            secp256k1_ec_pubkey_create(context, UnsafeMutablePointer<secp256k1_pubkey>(&hmacPoint), privateKeyPointer)
        }) == 0 {
            throw DerivationError.invalidHmacToPoint
        }

        var parentPoint = secp256k1_pubkey()
        if raw.withUnsafeBytes({ (serializedKeyPointer: UnsafePointer<UInt8>) -> Int32 in
            secp256k1_ec_pubkey_parse(context, UnsafeMutablePointer<secp256k1_pubkey>(&parentPoint), serializedKeyPointer, raw.count)
        }) == 0 {
            throw DerivationError.invalidRawToPoint
        }

        var storage = ContiguousArray<secp256k1_pubkey>()
        let pointers = UnsafeMutablePointer< UnsafePointer<secp256k1_pubkey>? >.allocate(capacity: 2)
        defer {
            pointers.deinitialize(count: 2)
            pointers.deallocate()
            secp256k1_context_destroy(context)
        }
        storage.append(parentPoint)
        storage.append(hmacPoint)

        for i in 0 ..< 2 {
            withUnsafePointer(to: &storage[i]) { (ptr) -> Void in
                pointers.advanced(by: i).pointee = ptr
            }
        }
        let immutablePointer = UnsafePointer(pointers)

        // Combine to points to found new point (new public Key)
        var publicKey = secp256k1_pubkey()
        if withUnsafeMutablePointer(to: &publicKey, { (pubKeyPtr: UnsafeMutablePointer<secp256k1_pubkey>) -> Int32 in
            secp256k1_ec_pubkey_combine(context, pubKeyPtr, immutablePointer, 2)
        }) == 0 {
            throw DerivationError.invalidCombinePoints
        }

        let childPublicKey = Crypto.publicKey(publicKey, compressed: true)

        return HDPublicKey(
                raw: childPublicKey,
                chainCode: derivedChainCode,
                xPubKey: xPubKey,
                depth: depth + 1,
                fingerprint: fingerprint,
                childIndex: derivingIndex
        )
    }

    static func from(privateKey raw: Data, compression: Bool = false) -> Data {
        Crypto.publicKey(privateKey: raw, compressed: compression)
    }

}

extension HDPublicKey {

    public var description: String {
        "\(raw.hex) ::: \(chainCode.hex) ::: depth: \(depth) - fingerprint: \(fingerprint) - childIndex: \(childIndex)"
    }

}
