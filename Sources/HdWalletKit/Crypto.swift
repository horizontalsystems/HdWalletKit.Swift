import Foundation
import Crypto
import CommonCrypto
import secp256k1

public struct Crypto {

    static func hmacSha512(_ data: Data, key: Data = "Bitcoin seed".data(using: .ascii)!) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
    }

    static func deriveKey(password: String, salt: Data, iterations: Int = 2048, keyLength: Int = 64) -> Data {
        var derivedKeyData = Data(repeating: 0, count: keyLength)
        let derivationStatus = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        password, password.count,
                        saltBytes, salt.count,
                        CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        derivedKeyBytes, keyLength)
            }
        }
        if (derivationStatus != 0) { // todo: Handle case with wrong status
            print("=> Can't derive key: \(derivationStatus)")
            return Data()
        }

        return derivedKeyData
    }

    static func publicKey(_ publicKey: secp256k1_pubkey, compressed: Bool) -> Data {
        var outputLen: Int = compressed ? 33 : 65

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }

        var publicKey = publicKey
        var output = Data(count: outputLen)
        let compressedFlags = compressed ? UInt32(SECP256K1_EC_COMPRESSED) : UInt32(SECP256K1_EC_UNCOMPRESSED)
        output.withUnsafeMutableBytes { pointer -> Void in
            guard let p = pointer.bindMemory(to: UInt8.self).baseAddress else { return }
            secp256k1_ec_pubkey_serialize(context, p, &outputLen, &publicKey, compressedFlags)
        }

        return output
    }

    static func publicKey(privateKey: Data, compressed: Bool) -> Data {
        let privateKey = privateKey.bytes
        var pubKeyPoint = secp256k1_pubkey()

        let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!
        defer {
            secp256k1_context_destroy(context)
        }
        _ = SecpResult(secp256k1_ec_pubkey_create(context, &pubKeyPoint, privateKey))


        return publicKey(pubKeyPoint, compressed: compressed)
    }

}

public extension Crypto {

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func ripeMd160(_ data: Data) -> Data {
        RIPEMD160.hash(data)
    }

    static func doubleSha256(_ data: Data) -> Data {
        sha256(sha256(data))
    }

    static func ripeMd160Sha256(_ data: Data) -> Data {
        ripeMd160(sha256(data))
    }

}

enum SecpResult {
    case success
    case failure

    init(_ result:Int32) {
        switch result {
        case 1:
            self = .success
        default:
            self = .failure
        }
    }
}
