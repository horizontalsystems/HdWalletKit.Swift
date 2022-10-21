import Foundation

public class HDAccountWallet {
    private let keychain: HDKeychain

    public var gapLimit: Int

    public init(privateKey: HDPrivateKey, gapLimit: Int = 5) {
        self.gapLimit = gapLimit

        keychain = HDKeychain(privateKey: privateKey)
    }

    public func privateKey(index: Int, chain: Chain) throws -> HDPrivateKey {
        try privateKey(path: "\(chain.rawValue)/\(index)")
    }

    public func privateKey(path: String) throws -> HDPrivateKey {
        try keychain.derivedKey(path: path)
    }

    public func publicKey(index: Int, chain: Chain) throws -> HDPublicKey {
        try privateKey(index: index, chain: chain).publicKey()
    }

    public func publicKeys(indices: Range<UInt32>, chain: Chain) throws -> [HDPublicKey] {
        try keychain.derivedNonHardenedPublicKeys(path: "\(chain.rawValue)", indices: indices)
    }

    public enum Chain : Int {
        case external
        case `internal`
    }

}
