import UIKit
import HdWalletKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        let words = ["piece", "hunt", "scene", "agent", "subject", "clever", "expand", "maze", "drastic", "flash", "local", "usage"]
        let seed = Mnemonic.seed(mnemonic: words)
        let hdWallet = HDWallet(seed: seed, coinType: 0, xPrivKey: 1, xPubKey: 1)

        do {
            let privateKey = try hdWallet.privateKey(account: 0, index: 1, chain: .external)
            print("Private key: \(privateKey.raw.hexString)")
        } catch {
            print("Can't get private key!")
        }
    }

}

extension Data {
    /// Initializes `Data` with a hex string representation.
    public init?(hexString: String) {
        let string: String
        if hexString.hasPrefix("0x") {
            string = String(hexString.dropFirst(2))
        } else {
            string = hexString
        }

        // Convert the string to bytes for better performance
        guard let stringData = string.data(using: .ascii, allowLossyConversion: true) else {
            return nil
        }

        self.init(capacity: string.count / 2)
        let stringBytes = Array(stringData)
        for i in stride(from: 0, to: stringBytes.count, by: 2) {
            guard let high = Data.value(of: stringBytes[i]) else {
                return nil
            }
            if i < stringBytes.count - 1, let low = Data.value(of: stringBytes[i + 1]) {
                append((high << 4) | low)
            } else {
                append(high)
            }
        }
    }

    /// Converts an ASCII byte to a hex value.
    private static func value(of nibble: UInt8) -> UInt8? {
        guard let letter = String(bytes: [nibble], encoding: .ascii) else { return nil }
        return UInt8(letter, radix: 16)
    }

    /// Returns the hex string representation of the data.
    public var hexString: String {
        map({ String(format: "%02x", $0) }).joined()
    }

}
