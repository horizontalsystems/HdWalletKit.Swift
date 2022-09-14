import UIKit
import HdWalletKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        let words = ["piece", "hunt", "scene", "agent", "subject", "clever", "expand", "maze", "drastic", "flash", "local", "usage"]
        let seed = Mnemonic.seed(mnemonic: words)
        print("==> Seed: \(seed.hex)")

        let hdWallet = HDWallet(seed: seed, coinType: 0, xPrivKey: 0x0488ade4, xPubKey: 0x0488b21e)
        do {
            let privateKey = try hdWallet.privateKey(account: 0, index: 44, chain: .internal)
            print("==> HD Private key: \(privateKey.raw.hex)")
            print("==> HD Public key: \(privateKey.publicKey(compressed: true).raw.hex)")

            print("========== Generate and check PublickKeys ===============")
            try generateAndCheckPublicKeys(privateKey: privateKey)
            print()
            print("=======================================================")
            try derivedNonHardenedPublicKeys(privateKey: privateKey)
        } catch {
            print("Can't get private key!")
        }
    }

    func generateAndCheckPublicKeys(privateKey: HDPrivateKey) throws {
        var last = privateKey
        for i in 0..<20 {
            print("================= \(i) ===================")
            let privKey = try last.derived(at: UInt32(i), hardened: false)

            print("==> Private key: \(privKey.raw.hex)")
            print("==> Public key: \(privKey.publicKey(compressed: true).description)")

            let pubKey = last.publicKey()
            print("==> DerivedPublic key: \(try pubKey.derived(at: UInt32(i)).description)")
        }
    }

    func derivedNonHardenedPublicKeys(privateKey: HDPrivateKey) throws {
        do {
            let keys = try privateKey.derivedNonHardenedPublicKeys(at: 0..<5)
            keys.enumerated().forEach { index, key in
                print("==> \(index) ==> Public key: \(key.description)")
            }
        } catch {
            print("Can't get private key!")
            return
        }
    }

}
