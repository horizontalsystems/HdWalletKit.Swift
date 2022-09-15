import UIKit
import HdWalletKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()

        let words = ["piece", "hunt", "scene", "agent", "subject", "clever", "expand", "maze", "drastic", "flash", "local", "usage"]
        guard let seed = Mnemonic.seed(mnemonic: words) else {
            print("==! Can't create Seed!")
            return
        }
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
        for i in 0..<20 {
            print("================= \(i) ===================")
            let childKey = try privateKey.derived(at: UInt32(i), hardened: false)

            print("==> Private key: \(childKey.raw.hex)")
            print("==> Public key: \(childKey.publicKey(compressed: true).description)")
            let pubKey = privateKey.publicKey()
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
