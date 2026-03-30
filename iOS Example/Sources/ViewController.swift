import HdWalletKit
import UIKit

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()

        let words = ["piece", "hunt", "scene", "agent", "subject", "clever", "expand", "maze", "drastic", "flash", "local", "usage"]
        guard let seed = Mnemonic.seed(mnemonic: words) else {
            print("==! Can't create Seed!")
            return
        }
        print("==> Seed: \(seed.hs.hex)")

        let hdWallet = HDWallet(seed: seed, coinType: 0, xPrivKey: HDExtendedKeyVersion.xprv.rawValue)
        do {
            let privateKey = try hdWallet.privateKey(account: 0, index: 44, chain: .internal)
            print("==> HD Private key: \(privateKey.raw.hs.hex)")
            print("==> HD Public key: \(privateKey.publicKey(compressed: true).raw.hs.hex)")

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
        for i in 0 ..< 20 {
            print("================= \(i) ===================")
            let childKey = try privateKey.derived(at: UInt32(i), hardened: false)

            print("==> Private key: \(childKey.raw.hs.hex)")
            print("==> Public key: \(childKey.publicKey(compressed: true).description)")
            let pubKey = privateKey.publicKey()
            try print("==> DerivedPublic key: \(pubKey.derived(at: UInt32(i)).description)")
        }
    }

    func derivedNonHardenedPublicKeys(privateKey: HDPrivateKey) throws {
        do {
            let keys = try privateKey.derivedNonHardenedPublicKeys(at: 0 ..< 5)
            for (index, key) in keys.enumerated() {
                print("==> \(index) ==> Public key: \(key.description)")
            }
        } catch {
            print("Can't get private key!")
            return
        }
    }
}
