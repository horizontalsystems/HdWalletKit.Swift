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
            generateAndCheckPublicKeys(privateKey: privateKey)
        } catch {
            print("Can't get private key!")
        }
    }

    func generateAndCheckPublicKeys(privateKey: HDPrivateKey) {
        print("==> Private key: \(privateKey.raw.hex)")
        print("==> Public key: \(privateKey.publicKey(compressed: true).raw.hex)")
        var last = privateKey
        for i in 0..<5 {
            print("================= \(i) ===================")
            let privKey = last.derived(at: UInt32(i), hardened: false)

            print("==> Private key: \(privKey.raw.hex)")
            print("==> Public key: \(privKey.publicKey(compressed: true).raw.hex)")
            let pubKey = last.publicKey()
            print("==> DerivedPublic key: \(pubKey.derived(at: UInt32(i)).raw.hex)")
            last = privKey
        }

    }

}
