import XCTest
import HdWalletKit

class HDWalletKitTests: XCTestCase {

    func testExample() {
        let words = try! Mnemonic.generate()
        let seed = Mnemonic.seed(mnemonic: words)!
        let hdWallet = HDWallet(seed: seed, coinType: 1, xPrivKey: HDExtendedKeyVersion.xprv.rawValue)

        _ = try! hdWallet.privateKey(account: 1, index: 1, chain: .external)

        XCTAssert(true, "Pass")
    }

    func testPublicKeyInitializationFromBip49ExtendedPublicKeyString() {
        let words = try! Mnemonic.generate()
        let seed = Mnemonic.seed(mnemonic: words)!
        let hdWallet = HDWallet(seed: seed, coinType: 1, xPrivKey: HDExtendedKeyVersion.xprv.rawValue, purpose: .bip49)

        let k = try! hdWallet.publicKeys(account: 0, indices: 0..<1, chain: .external).first!
        let extended = try! hdWallet.privateKey(path: "m/49'/1'/0'").publicKey().extended()
        let k2 = try! ReadOnlyHDWallet.publicKeys(extendedPublicKey: extended, indices: 0..<5, chain: .external).first!

        XCTAssertEqual(k.version, k2.version)
        XCTAssertEqual(k.depth, k2.depth)
        XCTAssertEqual(k.fingerprint, k2.fingerprint)
        XCTAssertEqual(k.childIndex, k2.childIndex)
        XCTAssertEqual(k.raw, k2.raw)
        XCTAssertEqual(k.chainCode, k2.chainCode)
    }

    func testPublicKeyInitializationFromBip86ExtendedPublicKeyString() {
        let words = try! Mnemonic.generate()
        let seed = Mnemonic.seed(mnemonic: words)!
        let hdWallet = HDWallet(seed: seed, coinType: 1, xPrivKey: HDExtendedKeyVersion.xprv.rawValue, purpose: .bip86)
        
        let k = try! hdWallet.publicKeys(account: 0, indices: 0..<1, chain: .external).first!
        let extended = try! hdWallet.privateKey(path: "m/86'/1'/0'").publicKey().extended()
        let k2 = try! ReadOnlyHDWallet.publicKeys(extendedPublicKey: extended, indices: 0..<5, chain: .external).first!
        
        XCTAssertEqual(k.version, k2.version)
        XCTAssertEqual(k.depth, k2.depth)
        XCTAssertEqual(k.fingerprint, k2.fingerprint)
        XCTAssertEqual(k.childIndex, k2.childIndex)
        XCTAssertEqual(k.raw, k2.raw)
        XCTAssertEqual(k.chainCode, k2.chainCode)
    }

    func testBatchPublicKeyGeneration() {
        let words = try! Mnemonic.generate()
        let seed = Mnemonic.seed(mnemonic: words)!
        let hdWallet = HDWallet(seed: seed, coinType: 1, xPrivKey: HDExtendedKeyVersion.xprv.rawValue)

        var publicKeys = [HDPublicKey]()
        for i in 0..<10 {
            publicKeys.append(try! hdWallet.publicKey(account: 0, index: i, chain: .external))
        }

        let batchPublicKeys: [HDPublicKey] = try! hdWallet.publicKeys(account: 0, indices: 0..<10, chain: .external)

        XCTAssertEqual(publicKeys.count, batchPublicKeys.count)

        for (i, p) in publicKeys.enumerated() {
            let bp = batchPublicKeys[i]

            XCTAssertEqual(p.raw, bp.raw)
        }
    }
    
    func testChineseMnemonicToSeed() {
        let seed = Mnemonic.seed(mnemonic: "みすえる　ろれつ　げざい　かがく　けんすう　てんけん　つうか　ひさい　そんみん　せんたく　りそく　えいえん".wordsList)!
        XCTAssertEqual(seed.hex, "38783fa1226a63555ac4c582e8fa5b4a354aad4867510fc61288a91e3cd602743f2940e784e786468fcd64e71d745113fc8301fe64544cfbd022f48df13e0549")
    }
    
    let NFCEncodedWords = "superbe volume dénuder caribou donjon navire médaille réitérer instinct heureux ventouse barrage".wordsList

    func testFrenchMnemonicToSeed() {
        let seed = Mnemonic.seed(mnemonic: NFCEncodedWords)!
        XCTAssertEqual(seed.hex, "0f018e4e329afbe1453cae154bd2666a7f57bc92fab055bd3591ce3d137ae1df6994c636590f10cbaa93caa17a83a7f4768f087ac9e5d31cd1a396e50841b3fc")
    }

    func testFrenchMnemonicToSeedNonStandard() {
        let seed = Mnemonic.seedNonStandard(mnemonic: NFCEncodedWords)!
        XCTAssertEqual(seed.hex, "8dadef68dcaca7d8ffaa0354a66a3fb8227ac3f756273233b8cf978f69c3942c683dc5327b08431e7df585d42d86070b2dbda2c290763ae268df9c8589fee97f")
    }
    
    func testLanguageEnglish() {
        let englishWords = "tonight wrestle dress clay empower permit obscure skirt lock key weasel boss".wordsList
        XCTAssertEqual(Mnemonic.language(words: englishWords), Mnemonic.Language.english)
    }
    
    func testLanguageChinese() {
        let englishWords = "叙 玄 告 斗 充 售 岸 陵 床 零 邵 长".wordsList
        XCTAssertEqual(Mnemonic.language(words: englishWords), Mnemonic.Language.simplifiedChinese)
    }

}

extension Data {
    
    var hex: String {
        self.reduce("") {$0 + String(format: "%02x", $1)}
    }
    
}

extension String {
    
    var wordsList: [String] {
        self.split(separator: " ").map(String.init)
    }
    
}
