import HsExtensions

public enum HDExtendedKeyType: UInt32, CaseIterable {
    case xprv = 0x0488ade4
    case xpub = 0x0488b21e
    case yprv = 0x049d7878
    case ypub = 0x049d7cb2
    case Yprv = 0x0295b005
    case Ypub = 0x0295b43f
    case zprv = 0x04b2430c
    case zpub = 0x04b24746
    case Zprv = 0x02aa7a99
    case Zpub = 0x02aa7ed3
    case Ltpv = 0x019d9cfe
    case Ltub = 0x019da462
    case Mtpv = 0x01b26792
    case Mtub = 0x01b26ef6

    public init(mnemonicDerivation: MnemonicDerivation, coinType: ExtendedKeyCoinType, isPrivate: Bool = true) throws {
        switch mnemonicDerivation {
        case .bip44:
            switch coinType {
            case .bitcoin: self = isPrivate ? .xprv : .xpub
            case .litecoin: self = isPrivate ? .Ltpv : .Ltub
            }
        case .bip49:
            switch coinType {
            case .bitcoin: self = isPrivate ? .yprv : .ypub
            case .litecoin: self = isPrivate ? .Mtpv : .Mtub
            }
        case .bip84:
            switch coinType {
            case .bitcoin: self = isPrivate ? .zprv : .zpub
            case .litecoin: throw ParsingError.wrongMnemonicDerivation
            }
        }
    }

    public init?(string: String) {
        guard let result = Self.allCases.first(where: { $0.string == string }) else {
            return nil
        }

        self = result
    }

    public var string: String {
        switch self {
        case .xprv: return "xprv"
        case .xpub: return "xpub"
        case .yprv: return "yprv"
        case .ypub: return "ypub"
        case .Yprv: return "Yprv"
        case .Ypub: return "Ypub"
        case .zprv: return "zprv"
        case .zpub: return "zpub"
        case .Zprv: return "Zprv"
        case .Zpub: return "Zpub"
        case .Ltpv: return "Ltpv"
        case .Ltub: return "Ltub"
        case .Mtpv: return "Mtpv"
        case .Mtub: return "Mtub"
        }
    }

    public var mnemonicDerivation: MnemonicDerivation {
        switch self {
        case .xprv, .xpub, .Ltpv, .Ltub: return .bip44
        case .yprv, .ypub, .Yprv, .Ypub, .Mtpv, .Mtub: return .bip49
        case .zprv, .zpub, .Zprv, .Zpub: return .bip84
        }
    }

    public var coinType: ExtendedKeyCoinType {
        switch self {
        case .xprv, .xpub, .yprv, .ypub, .Yprv, .Ypub, .zprv, .zpub, .Zprv, .Zpub: return .bitcoin
        case .Ltpv, .Ltub, .Mtpv, .Mtub: return .litecoin
        }
    }

    public var pubKey: Self {
        switch self {
        case .xprv: return .xpub
        case .yprv: return .ypub
        case .Yprv: return .Ypub
        case .zprv: return .zpub
        case .Zprv: return .Zpub
        case .Ltpv: return .Ltub
        case .Mtpv: return .Mtub
        default: return self
        }
    }

    public var isPublic: Bool {
        switch self {
        case .xpub, .ypub, .zpub, .Ypub, .Zpub,.Ltub, .Mtub: return true
        default: return false
        }
    }

}

extension HDExtendedKeyType {

    enum ParsingError: Error {
        case wrongMnemonicDerivation
    }

}

public enum MnemonicDerivation {
    case bip44, bip49, bip84
}

public enum ExtendedKeyCoinType {
    case bitcoin
    case litecoin
}
