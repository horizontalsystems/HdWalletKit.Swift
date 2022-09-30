import Foundation
import HsCryptoKit

extension String {

    func pad(toSize: Int) -> String {
        guard count < toSize else { return self }
        var padded = self
        for _ in 0..<(toSize - count) {
            padded = "0" + padded
        }
        return padded
    }

    /// turns an array of "0"s and "1"s into bytes. fails if count is not modulus of 8
    func bitStringToBytes() -> Data? {
        let length = 8
        guard count % length == 0 else {
            return nil
        }
        var data = Data(capacity: count)

        for i in 0 ..< count / length {
            let startIdx = self.index(startIndex, offsetBy: i * length)
            let subArray = self[startIdx ..< self.index(startIdx, offsetBy: length)]
            let subString = String(subArray)
            guard let byte = UInt8(subString, radix: 2) else {
                return nil
            }
            data.append(byte)
        }
        return data
    }

}

extension UInt8 {

    func mnemonicBits() -> [String] {
        let totalBitsCount = MemoryLayout<UInt8>.size * 8

        var bitsArray = [String](repeating: "0", count: totalBitsCount)

        for j in 0 ..< totalBitsCount {
            let bitVal: UInt8 = 1 << UInt8(totalBitsCount - 1 - j)
            let check = self & bitVal

            if check != 0 {
                bitsArray[j] = "1"
            }
        }

        return bitsArray
    }

}

extension Data {

    func toBitArray() -> [String] {
        var toReturn = [String]()
        for num in [UInt8](self) {
            toReturn.append(contentsOf: num.mnemonicBits())
        }

        return toReturn
    }

    var uint32: UInt32 {
        get {
            let i32array = self.withUnsafeBytes { $0.load(as: UInt32.self) }
            return i32array
        }
    }

}

extension UInt32 {

    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
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
    public var hex: String {
        map({ String(format: "%02x", $0) }).joined()
    }

}
