//
//  SymmetricEncrypt.swift
//  YFEncryptSwift
//
//  Created by HarryPhone on 2021/4/22.
//

import Foundation
import CommonCrypto

public struct SymmetricEncrypt {
    public enum Kind {
        case AES, DES, _3DES, CAST, RC4, RC2, Blowfish
    }
    
    public var type: Kind
    
    public var isNoPadding: Bool
    
    public init(type: Kind = .AES, isNoPadding: Bool = false) {
        self.type = type
        self.isNoPadding = isNoPadding
    }
    
    public func encrypt(data: Data, keyData: Data, iv: Data? = nil) -> Data? {
        return operation(data, keyData, iv, true)
    }
    
    public func decrypt(data: Data, keyData: Data, iv: Data? = nil) -> Data? {
        return operation(data, keyData, iv, false)
    }
    
    
    /// 常用加密算法，注意下面String的编码格式，如果编码格式不对，请调用原始的Data方法
    /// - Parameters:
    ///   - content: 需要加密的内容，utf8编码
    ///   - key: 秘钥，base64编码
    ///   - iv: nil为ECB加密模式，否则为CBC加密模式
    /// - Returns: 加密完的结果，base64编码
    public func encrypt(content: String, key: String, iv: [UInt8]? = nil) -> String? {
        guard let data = content.data(using: .utf8),
              let keyData = Data.init(base64Encoded: key)
        else {
            assertionFailure("对称加密String编码格式解析失败")
            return nil
        }
        
        if let result = encrypt(data: data, keyData: keyData, iv: iv == nil ? nil : Data(iv!)) {
            return result.base64EncodedString()
        } else {
            return nil
        }
    }
    
    /// 常用解密算法，注意下面String的编码格式，如果编码格式不对，请调用原始的Data方法
    /// - Parameters:
    ///   - content: 需要加密的内容，base64编码
    ///   - key: 秘钥，base64编码
    ///   - iv: nil为ECB加密模式，否则为CBC加密模式
    /// - Returns: 加密完的结果
    public func decrypt(content: String, key: String, iv: [UInt8]? = nil) -> Data? {
        guard let data = Data.init(base64Encoded: content),
              let keyData = Data.init(base64Encoded: key)
        else {
            assertionFailure("对称加密String编码格式解析失败")
            return nil
        }
        
        return decrypt(data: data, keyData: keyData, iv: iv == nil ? nil : Data(iv!))
    }
    
    public enum KeyKind {
        case AES128, AES192, AES256, DES, _3DES
    }
    
    /// 生成随机秘钥
    /// - Parameter keyKind: 提供了常用的几种对称加密方式
    /// - Returns: 随机秘钥，是base64编码的字符串
    public static func generateRandomKey(_ keyKind: KeyKind) -> String {
        switch keyKind {
        case .AES128:
            return String.yf.randomKey(dataLength: kCCKeySizeAES128)
        case .AES192:
            return String.yf.randomKey(dataLength: kCCKeySizeAES192)
        case .AES256:
            return String.yf.randomKey(dataLength: kCCKeySizeAES256)
        case .DES:
            return String.yf.randomKey(dataLength: kCCAlgorithmDES)
        case ._3DES:
            return String.yf.randomKey(dataLength: kCCAlgorithm3DES)
        }
    }
    
}

extension SymmetricEncrypt {
    
    func operation(_ data: Data, _ keyData: Data, _ iv: Data?, _ isEncrypt: Bool) -> Data? {
        if data.count == 0 || keyData.count == 0 {
            assertionFailure("The encrypted content or secret key is empty")
            return nil
        }
        
        var algorithm: Int
        var blockSize: Int
        var keySize = keyData.count
        
        switch type {
        case .AES:
            algorithm = kCCAlgorithmAES128
            blockSize = kCCBlockSizeAES128
            if keySize <= kCCKeySizeAES128 {
                keySize = kCCKeySizeAES128
            } else if keySize <= kCCKeySizeAES192 {
                keySize = kCCKeySizeAES192
            } else {
                keySize = kCCKeySizeAES256
            }
        case .DES:
            algorithm = kCCAlgorithmDES
            blockSize = kCCBlockSizeDES
            keySize = kCCKeySizeDES
        case ._3DES:
            algorithm = kCCAlgorithm3DES
            blockSize = kCCBlockSize3DES
            keySize = kCCKeySize3DES
        case .CAST:
            algorithm = kCCAlgorithmCAST
            blockSize = kCCBlockSizeCAST
            keySize = min(max(keySize, kCCKeySizeMinCAST), kCCKeySizeMaxCAST)
        case .RC4:
            algorithm = kCCAlgorithmRC4
            blockSize = kCCBlockSizeRC2
            keySize = min(max(keySize, kCCKeySizeMinRC4), kCCKeySizeMaxRC4)
        case .RC2:
            algorithm = kCCAlgorithmRC2
            blockSize = kCCBlockSizeRC2
            keySize = min(max(keySize, kCCKeySizeMinRC2), kCCKeySizeMaxRC2)
        case .Blowfish:
            algorithm = kCCAlgorithmBlowfish
            blockSize = kCCBlockSizeBlowfish
            keySize = min(max(keySize, kCCKeySizeMinBlowfish), kCCKeySizeMaxBlowfish)
        }
        
        var option: CCOptions = 0
        if !isNoPadding {
            option |= UInt32(kCCOptionPKCS7Padding)
        }
        
        if iv == nil {
            option |= UInt32(kCCOptionECBMode)
        }
        
        let bufferSize = data.count + blockSize
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferSize, alignment: 1)
        defer {
            buffer.deallocate()
        }
        
        var encryptedSize = 0
        let cryptStatus = CCCrypt(isEncrypt ? CCOperation(kCCEncrypt) : CCOperation(kCCDecrypt),
                                  CCAlgorithm(algorithm),
                                  option,
                                  NSData(data: keyData).bytes,
                                  keySize,
                                  (iv != nil) ? NSData(data: iv!).bytes : NSData().bytes,
                                  NSData(data: data).bytes,
                                  data.count,
                                  buffer,
                                  bufferSize,
                                  &encryptedSize)
        if cryptStatus == kCCSuccess {
            return Data.init(bytes: buffer, count: encryptedSize)
        } else {
            print("SymmetricEncrypt errorStatus: \(cryptStatus)")
            return nil
        }
        
    }
}
