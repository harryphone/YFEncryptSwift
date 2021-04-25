//
//  EncryptExtension.swift
//  YFEncryptSwift
//
//  Created by HarryPhone on 2021/4/22.
//

import Foundation

// MARK: - 添加yf调用
public struct YFEncrypt<Base> {
    public let base: Base
    public init(_ base: Base) {
        self.base = base
    }
}

public protocol YFEncryptCompatible {
    
    associatedtype YFEncryptCompatibleType
    
    var yf: YFEncryptCompatibleType { get }
    static var yf: YFEncryptCompatibleType.Type { get }
    
}

public extension YFEncryptCompatible {
    
    var yf: YFEncrypt<Self> {
        return YFEncrypt(self)
    }
    
    static var yf: YFEncrypt<Self>.Type {
        return YFEncrypt<Self>.self
    }
}

// MARK: - string 加密扩展

extension String: YFEncryptCompatible { }

extension YFEncrypt where Base == String {
    
    // MARK: - public
    
    /// 生成随机秘钥字符串，base64编码的
    /// - Parameter dataLength: 数据长度，例如，如果随机生成aes128的秘钥，传16.
    /// - Returns: 生成的随机秘钥，base64编码
    public static func randomKey(dataLength: Int) -> String {
        return Data.yf.randomData(length: dataLength).base64EncodedString()
    }
    
    public var MD5: String {
        return hash(type: .MD5)
    }
    
    public var SHA1: String {
        return hash(type: .SHA1)
    }
    
    public var SHA224: String {
        return hash(type: .SHA224)
    }
    
    public var SHA256: String {
        return hash(type: .SHA256)
    }
    
    public var SHA384: String {
        return hash(type: .SHA384)
    }
    
    public var SHA512: String {
        return hash(type: .SHA512)
    }
    
    /// aes加密便利方法，自己本身是base64编码格式，编码格式不对，自己用SymmetricEncrypt实现
    /// - Parameter key: base64编码格式
    /// - Returns: 加密结果 base64编码格式
    public func aesEncrypt(_ key: String) -> String? {
        let encryptor = SymmetricEncrypt.init()
        return encryptor.encrypt(content: base, key: key)
    }
    
    /// aes解密便利方法，自己本身是base64编码格式，编码格式不对，自己用SymmetricEncrypt实现
    /// - Parameter key: base64编码格式
    /// - Returns: 加密结果
    public func aesDecrypt(_ key: String) -> Data? {
        let encryptor = SymmetricEncrypt.init()
        return encryptor.decrypt(content: key, key: key)
    }
    
    // MARK: - private
    
    func hash(type: YFHash.Kind) -> String {
        if let data = base.data(using: .utf8) {
            let encryptor = YFHash.init(data: data, type: type)
            return encryptor.getHashString()
        } else {
            return ""
        }
    }
   
}

// MARK: - data 加密扩展

extension Data: YFEncryptCompatible { }

extension YFEncrypt where Base == Data {
    
    // MARK: - public
    
    /// 生成随机数据，可以用来生成随机秘钥
    /// - Parameter length: 数据长度，例如，如果随机生成aes128的秘钥，传16.
    /// - Returns: 生成的随机数据
    public static func randomData(length: Int) -> Data {
        var digest = Data(count: length)
        digest.withUnsafeMutableBytes {
            arc4random_buf($0, length)
        }
        return digest
    }
    
    public var MD5: String {
        return hash(type: .MD5)
    }
    
    public var SHA1: String {
        return hash(type: .SHA1)
    }
    
    public var SHA224: String {
        return hash(type: .SHA224)
    }
    
    public var SHA256: String {
        return hash(type: .SHA256)
    }
    
    public var SHA384: String {
        return hash(type: .SHA384)
    }
    
    public var SHA512: String {
        return hash(type: .SHA512)
    }
    
    /// aes加密便利方法，编码格式不对，自己用SymmetricEncrypt实现
    /// - Parameter key: base64编码格式
    /// - Returns: 加密结果 base64编码格式
    public func aesEncrypt(_ key: String) -> String? {
        let encryptor = SymmetricEncrypt.init()
        guard let keyData = Data.init(base64Encoded: key)
              else {
            assertionFailure("对称加密编码格式解析失败")
            return nil
        }
 
        if let result = encryptor.encrypt(data: base, keyData: keyData, iv: nil) {
            return result.base64EncodedString()
        } else {
            return nil
        }
    }
    
    /// aes解密便利方法，编码格式不对，自己用SymmetricEncrypt实现
    /// - Parameter key: base64编码格式
    /// - Returns: 加密结果
    public func aesDecrypt(_ key: String) -> Data? {
        let encryptor = SymmetricEncrypt.init()
        guard let keyData = Data.init(base64Encoded: key)
              else {
            assertionFailure("对称加密编码格式解析失败")
            return nil
        }
        return encryptor.decrypt(data: base, keyData: keyData, iv: nil)
    }
    
    // MARK: - private
    func hash(type: YFHash.Kind) -> String {
        let encryptor = YFHash.init(data: base, type: type)
        return encryptor.getHashString()
    }
   
}



