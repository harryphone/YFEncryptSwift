//
//  Hash.swift
//  YFEncryptSwift
//
//  Created by HarryPhone on 2021/4/15.
//

import Foundation
import CommonCrypto
//import CryptoKit

public struct YFHash {
    public enum Kind {
        case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    }
    
    public var type: Kind
    
    public var hmacKey: Data?
    
    public var data: Data?
    
    public var filePath: String?
    
    
    /// 哈希函数的初始化方法
    /// - Parameters:
    ///   - type: hash函数的类型
    ///   - data: 需要hash的数据
    ///   - hmacKey: 如果需要hmac加密，那么传此项
    public init(data: Data, type: Kind = .MD5, hmacKey: Data? = nil) {
        self.type = type
        self.hmacKey = hmacKey
        self.data = data
    }
    
    /// 哈希函数的初始化方法
    /// - Parameters:
    ///   - type: hash函数的类型
    ///   - filePath: 需要hash的文件路径
    ///   - hmacKey: 如果需要hmac加密，那么传此项
    public init(filePath: String, type: Kind = .MD5, hmacKey: Data? = nil) {
        self.type = type
        self.hmacKey = hmacKey
        self.filePath = filePath
    }
    
    public func getHashData() -> Data {
        if let hmacKey = hmacKey, let filePath = filePath {
            return fileHmacHashData(filePath: filePath, hmacKey: hmacKey)
        } else if let hmacKey = hmacKey, let data = data {
            return hmacHashData(data: data, hmacKey: hmacKey)
        } else if let filePath = filePath {
            return fileHashData(filePath: filePath)
        } else if let data = data {
            return hashData(data: data)
        } else {
            assertionFailure("未知错误")
            return Data()
        }
    }
    
    public func getHashString() -> String {
        let digest = [UInt8](getHashData())
        return digest.reduce("") { $0 + String(format:"%02x", $1) }
    }


    
}

extension YFHash {
    
    var hashDigestLength: Int32 {
        switch type {
        case .MD5:
            return CC_MD5_DIGEST_LENGTH;
        case .SHA1:
            return CC_SHA1_DIGEST_LENGTH;
        case .SHA224:
            return CC_SHA224_DIGEST_LENGTH;
        case .SHA256:
            return CC_SHA256_DIGEST_LENGTH;
        case .SHA384:
            return CC_SHA384_DIGEST_LENGTH;
        case .SHA512:
            return CC_SHA512_DIGEST_LENGTH;
        }
    }
    
    var hmacAlgorithm: Int {
        switch type {
        case .MD5:
            return kCCHmacAlgMD5;
        case .SHA1:
            return kCCHmacAlgSHA1;
        case .SHA224:
            return kCCHmacAlgSHA224;
        case .SHA256:
            return kCCHmacAlgSHA256;
        case .SHA384:
            return kCCHmacAlgSHA384;
        case .SHA512:
            return kCCHmacAlgSHA512;
        }
    }
    
    
    func hashData(data: Data) -> Data {
        
        var digest = Data(count: Int(hashDigestLength))
        digest.withUnsafeMutableBytes { (digestPtr: UnsafeMutablePointer<UInt8>) in
            // 这里碰到一个坑，Data的长度不一样，内存结构也会不一样（测下来15），本来data.withUnsafeBytes { $0 }只能用NSData(data: data).bytes了
            let dataPtr = NSData(data: data).bytes
                switch type {
                case .MD5:
                    CC_MD5(dataPtr, numericCast(data.count), digestPtr)
                case .SHA1:
                    CC_SHA1(dataPtr, numericCast(data.count), digestPtr)
                case .SHA224:
                    CC_SHA224(dataPtr, numericCast(data.count), digestPtr)
                case .SHA256:
                    CC_SHA256(dataPtr, numericCast(data.count), digestPtr)
                case .SHA384:
                    CC_SHA384(dataPtr, numericCast(data.count), digestPtr)
                case .SHA512:
                    CC_SHA512(dataPtr, numericCast(data.count), digestPtr)
                }
        }
        return digest
    }

    
    func hmacHashData(data: Data, hmacKey: Data) -> Data {
        // 对比下不同实现形式
//        var digest = [UInt8](repeating: 0, count: Int(hashDigestLength))
//        CCHmac(CCHmacAlgorithm(hmacAlgorithm), hmacKey.withUnsafeBytes { $0 }, hmacKey.count, data.withUnsafeBytes { $0 }, data.count, &digest);
//        return Data(digest)
        var digest = Data(count: Int(hashDigestLength))
        digest.withUnsafeMutableBytes {
            CCHmac(CCHmacAlgorithm(hmacAlgorithm), NSData(data: hmacKey).bytes, hmacKey.count, NSData(data: data).bytes, data.count, $0);
        }
        return digest
    }
    
    static let DefaultChunkSizeForReadingData = 4096
    
    
    func fileHashData<Context>(
        _ handler: FileHandle, _ context: inout Context,
        _ initMethod: ((_ c: UnsafeMutablePointer<Context>) -> Int32),
        _ updateMethod: ((_ c: UnsafeMutablePointer<Context>, _ data: UnsafeRawPointer, _ len: CC_LONG) -> Int32),
        _ finalMethod: ((_ md: UnsafeMutablePointer<UInt8>, _ c: UnsafeMutablePointer<Context>) -> Int32)
    ) -> Data {
        
        _ = initMethod(&context)
        var digest = Data(count: Int(hashDigestLength))
        
        while autoreleasepool(invoking: {
            let data = handler.readData(ofLength: YFHash.DefaultChunkSizeForReadingData)
            if data.count > 0 {
                    _ = updateMethod(&context, NSData(data: data).bytes, numericCast(data.count))
                return true // Continue
            } else {
                digest.withUnsafeMutableBytes {
                    _ = finalMethod($0, &context)
                }
                return false // End of file
            }
        }) {}

        return digest
    }
    
    func fileHashData(filePath: String) -> Data {
        let fileHandle = FileHandle(forReadingAtPath: filePath)
        defer {
            fileHandle?.closeFile()
        }
        guard let handler = fileHandle else {
            assertionFailure("Cannot open file: \(filePath)")
            return Data()
        }

        switch type {
        case .MD5:
            var context = CC_MD5_CTX()
            return fileHashData(handler, &context, CC_MD5_Init, CC_MD5_Update, CC_MD5_Final)
        case .SHA1:
            var context = CC_SHA1_CTX()
            return fileHashData(handler, &context, CC_SHA1_Init, CC_SHA1_Update, CC_SHA1_Final)
        case .SHA224:
            var context = CC_SHA256_CTX()
            return fileHashData(handler, &context, CC_SHA224_Init, CC_SHA224_Update, CC_SHA224_Final)
        case .SHA256:
            var context = CC_SHA256_CTX()
            return fileHashData(handler, &context, CC_SHA256_Init, CC_SHA256_Update, CC_SHA256_Final)
        case .SHA384:
            var context = CC_SHA512_CTX()
            return fileHashData(handler, &context, CC_SHA384_Init, CC_SHA384_Update, CC_SHA384_Final)
        case .SHA512:
            var context = CC_SHA512_CTX()
            return fileHashData(handler, &context, CC_SHA512_Init, CC_SHA512_Update, CC_SHA512_Final)
        }
    }
    
    func fileHmacHashData(filePath: String, hmacKey: Data) -> Data {
        let fileHandle = FileHandle(forReadingAtPath: filePath)
        defer {
            fileHandle?.closeFile()
        }
        guard let handler = fileHandle else {
            assertionFailure("Cannot open file: \(filePath)")
            return Data()
        }
        
        var context = CCHmacContext()
        CCHmacInit(&context, CCHmacAlgorithm(hmacAlgorithm), NSData(data: hmacKey).bytes, hmacKey.count);
        
        var digest = Data(count: Int(hashDigestLength))
        
        while autoreleasepool(invoking: {
            let data = handler.readData(ofLength: YFHash.DefaultChunkSizeForReadingData)
            if data.count > 0 {
                CCHmacUpdate(&context, NSData(data: data).bytes, numericCast(data.count))
                return true // Continue
            } else {
                digest.withUnsafeMutableBytes {
                    CCHmacFinal($0, &context)
                }
                return false // End of file
            }
        }) {}

        return digest

    }
    
}
