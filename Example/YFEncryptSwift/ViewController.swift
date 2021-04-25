//
//  ViewController.swift
//  YFEncryptSwift
//
//  Created by HarryPhone on 04/15/2021.
//  Copyright (c) 2021 HarryPhone. All rights reserved.
//

import UIKit
import YFEncryptSwift

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
//        MD5Test()
//        fileSHA256Test()
//        hmacSHA512Test()
        AESTest()
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    func MD5Test() {
        let example = "hello, world!"
        
        var md5Str = example.yf.MD5
        print(md5Str)
        
        // or
        let encryptor = YFHash.init(data: example.data(using: .utf8)!)
        md5Str = encryptor.getHashString()
        print(md5Str)
    }
    
    func fileSHA256Test() {
        let filePath = Bundle.main.path(forResource: "private", ofType: "pem")!
        let encryptor = YFHash.init(filePath: filePath, type: .SHA256)
        print(encryptor.getHashString())
    }
    
    func hmacSHA512Test() {
        let contentData = "hello, world!".data(using: .utf8)!
        
        let hmacData = "hmac key".data(using: .utf8)!
        let encryptor = YFHash.init(data: contentData, type: .SHA512, hmacKey: hmacData)
        print(encryptor.getHashString())
    }
    
    func AESTest() {
//        let aesKey = SymmetricEncrypt.generateRandomKey(.AES256)
        let aesKey = "FfsGlCuQc3Za94ohGx2sIIiCmfFzCYeKxREnSS+HGGY="
        let content = "hello, world!"
//        print(aesKey)
        print(content.yf.aesEncrypt(aesKey)!)
        
        let encryptor = SymmetricEncrypt.init(type: .AES, isNoPadding: false)

        print(encryptor.encrypt(content: content, key: aesKey)!)
        
    }
    
}

