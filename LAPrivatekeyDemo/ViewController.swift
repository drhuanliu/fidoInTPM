//
//  ViewController.swift
//  LAPrivatekeyDemo
//
//  Created by Huan Liu on 7/1/23.
//

import UIKit
import LocalAuthentication

class ViewController: UIViewController {

    // a test nonce. In a real deployment, the nonce should be generated on the server.
    let nonce : Data = Data.init(base64Encoded: "dGVzdA==")!
    // key identifier, used to look up the private and public keys
    let keyIdentifier = "HuanDemo"
    
    @IBOutlet weak var statusLabel: UILabel!
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    // generate a key pair
    func generateClientKeys() async throws -> Data {
        let right = LARight()
        // in case there were key generated before, clean up before generate a new key pair
        try await LARightStore.shared.removeRight(forIdentifier: keyIdentifier)
        // generate a new key pair
        let persistedRight = try await LARightStore.shared.saveRight(right, identifier: keyIdentifier)
        return try await persistedRight.key.publicKey.bytes
    }
    
    
    @MainActor
    private func updateStatus(_ msg: String) {
        self.statusLabel.text = msg
    }
    
    
    @IBAction func enrollClicked(_ sender: Any) {
        Task {
            do {
                let publicKey = try await generateClientKeys()
                // send publicKey to server
                self.updateStatus("Generated key " + publicKey.base64EncodedString())
            }
            catch {
                print("Enrollment error: \(error)")
            }
        }
        
    }
    
    func signServerChallenge(nonce: Data) async throws -> Data {
        let persistedRight = try await LARightStore.shared.right(forIdentifier: keyIdentifier)
        try await persistedRight.authorize(localizedReason: "Authenticating...")

        // verify we can sign
        guard persistedRight.key.canSign(using: .ecdsaSignatureMessageX962SHA256) else {
            throw NSError(domain: "SampleErrorDomain", code: -1, userInfo: [:])
        }
        
        return try await persistedRight.key.sign(nonce, algorithm: .ecdsaSignatureMessageX962SHA256)
    }

    // Validate signature on client. This should be done on the server
    func verifySignatureLocally(nonce: Data, signature: Data) async throws -> Void {
        
        // On client, get a handle to the private key, then its public key.
        // On server, the public key should be looked up from the database
        let persistedRight = try await LARightStore.shared.right(forIdentifier: keyIdentifier)
        let publicKey = persistedRight.key.publicKey
                
        guard publicKey.canVerify(using: .ecdsaSignatureMessageX962SHA256) else {
            throw NSError(domain: "SampleErrorDomain", code: -1, userInfo: [:])
        }
        
        try await publicKey.verify(nonce, signature: signature, algorithm: .ecdsaSignatureMessageX962SHA256)
    }

    
    @IBAction func loginClicked(_ sender: Any) {
        Task {
            do {
                // fetch Challenge from server, let it be in "nonce"
                
            
                let sig = try await signServerChallenge(nonce: nonce)
         
                
                // call server to verify the signature
                
                // for simplicity in demo code, we verify on client
                try await verifySignatureLocally(nonce: nonce, signature: sig)

                // if no exception, we succeeded, let user know
                self.updateStatus("Validated signature \(sig.base64EncodedString())")
            }
            catch {
                print("Authentication error: \(error)")
            }

        }

        
    }
    
    
}

