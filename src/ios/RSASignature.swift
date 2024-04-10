import Foundation
import LocalAuthentication

@objc(RSASignature) class RSASignature : CDVPlugin {
    
    struct Shared {
        static let keypair: EllipticCurveKeyPair.Manager = {
            EllipticCurveKeyPair.logger = { print($0) }
            let publicAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let privateAccessControl = EllipticCurveKeyPair.AccessControl(protection: kSecAttrAccessibleAlwaysThisDeviceOnly, flags: [])
            let config = EllipticCurveKeyPair.Config(
                publicLabel: "com.alliance.aop.sign.public",
                privateLabel: "com.alliance.aop.sign.private",
                operationPrompt: "Sign transaction",
                publicKeyAccessControl: publicAccessControl,
                privateKeyAccessControl: privateAccessControl,
                token: .secureEnclaveIfAvailable)
            return EllipticCurveKeyPair.Manager(config: config)
        }()
    }

  @objc(getPublicKey:)
  func getPublicKey(_ command: CDVInvokedUrlCommand){
    var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Not available");
    do {
        let keyPEM = try Shared.keypair.publicKey().data().PEM
        //publicKeyTextView.text = key.PEM
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: ["publicKey":keyPEM]);
    } catch {
        //publicKeyTextView.text = "Error: \(error)"
    }
    commandDelegate.send(pluginResult, callbackId:command.callbackId);
  }

  @objc(getTrxSignature:)
  func getTrxSignature(_ command: CDVInvokedUrlCommand){
    var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Something went wrong");
    do {
        let privateKey = try Shared.keypair.privateKey();
    } catch {
        if error.localizedDescription.hasPrefix("Authentication failed.")  {
            try?Shared.keypair.deleteKeyPair();
        }
        do{
            let privateKey = try Shared.keypair.privateKey();
        } catch {
            commandDelegate.send(pluginResult, callbackId:command.callbackId);
        }
    }
    var reason = "Authentication";
    let data  = command.arguments[0] as AnyObject?;
    if let username = data?["username"] as! String? {
        if let date = data?["date"] as! String? {
            reason = username;
            reason += date;
        }
    }
    do {
        let digest = reason.data(using: .utf8)!
        let signature = try Shared.keypair.signUsingSha256(digest)
        pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: ["rsaSignature":signature.base64EncodedString()]);
    } catch {
        // handle error
    }
    commandDelegate.send(pluginResult, callbackId:command.callbackId);
  }
}
