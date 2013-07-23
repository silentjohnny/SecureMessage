//
//  SecKeyWrapper.h
//  SecureMessage
//
//  Created by Joris Verbogt on 7/22/13.
//  Copyright (c) 2013 Notificare. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#if STRONG_CRYPTO_ENABLED

#define kChosenCipherAlgorithm  kCCAlgorithmAES
#define kChosenCipherBlockSize  kCCBlockSizeAES128
#define kChosenCipherKeySize    kCCKeySizeAES256

#else

#define kChosenCipherAlgorithm  kCCAlgorithmDES
#define kChosenCipherBlockSize  kCCBlockSizeDES
#define kChosenCipherKeySize    kCCKeySizeDES

#endif

#define kChosenDigestLength     CC_SHA1_DIGEST_LENGTH
#define kPKCS1                  11
#define kTypeOfWrapPadding      kSecPaddingPKCS1
#define kTypeOfSigPadding       kSecPaddingPKCS1SHA1

#define kPublicKeyTag           "com.apple.sample.publickey"
#define kPrivateKeyTag          "com.apple.sample.privatekey"
#define kPeerPublicKeyTag       "com.apple.sample.peerpublickey"
#define kPeerPrivateKeyTag      "com.apple.sample.peerprivatekey"
#define kSymmetricKeyTag        "com.apple.sample.symmetrickey"

@interface SecKeyWrapper : NSObject

@property SecKeyRef publicKeyRef;
@property SecKeyRef privateKeyRef;
@property SecKeyRef peerPublicKeyRef;
@property SecKeyRef peerPrivateKeyRef;
@property (strong, nonatomic) NSData * symmetricKeyRef;
@property (strong, nonatomic) NSData * publicTag;
@property (strong, nonatomic) NSData * privateTag;
@property (strong, nonatomic) NSData * peerPublicTag;
@property (strong, nonatomic) NSData * peerPrivateTag;
@property (strong, nonatomic) NSData * symmetricTag;

+ (SecKeyWrapper *)sharedWrapper;
- (void)generateKeyPair:(NSUInteger)keySize;
- (void)deleteAsymmetricKeys;
- (void)deleteSymmetricKey;
- (void)generateSymmetricKey;
- (SecKeyRef)addPeerPublicKey:(NSString *)peerName keyBits:(NSData *)publicKey;
- (void)removePeerPublicKey:(NSString *)peerName;
- (NSData *)getSymmetricKeyBytes;
- (NSData *)wrapSymmetricKey:(NSData *)symmetricKey keyRef:(SecKeyRef)publicKey;
- (NSData *)unwrapSymmetricKey:(NSData *)wrappedSymmetricKey;
- (NSData *)getSignatureBytes:(NSData *)plainText;
- (NSData *)getHashBytes:(NSData *)plainText;
- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig;
- (NSData *)doCipher:(NSData *)plainText key:(NSData *)symmetricKey context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7;
- (SecKeyRef)getPublicKeyRef;
- (SecKeyRef)getPeerPublicKeyRef;
- (NSData *)getPublicKeyBits;
- (SecKeyRef)getPrivateKeyRef;
- (SecKeyRef)getPeerPrivateKeyRef;
- (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)keyRef;
- (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef;

@end