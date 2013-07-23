//
//  SecKeyWrapper.m
//  SecureMessage
//
//  Created by Joris Verbogt on 7/22/13.
//  Copyright (c) 2013 Notificare. All rights reserved.
//

#import "SecKeyWrapper.h"

@implementation SecKeyWrapper

#if DEBUG
#define LOGGING_FACILITY(X, Y)  \
NSAssert(X, Y);

#define LOGGING_FACILITY1(X, Y, Z)  \
NSAssert1(X, Y, Z);
#else
#define LOGGING_FACILITY(X, Y)  \
if (!(X)) {         \
NSLog(Y);       \
}

#define LOGGING_FACILITY1(X, Y, Z)  \
if (!(X)) {             \
NSLog(Y, Z);        \
}
#endif

// (See cssmtype.h and cssmapple.h on the Mac OS X SDK.)

enum {
    CSSM_ALGID_NONE =                   0x00000000L,
    CSSM_ALGID_VENDOR_DEFINED =         CSSM_ALGID_NONE + 0x80000000L,
    CSSM_ALGID_AES
};

// identifiers used to find public, private, and symmetric key.
static const uint8_t publicKeyIdentifier[]      = kPublicKeyTag;
static const uint8_t privateKeyIdentifier[]     = kPrivateKeyTag;
static const uint8_t peerPublicKeyIdentifier[]  = kPeerPublicKeyTag;
static const uint8_t peerPrivateKeyIdentifier[] = kPeerPrivateKeyTag;
static const uint8_t symmetricKeyIdentifier[]   = kSymmetricKeyTag;


/* Begin method definitions */

+ (SecKeyWrapper *)sharedWrapper {
    static SecKeyWrapper *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[SecKeyWrapper alloc] init];
        // Do any other initialisation stuff here
    });
    return sharedInstance;
}

- (id)init {
    if (self = [super init])
    {
        // Tag data to search for keys.
        [self setPrivateTag:[[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)]];
        [self setPublicTag:[[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)]];
        [self setPeerPrivateTag:[[NSData alloc] initWithBytes:peerPrivateKeyIdentifier length:sizeof(peerPrivateKeyIdentifier)]];
        [self setPeerPublicTag:[[NSData alloc] initWithBytes:peerPublicKeyIdentifier length:sizeof(peerPublicKeyIdentifier)]];
        [self setSymmetricTag:[[NSData alloc] initWithBytes:symmetricKeyIdentifier length:sizeof(symmetricKeyIdentifier)]];
    }

    return self;
}

- (void)deleteAsymmetricKeys {
    OSStatus sanityCheck = noErr;
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * queryPeerPublicKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * queryPeerPrivateKey = [[NSMutableDictionary alloc] init];

    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

    // Set the private key query dictionary.
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

    // Set the public key query dictionary.
    [queryPeerPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPeerPublicKey setObject:_peerPublicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPeerPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Set the private key query dictionary.
    [queryPeerPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPeerPrivateKey setObject:_peerPrivateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPeerPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

    // Delete the private key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing private key, OSStatus == %d.", (int)sanityCheck );

    // Delete the public key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing public key, OSStatus == %d.", (int)sanityCheck );

    // Delete the private key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPeerPrivateKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing private key, OSStatus == %d.", (int)sanityCheck );
    
    // Delete the public key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPeerPublicKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing public key, OSStatus == %d.", (int)sanityCheck );
    
    if (_publicKeyRef) CFRelease(_publicKeyRef);
    if (_privateKeyRef) CFRelease(_privateKeyRef);
    if (_peerPublicKeyRef) CFRelease(_peerPublicKeyRef);
    if (_peerPrivateKeyRef) CFRelease(_peerPrivateKeyRef);
}

- (void)deleteSymmetricKey {
    OSStatus sanityCheck = noErr;

    NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];

    // Set the symmetric key query dictionary.
    [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];

    // Delete the symmetric key.
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)querySymmetricKey);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Error removing symmetric key, OSStatus == %d.", (int)sanityCheck );

}

- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    _publicKeyRef = NULL;
    _privateKeyRef = NULL;
    _peerPublicKeyRef = NULL;
    _peerPrivateKeyRef = NULL;
    
    LOGGING_FACILITY1( keySize == 512 || keySize == 768 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
    
    // First delete current keys.
    [self deleteAsymmetricKeys];
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &_publicKeyRef, &_privateKeyRef);
    LOGGING_FACILITY( sanityCheck == noErr && _publicKeyRef != NULL && _privateKeyRef != NULL, @"Something really bad went wrong with generating the key pair." );
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &_peerPublicKeyRef, &_peerPrivateKeyRef);
    LOGGING_FACILITY( sanityCheck == noErr && _peerPublicKeyRef != NULL && _peerPrivateKeyRef != NULL, @"Something really bad went wrong with generating the key pair." );
    
}

- (void)generateSymmetricKey {
    OSStatus sanityCheck = noErr;
    uint8_t * symmetricKey = NULL;

    // First delete current symmetric key.
    [self deleteSymmetricKey];

    // Container dictionary
    NSMutableDictionary *symmetricKeyAttr = [[NSMutableDictionary alloc] init];
    [symmetricKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [symmetricKeyAttr setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
    unsigned int type = CSSM_ALGID_AES;
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:type] forKey:(__bridge id)kSecAttrKeyType];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [symmetricKeyAttr setObject:[NSNumber numberWithUnsignedInt:(unsigned int)(kChosenCipherKeySize << 3)]  forKey:(__bridge id)kSecAttrEffectiveKeySize];
    [symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanEncrypt];
    [symmetricKeyAttr setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecAttrCanDecrypt];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanDerive];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanSign];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanVerify];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanWrap];
    [symmetricKeyAttr setObject:(id)kCFBooleanFalse forKey:(__bridge id)kSecAttrCanUnwrap];

    // Allocate some buffer space. I don't trust calloc.
    symmetricKey = malloc( kChosenCipherKeySize * sizeof(uint8_t) );

    LOGGING_FACILITY( symmetricKey != NULL, @"Problem allocating buffer space for symmetric key generation." );

    memset((void *)symmetricKey, 0x0, kChosenCipherKeySize);

    sanityCheck = SecRandomCopyBytes(kSecRandomDefault, kChosenCipherKeySize, symmetricKey);
    LOGGING_FACILITY1( sanityCheck == noErr, @"Problem generating the symmetric key, OSStatus == %d.", (int)sanityCheck );

    self.symmetricKeyRef = (__bridge NSData *)((__bridge SecKeyRef)([[NSData alloc] initWithBytes:(const void *)symmetricKey length:kChosenCipherKeySize]));

    // Add the wrapped key data to the container dictionary.
    [symmetricKeyAttr setObject:self.symmetricKeyRef
                         forKey:(__bridge id)kSecValueData];

    // Add the symmetric key to the keychain.
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) symmetricKeyAttr, NULL);
    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecDuplicateItem, @"Problem storing the symmetric key in the keychain, OSStatus == %d.", (int)sanityCheck );

    if (symmetricKey) free(symmetricKey);
}

- (SecKeyRef)addPeerPublicKey:(NSString *)peerName keyBits:(NSData *)publicKey {
    OSStatus sanityCheck = noErr;
    SecKeyRef peerKeyRef = NULL;
    CFTypeRef persistPeer = NULL;

    LOGGING_FACILITY( peerName != nil, @"Peer name parameter is nil." );
    LOGGING_FACILITY( publicKey != nil, @"Public key parameter is nil." );

    NSData * peerTag = [[NSData alloc] initWithBytes:(const void *)[peerName UTF8String] length:[peerName length]];
    NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];

    [peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
    [peerPublicKeyAttr setObject:publicKey forKey:(__bridge id)kSecValueData];
    [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];

    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&persistPeer);

    // The nice thing about persistent references is that you can write their value out to disk and
    // then use them later. I don't do that here but it certainly can make sense for other situations
    // where you don't want to have to keep building up dictionaries of attributes to get a reference.
    //
    // Also take a look at SecKeyWrapper's methods (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)key
    // & (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef.

    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecDuplicateItem, @"Problem adding the peer public key to the keychain, OSStatus == %d.", (int)sanityCheck );

    if (persistPeer) {
        peerKeyRef = [self getKeyRefWithPersistentKeyRef:persistPeer];
    } else {
        [peerPublicKeyAttr removeObjectForKey:(__bridge id)kSecValueData];
        [peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        // Let's retry a different way.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);
    }

    LOGGING_FACILITY1( sanityCheck == noErr && peerKeyRef != NULL, @"Problem acquiring reference to the public key, OSStatus == %d.", (int)sanityCheck );

    if (persistPeer) CFRelease(persistPeer);
    return peerKeyRef;
}

- (void)removePeerPublicKey:(NSString *)peerName {
    OSStatus sanityCheck = noErr;

    LOGGING_FACILITY( peerName != nil, @"Peer name parameter is nil." );

    NSData * peerTag = [[NSData alloc] initWithBytes:(const void *)[peerName UTF8String] length:[peerName length]];
    NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];

    [peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];

    sanityCheck = SecItemDelete((__bridge CFDictionaryRef) peerPublicKeyAttr);

    LOGGING_FACILITY1( sanityCheck == noErr || sanityCheck == errSecItemNotFound, @"Problem deleting the peer public key to the keychain, OSStatus == %d.", (int)sanityCheck );

}

- (NSData *)wrapSymmetricKey:(NSData *)symmetricKey keyRef:(SecKeyRef)publicKey {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;

    LOGGING_FACILITY( symmetricKey != nil, @"Symmetric key parameter is nil." );
    LOGGING_FACILITY( publicKey != nil, @"Key parameter is nil." );

    NSData * cipher = nil;
    uint8_t * cipherBuffer = NULL;

    // Calculate the buffer sizes.
    cipherBufferSize = SecKeyGetBlockSize(publicKey);
    keyBufferSize = [symmetricKey length];

    if (kTypeOfWrapPadding == kSecPaddingNone) {
        LOGGING_FACILITY( keyBufferSize <= cipherBufferSize, @"Nonce integer is too large and falls outside multiplicative group." );
    } else {
        LOGGING_FACILITY( keyBufferSize <= (cipherBufferSize - 11), @"Nonce integer is too large and falls outside multiplicative group." );
    }

    // Allocate some buffer space. I don't trust calloc.
    cipherBuffer = malloc( cipherBufferSize * sizeof(uint8_t) );
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);

    // Encrypt using the public key.
    sanityCheck = SecKeyEncrypt(    publicKey,
                                kTypeOfWrapPadding,
                                (const uint8_t *)[symmetricKey bytes],
                                keyBufferSize,
                                cipherBuffer,
                                &cipherBufferSize
                                );

    LOGGING_FACILITY1( sanityCheck == noErr, @"Error encrypting, OSStatus == %d.", (int)sanityCheck );

    // Build up cipher text blob.
    cipher = [NSData dataWithBytes:(const void *)cipherBuffer length:(NSUInteger)cipherBufferSize];

    if (cipherBuffer) free(cipherBuffer);

    return cipher;
}

- (NSData *)unwrapSymmetricKey:(NSData *)wrappedSymmetricKey {
    OSStatus sanityCheck = noErr;
    size_t cipherBufferSize = 0;
    size_t keyBufferSize = 0;

    NSData * key = nil;
    uint8_t * keyBuffer = NULL;

    SecKeyRef privateKey = NULL;

    privateKey = [self getPeerPrivateKeyRef];
    LOGGING_FACILITY( privateKey != NULL, @"No private key found in the keychain." );

    // Calculate the buffer sizes.
    cipherBufferSize = SecKeyGetBlockSize(privateKey);
    keyBufferSize = [wrappedSymmetricKey length];

    LOGGING_FACILITY( keyBufferSize <= cipherBufferSize, @"Encrypted nonce is too large and falls outside multiplicative group." );

    // Allocate some buffer space. I don't trust calloc.
    keyBuffer = malloc( keyBufferSize * sizeof(uint8_t) );
    memset((void *)keyBuffer, 0x0, keyBufferSize);

    // Decrypt using the private key.
    sanityCheck = SecKeyDecrypt(    privateKey,
                                kTypeOfWrapPadding,
                                (const uint8_t *) [wrappedSymmetricKey bytes],
                                cipherBufferSize,
                                keyBuffer,
                                &keyBufferSize
                                );

    LOGGING_FACILITY1( sanityCheck == noErr, @"Error decrypting, OSStatus == %d.", (int)sanityCheck );

    // Build up plain text blob.
    key = [NSData dataWithBytes:(const void *)keyBuffer length:(NSUInteger)keyBufferSize];

    if (keyBuffer) free(keyBuffer);

    return key;
}

- (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;

    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);

    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], [plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);

    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];

    if (hashBytes) free(hashBytes);

    return hash;
}

- (NSData *)getSignatureBytes:(NSData *)plainText {
    OSStatus sanityCheck = noErr;
    NSData * signedHash = nil;

    uint8_t * signedHashBytes = NULL;
    size_t signedHashBytesSize = 0;

    SecKeyRef privateKey = NULL;

    privateKey = [self getPrivateKeyRef];
    signedHashBytesSize = SecKeyGetBlockSize(privateKey);

    // Malloc a buffer to hold signature.
    signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
    memset((void *)signedHashBytes, 0x0, signedHashBytesSize);

    // Sign the SHA1 hash.
    sanityCheck = SecKeyRawSign(    privateKey,
                                kTypeOfSigPadding,
                                (const uint8_t *)[[self getHashBytes:plainText] bytes],
                                kChosenDigestLength,
                                (uint8_t *)signedHashBytes,
                                &signedHashBytesSize
                                );

    LOGGING_FACILITY1( sanityCheck == noErr, @"Problem signing the SHA1 hash, OSStatus == %d.", (int)sanityCheck );

    // Build up signed SHA1 blob.
    signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];

    if (signedHashBytes) free(signedHashBytes);

    return signedHash;
}

- (BOOL)verifySignature:(NSData *)plainText secKeyRef:(SecKeyRef)publicKey signature:(NSData *)sig {
    size_t signedHashBytesSize = 0;
    OSStatus sanityCheck = noErr;

    // Get the size of the assymetric block.
    signedHashBytesSize = SecKeyGetBlockSize(publicKey);

    sanityCheck = SecKeyRawVerify(  publicKey,
                                  kTypeOfSigPadding,
                                  (const uint8_t *)[[self getHashBytes:plainText] bytes],
                                  kChosenDigestLength,
                                  (const uint8_t *)[sig bytes],
                                  signedHashBytesSize
                                  );

    return (sanityCheck == noErr) ? YES : NO;
}

- (NSData *)doCipher:(NSData *)plainText key:(NSData *)symmetricKey context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7 {
    CCCryptorStatus ccStatus = kCCSuccess;
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    // A friendly helper pointer.
    uint8_t * ptr;

    // Initialization vector; dummy in this case 0's.
    uint8_t iv[kChosenCipherBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));

    LOGGING_FACILITY(plainText != nil, @"PlainText object cannot be nil." );
    LOGGING_FACILITY(symmetricKey != nil, @"Symmetric key object cannot be nil." );
    LOGGING_FACILITY(pkcs7 != NULL, @"CCOptions * pkcs7 cannot be NULL." );
    LOGGING_FACILITY([symmetricKey length] == kChosenCipherKeySize, @"Disjoint choices for key size." );

    plainTextBufferSize = [plainText length];

    LOGGING_FACILITY(plainTextBufferSize > 0, @"Empty plaintext passed in." );

    // We don't want to toss padding on if we don't need to
    if (encryptOrDecrypt == kCCEncrypt) {
        if (*pkcs7 != kCCOptionECBMode) {
            if ((plainTextBufferSize % kChosenCipherBlockSize) == 0) {
                *pkcs7 = 0x0000;
            } else {
                *pkcs7 = kCCOptionPKCS7Padding;
            }
        }
    } else if (encryptOrDecrypt != kCCDecrypt) {
        LOGGING_FACILITY1( 0, @"Invalid CCOperation parameter [%d] for cipher context.", *pkcs7 );
    }

    // Create and Initialize the crypto reference.
    ccStatus = CCCryptorCreate( encryptOrDecrypt,
                               kChosenCipherAlgorithm,
                               *pkcs7,
                               (const void *)[symmetricKey bytes],
                               kChosenCipherKeySize,
                               (const void *)iv,
                               &thisEncipher
                               );

    LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem creating the context, ccStatus == %d.", ccStatus );

    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);

    // Allocate buffer.
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );

    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);

    // Initialize some necessary book keeping.

    ptr = bufferPtr;

    // Set up initial size.
    remainingBytes = bufferPtrSize;

    // Actually perform the encryption or decryption.
    ccStatus = CCCryptorUpdate( thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );

    LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with CCCryptorUpdate, ccStatus == %d.", ccStatus );

    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;

    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(  thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );

    totalBytesWritten += movedBytes;

    if (thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }

    LOGGING_FACILITY1( ccStatus == kCCSuccess, @"Problem with encipherment ccStatus == %d", ccStatus );

    cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];

    if (bufferPtr) free(bufferPtr);

    return cipherOrPlainText;

    /*
     Or the corresponding one-shot call:

     ccStatus = CCCrypt(    encryptOrDecrypt,
     kCCAlgorithmAES128,
     typeOfSymmetricOpts,
     (const void *)[self getSymmetricKeyBytes],
     kChosenCipherKeySize,
     iv,
     (const void *) [plainText bytes],
     plainTextBufferSize,
     (void *)bufferPtr,
     bufferPtrSize,
     &movedBytes
     );
     */
}

- (SecKeyRef)getPublicKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;

    if (_publicKeyRef == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];

        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];

        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);

        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
        }
    } else {
        publicKeyReference = _publicKeyRef;
    }

    return publicKeyReference;
}

- (SecKeyRef)getPeerPublicKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (_peerPublicKeyRef == NULL) {
        NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:_peerPublicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
        }
    } else {
        publicKeyReference = _peerPublicKeyRef;
    }
    
    return publicKeyReference;
}

- (NSData *)getPublicKeyBits {
    OSStatus sanityCheck = noErr;
    NSData * publicKeyBits = nil;

    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];

    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];

    // Get the key bits.
    CFTypeRef result;
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, &result);

    if (sanityCheck == errSecSuccess) {
        publicKeyBits = CFBridgingRelease(result);
    }
    if (sanityCheck != noErr)
    {
        publicKeyBits = nil;
    }

    return publicKeyBits;
}

- (SecKeyRef)getPrivateKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyReference = NULL;

    if (_privateKeyRef == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];

        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];

        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);

        if (sanityCheck != noErr)
        {
            privateKeyReference = NULL;
        }

    } else {
        privateKeyReference = _privateKeyRef;
    }

    return privateKeyReference;
}

- (SecKeyRef)getPeerPrivateKeyRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef privateKeyReference = NULL;
    
    if (_peerPrivateKeyRef == NULL) {
        NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
        
        // Set the private key query dictionary.
        [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPrivateKey setObject:_peerPrivateTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
        
        if (sanityCheck != noErr)
        {
            privateKeyReference = NULL;
        }
        
    } else {
        privateKeyReference = _peerPrivateKeyRef;
    }
    
    return privateKeyReference;
}

- (NSData *)getSymmetricKeyBytes {
    OSStatus sanityCheck = noErr;
    NSData *symmetricKeyReturn = nil;

    if (self.symmetricKeyRef == nil) {
        NSMutableDictionary * querySymmetricKey = [[NSMutableDictionary alloc] init];

        // Set the private key query dictionary.
        [querySymmetricKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [querySymmetricKey setObject:_symmetricTag forKey:(__bridge id)kSecAttrApplicationTag];
        [querySymmetricKey setObject:[NSNumber numberWithUnsignedInt:CSSM_ALGID_AES] forKey:(__bridge id)kSecAttrKeyType];
        [querySymmetricKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];

        // Get the key bits.
        CFTypeRef result;
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)querySymmetricKey, &result);
        
        if (sanityCheck == errSecSuccess) {
            symmetricKeyReturn = CFBridgingRelease(result);
        }
        
        if (sanityCheck == noErr && symmetricKeyReturn != nil) {
            [self setSymmetricKeyRef:(__bridge NSData *)((__bridge SecKeyRef)(symmetricKeyReturn))];
        } else {
            [self setSymmetricKeyRef:nil];
        }

    } else {
        symmetricKeyReturn = self.symmetricKeyRef;
    }

    return symmetricKeyReturn;
}

- (CFTypeRef)getPersistentKeyRefWithKeyRef:(SecKeyRef)keyRef {
    OSStatus sanityCheck = noErr;
    CFTypeRef persistentRef = NULL;

    LOGGING_FACILITY(keyRef != NULL, @"keyRef object cannot be NULL." );

    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];

    // Set the PersistentKeyRef key query dictionary.
    [queryKey setObject:(__bridge id)keyRef forKey:(__bridge id)kSecValueRef];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];

    // Get the persistent key reference.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&persistentRef);

    return persistentRef;
}

- (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef {
    OSStatus sanityCheck = noErr;
    SecKeyRef keyRef = NULL;

    LOGGING_FACILITY(persistentRef != NULL, @"persistentRef object cannot be NULL." );

    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];

    // Set the SecKeyRef query dictionary.
    [queryKey setObject:
     (__bridge id)persistentRef forKey:(__bridge id)kSecValuePersistentRef];
    [queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];

    // Get the persistent key reference.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&keyRef);
    return keyRef;
}

@end