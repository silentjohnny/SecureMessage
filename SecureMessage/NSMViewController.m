//
//  NSMViewController.m
//  SecureMessage
//
//  Created by Joris Verbogt on 7/22/13.
//  Copyright (c) 2013 Notificare. All rights reserved.
//

#import "NSMViewController.h"
#import "SecKeyWrapper.h"
#import "NSMAppDelegate.h"


@interface NSMViewController ()

@end

@implementation NSMViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    [self setEncrypted:[[NSMutableDictionary alloc] initWithCapacity:5]];
}

- (void)generateKeyPairCompleted {
    [[self spinner] stopAnimating];
    [[self generateOk] setHidden:NO];
    [[self signOk] setHidden:YES];
    [[self encryptOk] setHidden:YES];
    [[self decryptOk] setHidden:YES];
    [[self verifyOk] setHidden:YES];
}


- (IBAction)generate:(id)sender {
    [[self spinner] startAnimating];
    [[self spinner] setHidden:NO];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [[SecKeyWrapper sharedWrapper] generateKeyPair:kAsymmetricSecKeyPairModulusSize];
        [self performSelectorOnMainThread:@selector(generateKeyPairCompleted) withObject:nil waitUntilDone:NO];
    });
}

- (IBAction)sign:(id)sender {
    NSData *signature = [[SecKeyWrapper sharedWrapper] getSignatureBytes:[[_textView text] dataUsingEncoding:NSUTF8StringEncoding]];
    [_encrypted setObject:signature forKey:@"signature"];
    [[self signOk] setHidden:NO];
}


- (IBAction)encrypt:(id)sender {
    CCOptions pad = 0;
    [[SecKeyWrapper sharedWrapper] generateSymmetricKey];
    NSData *message = [[_textView text] dataUsingEncoding:NSUTF8StringEncoding];
    NSData *symmetricKey = [[SecKeyWrapper sharedWrapper] getSymmetricKeyBytes];
    NSData *encryptedMessage = [[SecKeyWrapper sharedWrapper] doCipher:message key:symmetricKey context:kCCEncrypt padding:&pad];
    [_textView setText:[encryptedMessage base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]];
    SecKeyRef peerPublicKeyRef = [[SecKeyWrapper sharedWrapper] getPeerPublicKeyRef];
    NSData *encryptedKey = [[SecKeyWrapper sharedWrapper] wrapSymmetricKey:symmetricKey keyRef:peerPublicKeyRef];
    [_encrypted setObject:encryptedMessage forKey:@"message"];
    [_encrypted setObject:[NSNumber numberWithUnsignedInt:pad] forKey:@"pad"];
    [_encrypted setObject:encryptedKey forKey:@"key"];
    [_encrypted setObject:[[SecKeyWrapper sharedWrapper] getPublicKeyBits] forKey:@"pubkey"];
    [[self encryptOk] setHidden:NO];
}

- (IBAction)decrypt:(id)sender {
    CCOptions pad = 0;
    pad = [(NSNumber *)[_encrypted objectForKey:@"pad"] unsignedIntValue];
    NSData *symmetricKey = [[SecKeyWrapper sharedWrapper] unwrapSymmetricKey:[_encrypted objectForKey:@"key"]];
    NSData *decryptedMessage = [[SecKeyWrapper sharedWrapper] doCipher:[_encrypted objectForKey:@"message"] key:symmetricKey context:kCCDecrypt padding:&pad];
    [_encrypted setObject:decryptedMessage forKey:@"decrypted"];
    [_textView setText:[NSString stringWithUTF8String:(const char *)[decryptedMessage bytes]]];
    [[self decryptOk] setHidden:NO];
}

- (IBAction)verify:(id)sender {
    BOOL verified = [[SecKeyWrapper sharedWrapper] verifySignature:[[_textView text] dataUsingEncoding:NSUTF8StringEncoding] secKeyRef:[[SecKeyWrapper sharedWrapper] getPublicKeyRef] signature:[_encrypted objectForKey:@"signature"]];
    if (verified == YES) {
        [[self verifyOk] setText:@"✔"];
        [[self verifyOk] setHidden:NO];
    } else {
        [[self verifyOk] setText:@"✘"];
        [[self verifyOk] setHidden:NO];
    }
}

@end
