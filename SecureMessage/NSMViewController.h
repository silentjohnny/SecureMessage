//
//  NSMViewController.h
//  SecureMessage
//
//  Created by Joris Verbogt on 7/22/13.
//  Copyright (c) 2013 Notificare. All rights reserved.
//

#import <UIKit/UIKit.h>

#define kMaxMessageLength 1024*1024*5

#if STRONG_CRYPTO_ENABLED

#define kAsymmetricSecKeyPairModulusSize 2048

#else

#define kAsymmetricSecKeyPairModulusSize 768

#endif

@interface NSMViewController : UIViewController
@property (weak, nonatomic) IBOutlet UIButton *generateButton;
@property (weak, nonatomic) IBOutlet UIButton *signButton;
@property (weak, nonatomic) IBOutlet UIButton *encryptButton;
@property (weak, nonatomic) IBOutlet UIButton *decryptButton;
@property (weak, nonatomic) IBOutlet UIButton *verifyButton;
@property (weak, nonatomic) IBOutlet UITextView *textView;
@property (strong, nonatomic) NSMutableDictionary *encrypted;
@property (weak, nonatomic) IBOutlet UIActivityIndicatorView *spinner;
@property (weak, nonatomic) IBOutlet UILabel *generateOk;
@property (weak, nonatomic) IBOutlet UILabel *signOk;
@property (weak, nonatomic) IBOutlet UILabel *encryptOk;
@property (weak, nonatomic) IBOutlet UILabel *decryptOk;
@property (weak, nonatomic) IBOutlet UILabel *verifyOk;

- (IBAction)generate:(id)sender;
- (IBAction)sign:(id)sender;
- (IBAction)encrypt:(id)sender;
- (IBAction)decrypt:(id)sender;
- (IBAction)verify:(id)sender;
- (void)generateKeyPairCompleted;

@end
