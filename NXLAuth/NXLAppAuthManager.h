//
//  NXLAppAuthManager.h
//  NXLAuth
//
//  Created by Jason Lee on 30/10/2018.
//  Copyright © 2018 Jaosn Lee. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppAuth/AppAuth.h>

@class OIDAuthState;
@class OIDServiceConfiguration;

@interface NXLAppAuthManager : NSObject <OIDAuthStateChangeDelegate>

@property(nonatomic, strong, nullable) OIDAuthState *authState;

// testing method
- (void)testMethod;

// get Authorization Request URL
- (void)ssoAuthRequest:(nullable NSArray<NSString *> *)scopes :(void (^)(OIDAuthorizationRequest *request))completion;

// perform Authorization Request
- (id<OIDExternalUserAgentSession>)ssoAuthStateByPresentingAuthorizationRequest:(OIDAuthorizationRequest *)authorizationRequest presentingViewController:(UIViewController *)presentingViewController :(void (^)(OIDAuthState *authState))completion;

// get fresh token
- (void)getFreshToken :(void (^)(NSString *_Nonnull accessToken, NSString *_Nonnull idToken, OIDAuthState *currentAuthState, NSError *_Nullable error))completion;

// get User Info
- (void)getUserInfo :(void (^)(NSDictionary* response))completion;

// logout
- (void)logOut;

- (id<OIDExternalUserAgentSession>)takeMultipleImagesWithCompletion:(OIDAuthorizationRequest *)authorizationRequest presentingViewController:(UIViewController *)presentingViewController
                                                           callback:(OIDAuthStateAuthorizationCallback)callback;


@end
