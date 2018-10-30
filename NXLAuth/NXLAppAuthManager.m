//
//  NXLAppAuthManager.m
//  NXLAuth
//
//  Created by Jason Lee on 30/10/2018.
//  Copyright © 2018 Jaosn Lee. All rights reserved.
//

#import "NXLAppAuthManager.h"
#import "NXLScopes.h"

#import <AppAuth/AppAuth.h>
#import <UIKit/UIKit.h>

OIDServiceConfiguration *_Nullable authConfig;
OIDAuthorizationRequest * authRequest = nil;
OIDAuthState *currentAuthState;

static NSString *kIssuer;
static NSString *kClientID;
static NSString *kRedirectURI;

typedef void (^PostRegistrationCallback)(OIDServiceConfiguration *configuration,
                                         OIDRegistrationResponse *registrationResponse);

static NSString *const kCurrentAuthStateKey = @"currentAuthState";

@implementation NXLAppAuthManager

- (instancetype)init {
    if (self = [super init]) {
        [self logMessage:@"[SSOFramework] SSOAppAuthManager Init"];
        [self loadState];
    }
    return self;
}

- (void)testMethod {
    NSLog(@"This is test method");
}

- (void)verifyConfig {
    [self logMessage:@"[SSOFramework] Verify Config"];
    NSDictionary *dictRoot = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle]pathForResource:@"configuration" ofType:@"plist"]];
    
    NSArray *arrayList = [NSArray arrayWithArray:[dictRoot objectForKey:@"SSOConfig"]];
    NSLog(@"[SSOFramework] Plist config: %@", arrayList);
    [arrayList enumerateObjectsUsingBlock:^(id obj, NSUInteger index, BOOL *stop) {
        NSLog(@"[Frameowrk] ISSUER: %@", [obj valueForKey:@"Issuer"]);
        NSLog(@"[Framework] CLIENT ID: %@", [obj valueForKey:@"ClientID"]);
        NSLog(@"[Framework] REDIRECT URL: %@", [obj valueForKey:@"RedirectURI"]);
        kIssuer = [obj valueForKey:@"Issuer"];
        kClientID = [obj valueForKey:@"ClientID"];
        kRedirectURI = [obj valueForKey:@"RedirectURI"];
#if !defined(NS_BLOCK_ASSERTIONS)
        
        // The example needs to be configured with your own client details.
        // See: https://github.com/openid/AppAuth-iOS/blob/master/Examples/Example-iOS_ObjC/README.md
        
        NSAssert(![kIssuer isEqualToString:@"https://issuer.example.com"],
                 @"Update kIssuer with your own issuer. "
                 "Instructions: https://github.com/openid/AppAuth-iOS/blob/master/Examples/Example-iOS_ObjC/README.md");
        
        NSAssert(![kClientID isEqualToString:@"YOUR_CLIENT_ID"],
                 @"Update kClientID with your own client ID. "
                 "Instructions: https://github.com/openid/AppAuth-iOS/blob/master/Examples/Example-iOS_ObjC/README.md");
        
        NSAssert(![kRedirectURI isEqualToString:@"com.example.app:/oauth2redirect/example-provider"],
                 @"Update kRedirectURI with your own redirect URI. "
                 "Instructions: https://github.com/openid/AppAuth-iOS/blob/master/Examples/Example-iOS_ObjC/README.md");
        
        // verifies that the custom URI scheme has been updated in the Info.plist
        NSArray __unused* urlTypes =
        [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleURLTypes"];
        NSAssert([urlTypes count] > 0, @"No custom URI scheme has been configured for the project.");
        NSArray *urlSchemes =
        [(NSDictionary *)[urlTypes objectAtIndex:0] objectForKey:@"CFBundleURLSchemes"];
        NSAssert([urlSchemes count] > 0, @"No custom URI scheme has been configured for the project.");
        NSString *urlScheme = [urlSchemes objectAtIndex:0];
        
        NSAssert(![urlScheme isEqualToString:@"com.example.app"],
                 @"Configure the URI scheme in Info.plist (URL Types -> Item 0 -> URL Schemes -> Item 0) "
                 "with the scheme of your redirect URI. Full instructions: "
                 "https://github.com/openid/AppAuth-iOS/blob/master/Examples/Example-iOS_ObjC/README.md");
        
#endif // !defined(NS_BLOCK_ASSERTIONS)
    }];
}

- (void)ssoAuthRequest:(nullable NSArray<NSString *> *)scopes :(void (^)(OIDAuthorizationRequest *request))completion {
    authRequest = nil;
    [self logMessage:@"[SSOFramework] ssoAuthRequest"];
    [self verifyConfig];
    
    NSURL *issuer = [NSURL URLWithString:kIssuer];
    
    [self logMessage:@"[SSOFramework] Fetching configuration for issuer: %@", issuer];
    
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    
    [OIDAuthorizationService discoverServiceConfigurationForIssuer:issuer completion:^(OIDServiceConfiguration *_Nullable configuration, NSError *_Nullable error) {
        [self logMessage:@"[SSOFramework] Got configuration document: %@", configuration.discoveryDocument];
        if (!configuration) {
            [self logMessage:@"[SSOFramework] Error retrieving discovery document: %@", [error localizedDescription]];
            [self setAuthState:nil];
            return;
        }
        
        [self logMessage:@"[SSOFramework] Got configuration: %@", configuration];
        if (!kClientID) {
            [self doClientRegistration:configuration
                              callback:^(OIDServiceConfiguration *configuration,
                                         OIDRegistrationResponse *registrationResponse) {
                                  authConfig = configuration;
                                  NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];
                                  
                                  authRequest =
                                  [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                                                clientId:registrationResponse.clientID
                                                                            clientSecret:registrationResponse.clientSecret
                                                                                  scopes:@[ OIDScopeOpenID, OIDScopeProfile ]
                                                                             redirectURL:redirectURI
                                                                            responseType:OIDResponseTypeCode
                                                                    additionalParameters:nil];
                                  [self logMessage:@"[SSOFramework] AuthRequest 0: %@", authRequest];
                              }];
        } else {
            [self logMessage:@"[SSOFramework] Done Retrieve Configuration"];
            authConfig = configuration;
            NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];
            
            authRequest =
            [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                          clientId:kClientID
                                                      clientSecret:nil
                                                            scopes:scopes
                                                       redirectURL:redirectURI
                                                      responseType:OIDResponseTypeCode
                                              additionalParameters:nil];
            [self logMessage:@"[SSOFramework] AuthRequest 0: %@", authRequest];
        }
        dispatch_semaphore_signal(sema);
    }];
    
    while (dispatch_semaphore_wait(sema, DISPATCH_TIME_NOW)) {
        [[NSRunLoop currentRunLoop]
         runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0]];
    }
    NSLog(@"[SSOFramework] AuthRequest 1: %@", authRequest);
    
    completion(authRequest);
    
    //    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    //        while(!authRequest);
    //       completion(authRequest);
    //    });
}

- (void)getUserInfo:(void (^)(NSDictionary* response))completion{
    NSURL *userinfoEndpoint =
    _authState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;
    if (!userinfoEndpoint) {
        [self logMessage:@"[Client] Userinfo endpoint not declared in discovery document"];
        return;
    }
    NSString *currentAccessToken = _authState.lastTokenResponse.accessToken;
    [self logMessage:@"[Client] Performing userinfo request"];
    
    [self getFreshToken:^(NSString * _Nonnull accessToken, NSString * _Nonnull idToken, OIDAuthState * _Nonnull currentAuthState, NSError * _Nullable error) {
        if (error) {
            [self logMessage:@"[Client1] Error fetching fresh tokens: %@", [error localizedDescription]];
            return;
        }
        // log whether a token refresh occurred
        if (![currentAccessToken isEqual:accessToken]) {
            [self logMessage:@"[Client] Token refreshed"];
            [self logMessage:@"Access token was refreshed automatically (%@ to %@)",
             currentAccessToken,
             accessToken];
            
        } else {
            [self logMessage:@"[Client] Token still valid"];
            [self logMessage:@"Access token was fresh and not updated [%@]", accessToken];
        }
        // creates request to the userinfo endpoint, with access token in the Authorization header
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:userinfoEndpoint];
        NSString *authorizationHeaderValue = [NSString stringWithFormat:@"Bearer %@", accessToken];
        [request addValue:authorizationHeaderValue forHTTPHeaderField:@"Authorization"];
        
        NSURLSessionConfiguration *configuration =
        [NSURLSessionConfiguration defaultSessionConfiguration];
        NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                                                              delegate:nil
                                                         delegateQueue:nil];
        
        [self logMessage:@"[Client] API Request URL: %@", request.URL];
        [self logMessage:@"[Client] API Request Header: %@", request.allHTTPHeaderFields];
        
        // performs HTTP request
        NSURLSessionDataTask *postDataTask =
        [session dataTaskWithRequest:request
                   completionHandler:^(NSData *_Nullable data,
                                       NSURLResponse *_Nullable response,
                                       NSError *_Nullable error) {
                       dispatch_async(dispatch_get_main_queue(), ^() {
                           if (error) {
                               [self logMessage:@"HTTP request failed %@", error];
                               return;
                           }
                           if (![response isKindOfClass:[NSHTTPURLResponse class]]) {
                               [self logMessage:@"Non-HTTP response"];
                               return;
                           }
                           
                           NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
                           id jsonDictionaryOrArray =
                           [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
                           
                           if (httpResponse.statusCode != 200) {
                               // server replied with an error
                               NSString *responseText = [[NSString alloc] initWithData:data
                                                                              encoding:NSUTF8StringEncoding];
                               if (httpResponse.statusCode == 401) {
                                   // "401 Unauthorized" generally indicates there is an issue with the authorization
                                   // grant. Puts OIDAuthState into an error state.
                                   NSError *oauthError =
                                   [OIDErrorUtilities resourceServerAuthorizationErrorWithCode:0
                                                                                 errorResponse:jsonDictionaryOrArray
                                                                               underlyingError:error];
                                   [self->_authState updateWithAuthorizationError:oauthError];
                                   // log error
                                   [self logMessage:@"Authorization Error (%@). Response: %@", oauthError, responseText];
                               } else {
                                   [self logMessage:@"HTTP: %d. Response: %@",
                                    (int)httpResponse.statusCode,
                                    responseText];
                               }
                               return;
                           }
                           
                           // success response
                           [self logMessage:@"Success: %@", jsonDictionaryOrArray];
                           completion(jsonDictionaryOrArray);
                       });
                   }];
        
        [postDataTask resume];
    }];
    
}

- (void)getFreshToken :(void (^)(NSString *_Nonnull accessToken, NSString *_Nonnull idToken, OIDAuthState *currentAuthState, NSError *_Nullable error))completion{
    NSLog(@"[SSOFramework] Get Fresh Token");
    NSString *currentAccessToken = _authState.lastTokenResponse.accessToken;
    [_authState performActionWithFreshTokens:^(NSString *_Nonnull accessToken,
                                               NSString *_Nonnull idToken,
                                               NSError *_Nullable error) {
        if (error) {
            [self logMessage:@"[Clientttt] Error fetching fresh tokens: %@", error];
            completion(accessToken, idToken, self->_authState, error);
            return;
        }
        
        // log whether a token refresh occurred
        if (![currentAccessToken isEqual:accessToken]) {
            [self logMessage:@"[SSOFramework] Token refreshed"];
            [self logMessage:@"Access token was refreshed automatically (%@ to %@)",
             currentAccessToken,
             accessToken];
            
        } else {
            [self logMessage:@"[SSOFramework] Token still valid"];
            [self logMessage:@"Access token was fresh and not updated [%@]", accessToken];
        }
        completion(accessToken, idToken, self->_authState, nil);
    }];
}

- (OIDAuthorizationRequest *)doAuthorizationRequest:(OIDServiceConfiguration *)configuration
                                           clientID:(NSString *)clientID
                                       clientSecret:(NSString *)clientSecret {
    NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];
    // builds authentication request
    OIDAuthorizationRequest *request =
    [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                  clientId:clientID
                                              clientSecret:clientSecret
                                                    scopes:@[ OIDScopeOpenID, OIDScopeProfile ]
                                               redirectURL:redirectURI
                                              responseType:OIDResponseTypeCode
                                      additionalParameters:nil];
    return request;
    
}

- (void)doClientRegistration:(OIDServiceConfiguration *)configuration
                    callback:(PostRegistrationCallback)callback {
    NSURL *redirectURI = [NSURL URLWithString:kRedirectURI];
    
    OIDRegistrationRequest *request =
    [[OIDRegistrationRequest alloc] initWithConfiguration:configuration
                                             redirectURIs:@[ redirectURI ]
                                            responseTypes:nil
                                               grantTypes:nil
                                              subjectType:nil
                                  tokenEndpointAuthMethod:@"client_secret_post"
                                     additionalParameters:nil];
    // performs registration request
    [self logMessage:@"Initiating registration request"];
    
    [OIDAuthorizationService performRegistrationRequest:request
                                             completion:^(OIDRegistrationResponse *_Nullable regResp, NSError *_Nullable error) {
                                                 if (regResp) {
                                                     [self setAuthState:[[OIDAuthState alloc] initWithRegistrationResponse:regResp]];
                                                     [self logMessage:@"Got registration response: [%@]", regResp];
                                                     callback(configuration, regResp);
                                                 } else {
                                                     [self logMessage:@"Registration error: %@", [error localizedDescription]];
                                                     [self setAuthState:nil];
                                                 }
                                             }];
}

- (id<OIDExternalUserAgentSession>)ssoAuthStateByPresentingAuthorizationRequest:(OIDAuthorizationRequest *)authorizationRequest presentingViewController:(UIViewController *)presentingViewController :(void (^)(OIDAuthState *authState))completion{
    
    [self logMessage:@"[SSOFramework] Open SVC@"];
    OIDExternalUserAgentIOS *externalUserAgent =
    [[OIDExternalUserAgentIOS alloc]
     initWithPresentingViewController:presentingViewController];
    
    id<OIDExternalUserAgentSession> userAgentSession = [OIDAuthState authStateByPresentingAuthorizationRequest:authRequest
                                                                                             externalUserAgent:externalUserAgent
                                                                                                      callback:^(OIDAuthState *_Nullable authState, NSError *_Nullable error) {
                                                                                                          completion(authState);
                                                                                                          NSLog(@"[SSOFramework] authState: %@", authState);
                                                                                                          NSLog(@"[SSOFramework] authorizationCode: %@", authState.lastAuthorizationResponse.authorizationCode);
                                                                                                          NSLog(@"[SSOFramework] accessToken: %@", authState.lastTokenResponse.accessToken);
                                                                                                          NSLog(@"[SSOFramework] idToken: %@", authState.lastTokenResponse.idToken);
                                                                                                          
                                                                                                          
                                                                                                          if (authState) {
                                                                                                              [self setAuthState:authState];
                                                                                                              [self logMessage:@"[SSOFramework] Got authorization tokens. Access token: %@",
                                                                                                               authState.lastTokenResponse.accessToken];
                                                                                                          } else {
                                                                                                              [self logMessage:@"[SSOFramework] Authorization error: %@", [error localizedDescription]];
                                                                                                              [self setAuthState:nil];
                                                                                                          }
                                                                                                      }];
    
    
    // take picture codes...
    
    return userAgentSession;
}

- (id<OIDExternalUserAgentSession>)takeMultipleImagesWithCompletion:(OIDAuthorizationRequest *)authorizationRequest
                                           presentingViewController:(UIViewController *)presentingViewController
                                                           callback:(OIDAuthStateAuthorizationCallback)callback {
    [self logMessage:@"[SSOFramework] Open SVC@"];
    OIDExternalUserAgentIOS *externalUserAgent =
    [[OIDExternalUserAgentIOS alloc]
     initWithPresentingViewController:presentingViewController];
    
    id<OIDExternalUserAgentSession> userAgentSession =  [OIDAuthState authStateByPresentingAuthorizationRequest:authRequest
                                                                                              externalUserAgent:externalUserAgent
                                                                                                       callback:callback];
    return userAgentSession;
}

- (void)logMessage:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2) {
    // gets message as string
    va_list argp;
    va_start(argp, format);
    NSString *log = [[NSString alloc] initWithFormat:format arguments:argp];
    va_end(argp);
    
    // outputs to stdout
    NSLog(@"%@", log);
}

- (void)didChangeState:(OIDAuthState *)state {
    NSLog(@"AAAAAAAA");
    [self stateChanged];
}

- (void)stateChanged {
    [self saveState];
    //    [self updateUI];
}

- (void)saveState {
    // for production usage consider using the OS Keychain instead
    NSLog(@"[SSOFramework] Save Current AuthState");
    //    NSLog(@"[SSOFramework] AuthState before archieve: %@", _authState);
    NSData *archivedAuthState = [ NSKeyedArchiver archivedDataWithRootObject:_authState];
    [[NSUserDefaults standardUserDefaults] setObject:archivedAuthState
                                              forKey:kCurrentAuthStateKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

- (void)loadState {
    // loads OIDAuthState from NSUSerDefaults
    NSLog(@"[SSOFramework] Load AuthState");
    NSData *archivedAuthState =
    [[NSUserDefaults standardUserDefaults] objectForKey:kCurrentAuthStateKey];
    OIDAuthState *authState = [NSKeyedUnarchiver unarchiveObjectWithData:archivedAuthState];
    if (!authState) {
        [self logMessage:@"[SSOFramework] Load Previous State: %@", nil];
    } else {
        [self logMessage:@"[SSOFramework] Load Previous State Success"];
    }
    [self setAuthState:authState];
}

- (void)setAuthState:(nullable OIDAuthState *)authState {
    NSLog(@"[SSOFramework] Set Current AuthState");
    if (_authState == authState) {
        return;
    }
    _authState = authState;
    _authState.stateChangeDelegate = self;
    [self stateChanged];
}

- (void)logOut2 {
    NSLog(@"Logout");
    [self setAuthState:nil];
}

- (void)logOut{
    NSURL *logoutEndpoint = [NSURL URLWithString:@"https://auth.sso.unifi.space/oauth2/auth/sessions/login/revoke"];
    //    if (!logoutEndpoint) {
    //        [self logMessage:@"[Client] Userinfo endpoint not declared in discovery document"];
    //        return;
    //    }
    NSString *currentAccessToken = _authState.lastTokenResponse.accessToken;
    [self logMessage:@"[Client] Logout request"];
    
    [self getFreshToken:^(NSString * _Nonnull accessToken, NSString * _Nonnull idToken, OIDAuthState * _Nonnull currentAuthState, NSError * _Nullable error) {
        if (error) {
            [self logMessage:@"[Client1] Error fetching fresh tokens: %@", [error localizedDescription]];
            return;
        }
        // log whether a token refresh occurred
        if (![currentAccessToken isEqual:accessToken]) {
            [self logMessage:@"[Client] Token refreshed"];
            [self logMessage:@"Access token was refreshed automatically (%@ to %@)",
             currentAccessToken,
             accessToken];
            
        } else {
            [self logMessage:@"[Client] Token still valid"];
            [self logMessage:@"Access token was fresh and not updated [%@]", accessToken];
        }
        // creates request to the userinfo endpoint, with access token in the Authorization header
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:logoutEndpoint];
        NSString *authorizationHeaderValue = [NSString stringWithFormat:@"Bearer %@", accessToken];
        [request addValue:authorizationHeaderValue forHTTPHeaderField:@"Authorization"];
        
        NSURLSessionConfiguration *configuration =
        [NSURLSessionConfiguration defaultSessionConfiguration];
        NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                                                              delegate:nil
                                                         delegateQueue:nil];
        
        [self logMessage:@"[Client] LOGOUT URL: %@", request.URL];
        [self logMessage:@"[Client] LOGOUT Header: %@", request.allHTTPHeaderFields];
        
        // performs HTTP request
        NSURLSessionDataTask *postDataTask =
        [session dataTaskWithRequest:request
                   completionHandler:^(NSData *_Nullable data,
                                       NSURLResponse *_Nullable response,
                                       NSError *_Nullable error) {
                       dispatch_async(dispatch_get_main_queue(), ^() {
                           if (error) {
                               [self logMessage:@"HTTP request failed %@", error];
                               return;
                           }
                           if (![response isKindOfClass:[NSHTTPURLResponse class]]) {
                               [self logMessage:@"Non-HTTP response"];
                               return;
                           }
                           
                           NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
                           id jsonDictionaryOrArray =
                           [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
                           
                           if (httpResponse.statusCode != 200) {
                               // server replied with an error
                               NSString *responseText = [[NSString alloc] initWithData:data
                                                                              encoding:NSUTF8StringEncoding];
                               if (httpResponse.statusCode == 401) {
                                   // "401 Unauthorized" generally indicates there is an issue with the authorization
                                   // grant. Puts OIDAuthState into an error state.
                                   NSError *oauthError =
                                   [OIDErrorUtilities resourceServerAuthorizationErrorWithCode:0
                                                                                 errorResponse:jsonDictionaryOrArray
                                                                               underlyingError:error];
                                   [self->_authState updateWithAuthorizationError:oauthError];
                                   // log error
                                   [self logMessage:@"Authorization Error (%@). Response: %@", oauthError, responseText];
                               } else {
                                   [self logMessage:@"HTTP: %d. Response: %@",
                                    (int)httpResponse.statusCode,
                                    responseText];
                               }
                               return;
                           }
                           
                           // success response
                           [self logMessage:@"Success: %@", jsonDictionaryOrArray];
                           //                           completion(jsonDictionaryOrArray);
                       });
                   }];
        
        [postDataTask resume];
        [self setAuthState:nil];
    }];
    
}

@end
