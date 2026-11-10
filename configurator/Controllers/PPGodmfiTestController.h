//
//  PPGodmfiTestController — runs the installed amfi verdict-matrix test script with administrator
//  privileges. Used by the main-screen godmfi box (PPMainViewController).
//
#import <Foundation/Foundation.h>

@interface PPGodmfiTestController : NSObject
+ (NSString *)scriptPath;
+ (BOOL)isInstalled;
// Runs the test script as root (admin prompt) on a background queue; completion on the main thread.
+ (void)runWithCompletion:(void (^)(NSString *output))completion;
@end
