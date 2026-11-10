//
//  PPGodmfiTestController — a small window that runs the installed amfi verdict-matrix test
//  script with administrator privileges and shows its output.
//
#import <Cocoa/Cocoa.h>

@interface PPGodmfiTestController : NSObject
- (void)showWindow;

// Shared runner, used by this window and by the main-screen godmfi box.
+ (NSString *)scriptPath;
+ (BOOL)isInstalled;
// Runs the test script as root (admin prompt) on a background queue; completion on the main thread.
+ (void)runWithCompletion:(void (^)(NSString *output))completion;
@end
