//
//  PPGodmfiTestController.m
//
#import "PPGodmfiTestController.h"

// The verdict-matrix test script, installed by the package.
static NSString *const kTestScript = @"/opt/pluginplayground/tests/amfi-verdict-matrix.sh";

@implementation PPGodmfiTestController

+ (NSString *)scriptPath { return kTestScript; }

+ (BOOL)isInstalled {
    return [[NSFileManager defaultManager] isExecutableFileAtPath:kTestScript];
}

+ (void)runWithCompletion:(void (^)(NSString *))completion {
    // `|| true` so a non-zero exit (any FAIL) does not make `do shell script` throw away the output.
    NSString *applescript = [NSString stringWithFormat:
        @"do shell script \"%@ 2>&1 || true\" with administrator privileges", kTestScript];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *result = [self runApplescriptBlocking:applescript];
        dispatch_async(dispatch_get_main_queue(), ^{ if (completion) completion(result); });
    });
}

+ (NSString *)runApplescriptBlocking:(NSString *)applescript {
    NSString *result;
    @try {
        NSTask *task = [[NSTask alloc] init];
        task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/osascript"];
        task.arguments = @[@"-e", applescript];
        NSPipe *outPipe = [NSPipe pipe];
        NSPipe *errPipe = [NSPipe pipe];
        task.standardOutput = outPipe;
        task.standardError = errPipe;
        NSError *err = nil;
        if (![task launchAndReturnError:&err]) {
            result = [NSString stringWithFormat:@"Failed to launch osascript: %@", err.localizedDescription];
        } else {
            NSData *outData = [[outPipe fileHandleForReading] readDataToEndOfFile];
            NSData *errData = [[errPipe fileHandleForReading] readDataToEndOfFile];
            [task waitUntilExit];
            NSString *out  = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding] ?: @"";
            NSString *erro = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding] ?: @"";
            if (out.length)                        result = out;
            else if ([erro containsString:@"-128"]) result = @"Cancelled — administrator authorization was denied.";
            else                                    result = erro.length ? erro : @"(no output)";
        }
    } @catch (NSException *ex) {
        result = [NSString stringWithFormat:@"Error running tests: %@", ex.reason];
    }
    return result;
}

@end
