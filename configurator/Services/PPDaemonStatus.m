//Created by Salty on 9/2/26.

#import "PPDaemonStatus.h"
#import <libproc.h>

NSString* const plistPath = @"/Library/LaunchDaemons/com.pluginplayground.godmfi.plist";

@implementation PPDaemonStatus
+ (BOOL)fangsIsRunning {
    NSTask *checkTask = [[NSTask alloc] init];
    [checkTask setArguments:@[@"-x", @"fangs"]];
    [checkTask setLaunchPath:@"/usr/bin/pgrep"];

    [checkTask setStandardOutput:[NSFileHandle fileHandleWithNullDevice]];
    [checkTask setStandardError:[NSFileHandle fileHandleWithNullDevice]];
    
    NSError *err = nil;

    if (![checkTask launchAndReturnError:&err]) {
        return NO;
    }
    
    [checkTask waitUntilExit];
    
    return [checkTask terminationStatus] == 0;
}

+ (BOOL)plistExists {
    NSFileManager *fm = [NSFileManager defaultManager];
    return [fm fileExistsAtPath:plistPath];
}

+ (void)removePlist {
    if (![PPDaemonStatus plistExists])
        return;

    NSString *script = [NSString stringWithFormat:
        @"do shell script \"rm -f %@\" with administrator privileges",
        plistPath];

    NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:script];

    NSDictionary *errorInfo = nil;
    [appleScript executeAndReturnError:&errorInfo];

    if (errorInfo) {
        NSLog(@"Failed to remove plist: %@", errorInfo);
    }
}

+ (void)addPlist {
    if ([PPDaemonStatus plistExists])
        return;
    
    NSDictionary *plistDict = @{
        @"Label" : @"com.pluginplayground.godmfi",
        @"ProgramArguments" : @[@"/opt/pluginplayground/bin/godmfi-launch",
                                @"/opt/pluginplayground/bin/fangs"],
        @"RunAtLoad" : @YES,
        @"KeepAlive" : @YES,
        @"StandardOutPath" : @"/var/log/pluginplayground/godmfi.log",
        @"StandardErrorPath" : @"/var/log/pluginplayground/godmfi.err"
    };

    NSData *plistData =
        [NSPropertyListSerialization dataWithPropertyList:plistDict
                                                   format:NSPropertyListXMLFormat_v1_0
                                                  options:0
                                                    error:nil];

    NSString *base64 = [plistData base64EncodedStringWithOptions:0];

    NSString *script =
        [NSString stringWithFormat:
            @"do shell script \"echo %@ | base64 -D > %@ && "
             "chown root:wheel %@ && "
             "chmod 644 %@ && "
             "launchctl load %@\" with administrator privileges",
             base64,
             plistPath,
             plistPath,
             plistPath,
             plistPath];

    NSAppleScript *appleScript =
        [[NSAppleScript alloc] initWithSource:script];

    NSDictionary *errorInfo = nil;
    [appleScript executeAndReturnError:&errorInfo];

    if (errorInfo)
        NSLog(@"Failed to install plist: %@", errorInfo);
}
@end
