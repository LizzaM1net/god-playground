//Created by Salty on 8/4/26.

#import <Foundation/Foundation.h>
#import <Swingset/Swingset.h>
#import <mach-o/dyld.h>
#import <mach-o/fat.h>
#import <sys/stat.h>

@interface PPFangsOptions : NSObject
@property (assign) BOOL disablePAC;
@property (assign) BOOL useLegacyAmmonia;
@property (assign) BOOL pauseInjection;
@end

@interface PPFangsLibraries : NSObject
+ (instancetype)fangsLibrariesWithLibraryPathArray:(NSArray<NSString *> *)pathArray;
@property (strong) NSArray<NSString *> *libs;
@property (strong, readonly) NSString *libsForDYLD;
@end

@interface PPOptionsLoader : NSObject
+ (PPFangsOptions *)loadOptions;
+ (PPFangsLibraries *)librariesForInsertionUsingAmmonia:(BOOL)ammonia toExePath:(const char *)path;

// Tweaks whose .options declares a `trajectory` take a dedicated path instead of DYLD injection
// (which amfid, a restricted platform binary, ignores anyway). They are NEVER DYLD-injected.
// Currently the only trajectory is "amfi-verdict-override": fangs resolves amfid's
// validateWithError: offset, keeps the dylib's vnode warm, and code-patches every amfid instance
// so the stub dlopen()s the dylib and routes the verdict through godmfi_decide.
// Returns the dylib paths whose trajectory begins with the given prefix (e.g. @"amfi").
+ (NSArray<NSString *> *)trajectoryLibrariesUsingAmmonia:(BOOL)ammonia withPrefix:(NSString *)prefix;
@end
