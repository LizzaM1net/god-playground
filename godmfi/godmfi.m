//
//  godmfi.dylib — cert-pinned amfid verdict, loaded into amfid by godmfi-launch/fangs.
//
//  - exports godmfi_decide(): the verdict for validateWithError:, called by the code-patch
//    stub (so the triggering binary itself gets the override on its FIRST validation — no
//    sacrificial binary). It runs the ORIGINAL via the trampoline, then overrides for god.
//  - swizzles the getters the handler reads AFTER validateWithError (isValid /
//    areEntitlementsValidated / signerType) so they report god values on that same call.
//  - is_god() reads the validator's URL straight from its ivar (works for the current
//    validator too — no init swizzle, no associated object).
//
//  Pin: /Library/Application Support/godmfi/pin.plist (cert_sha256, observe, signer_type).
//
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <CommonCrypto/CommonDigest.h>
#import <os/log.h>
#import <stdarg.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

static NSData  *gPin = nil;      // 32-byte god cert SHA-256
static BOOL     gObserve = NO;   // observe-only: log the real verdict, never override
static BOOL     gHasSigner = NO;
static long     gSigner = 0;
static BOOL     gDebug = NO;     // pin.plist "debug": append a verbose trail to /tmp/godmfi.log
static os_log_t gLog;

// Verbose debug trail — off unless pin.plist sets debug=true. The load line always goes to os_log.
static void flog(const char *fmt, ...) {
    if (!gDebug) return;
    FILE *f = fopen("/tmp/godmfi.log", "a"); if (!f) return;
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f); fclose(f);
}

static void load_pin(void) {
    gLog = os_log_create("com.awaremeta.godmfi", "amfid");
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:@"/Library/Application Support/godmfi/pin.plist"];
    gObserve = [d[@"observe"] boolValue];
    gDebug   = [d[@"debug"] boolValue];
    NSString *hex = d[@"cert_sha256"];
    if (hex.length == 64) {
        NSMutableData *raw = [NSMutableData dataWithLength:32];
        uint8_t *b = raw.mutableBytes; const char *s = hex.UTF8String; BOOL ok = YES;
        for (int i = 0; i < 32; i++) { unsigned v; if (sscanf(s + 2*i, "%2x", &v) != 1) { ok = NO; break; } b[i] = (uint8_t)v; }
        if (ok) gPin = raw;
    }
    if (d[@"signer_type"]) { gHasSigner = YES; gSigner = [d[@"signer_type"] integerValue]; }
}

// Decide whether `code` is a genuine god binary.
//
// TWO things must hold, and the old code only checked the first:
//   1. Identity: the leaf signing cert is exactly our pinned god cert (SHA-256 == pin).
//   2. Possession: the code signature is CRYPTOGRAPHICALLY VALID — the CMS was actually produced
//      by the private key matching that leaf cert, over this code's CodeDirectory.
//
// Checking (1) alone — hashing the cert extracted via kSecCSSigningInformation — is NOT a
// signature check: that cert is public (god.crt + the pin are world-readable), and the extracted
// cert chain is whatever bytes are embedded in the signature blob, verified or not. An attacker
// who embeds the public god cert in a binary they signed with their OWN key would pass (1). So we
// MUST also verify (2).
//
// We can't lean on amfid's own verdict (it rejects the god cert as an untrusted anchor), but we
// CAN ask Security to verify the signature itself against a requirement pinned to the god cert.
// SecStaticCodeCheckValidity verifies the CodeDirectory hashes AND the CMS signature over them;
// pinning the anchor/leaf by hash makes a self-signed god cert acceptable WITHOUT chaining to
// Apple, while a forged binary (god cert present, signed by another key) fails signature
// verification. This makes the private key the real gate.
//
// NOTE: requirement-language cert hashes (H"...") are SHA-1 of the DER cert, not SHA-256.
// NOTE: verify on-device — if CheckValidity rejects the self-signed anchor on this macOS build
//       (errSecCSSignatureUntrustedCert), fall back to a manual CMS verification against the pin.
static BOOL code_is_god(SecStaticCodeRef code) {
    if (!gPin || !code) return NO;

    // 1. Identity: extract the leaf, confirm SHA-256 == pin, and derive its SHA-1 for the pin req.
    CFDictionaryRef info = NULL;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess || !info)
        return NO;
    BOOL identity_ok = NO;
    uint8_t sha1[CC_SHA1_DIGEST_LENGTH];
    CFArrayRef certs = CFDictionaryGetValue(info, kSecCodeInfoCertificates);
    if (certs && CFArrayGetCount(certs) > 0) {
        SecCertificateRef leaf = (SecCertificateRef)CFArrayGetValueAtIndex(certs, 0);
        CFDataRef der = SecCertificateCopyData(leaf);
        if (der) {
            uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(CFDataGetBytePtr(der), (CC_LONG)CFDataGetLength(der), sha256);
            if (memcmp(sha256, gPin.bytes, CC_SHA256_DIGEST_LENGTH) == 0) {
                CC_SHA1(CFDataGetBytePtr(der), (CC_LONG)CFDataGetLength(der), sha1);
                identity_ok = YES;
            }
            CFRelease(der);
        }
    }
    CFRelease(info);
    if (!identity_ok) { flog("[godmfi] leaf != pin"); return NO; }

    // 2. Possession: verify the signature, pinned to that exact cert as leaf AND anchor (the god
    //    cert is self-signed, so it is both). A valid CMS from the god key is required to pass.
    char hex[CC_SHA1_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) sprintf(hex + 2 * i, "%02x", sha1[i]);
    NSString *reqStr = [NSString stringWithFormat:
        @"certificate leaf = H\"%s\" and anchor = H\"%s\"", hex, hex];
    SecRequirementRef req = NULL;
    if (SecRequirementCreateWithString((__bridge CFStringRef)reqStr, kSecCSDefaultFlags, &req) != errSecSuccess || !req) {
        flog("[godmfi] SecRequirementCreateWithString failed");
        return NO;
    }
    // Only the main executable's signature matters for the verdict; amfid validates resources
    // separately, so skip them here (faster, and avoids spurious resource-level failures).
    OSStatus v = SecStaticCodeCheckValidity(code, kSecCSDoNotValidateResources, req);
    CFRelease(req);
    BOOL ok = (v == errSecSuccess);
    flog("[godmfi] CheckValidity=%d (leaf+anchor pinned) -> god=%d", (int)v, ok);
    return ok;
}

// Get the SecStaticCode amfid is validating straight off the validator object:
//   AMFIPathValidator_macos -> `_code` ivar (SecStaticCodeRef, enc ^{__SecCode=}) [borrowed]
//   AMFIPathValidator_ios   -> `_url` ivar (NSURL) -> SecStaticCodeCreateWithPath [owned]
// *owned tells the caller whether to CFRelease the returned ref.
static SecStaticCodeRef validator_code(id self, BOOL *owned) {
    *owned = NO;
    Class c = object_getClass(self);
    unsigned n = 0; Ivar *ivs = class_copyIvarList(c, &n);
    SecStaticCodeRef code = NULL; NSURL *url = nil;
    void *base = (__bridge void *)self;
    for (unsigned i = 0; i < n; i++) {
        const char *nm = ivar_getName(ivs[i]);
        const char *enc = ivar_getTypeEncoding(ivs[i]);
        if (nm && strcmp(nm, "_code") == 0 && enc && strstr(enc, "__SecCode")) {
            code = *(SecStaticCodeRef *)((uint8_t *)base + ivar_getOffset(ivs[i]));  // borrowed
            break;
        }
        if (!url && enc && strstr(enc, "NSURL")) {
            id v = object_getIvar(self, ivs[i]);
            if ([v isKindOfClass:[NSURL class]]) url = v;
        }
    }
    if (ivs) free(ivs);
    if (code) return code;                 // borrowed; *owned stays NO
    if (url) {
        SecStaticCodeRef mk = NULL;
        if (SecStaticCodeCreateWithPath((__bridge CFURLRef)url, kSecCSDefaultFlags, &mk) == errSecSuccess && mk) {
            *owned = YES; return mk;
        }
    }
    return NULL;
}

static BOOL is_god(id self) {
    BOOL owned = NO;
    SecStaticCodeRef code = validator_code(self, &owned);
    BOOL g = code_is_god(code);
    if (owned && code) CFRelease(code);
    flog("[godmfi] is_god=%d class=%s", g, class_getName(object_getClass(self)));
    return g;
}

// shared verdict core: `getreal` returns the ORIGINAL validateWithError: result.
static long decide(id self, SEL sel, void *err, long (*getreal)(id, SEL, void *)) {
    long real = getreal(self, sel, err);
    if (gObserve) { flog("[godmfi] observe validateWithError=%ld god=%d", real, is_god(self)); return real; }
    if (!real && is_god(self)) { flog("[godmfi] override validateWithError -> 1"); return 1; }
    return real;
}

// exported: used by the launcher's code-patch stub for the IN-FLIGHT (current) validation,
// where the ObjC swizzle below isn't active yet. tramp = the stub's trampoline to the orig.
__attribute__((visibility("default")))
long godmfi_decide(id self, SEL sel, void *err, void *tramp_raw) {
    // tramp_raw is a RAW code address (the stub's trampoline, page+0) with no PAC signature.
    // On arm64e, calling it as a C function pointer would auth-branch (blraa) and fault, so we
    // sign it for the function-pointer key (discriminator 0 = the macOS C function-pointer ABI).
#if __has_feature(ptrauth_calls)
    long (*tramp)(id, SEL, void *) = ptrauth_sign_unauthenticated(tramp_raw, ptrauth_key_function_pointer, 0);
#else
    long (*tramp)(id, SEL, void *) = (long (*)(id, SEL, void *))tramp_raw;
#endif
    return decide(self, sel, err, tramp);
}

// ---- swizzles: validateWithError: (fangs path + future calls) + the 3 getters ----
static NSMutableDictionary *gOrig;
static IMP origFor(id self, SEL s) {
    NSValue *v = gOrig[[NSString stringWithFormat:@"%s:%s", class_getName(object_getClass(self)), sel_getName(s)]];
    return v ? (IMP)v.pointerValue : NULL;
}
static BOOL repl_validate(id self, SEL _cmd, void *err) {
    long (*o)(id, SEL, void *) = (void *)origFor(self, _cmd);
    return (BOOL)decide(self, _cmd, err, o);
}
static BOOL repl_isValid(id self, SEL _cmd) {
    BOOL (*o)(id, SEL) = (void *)origFor(self, _cmd); BOOL v = o(self, _cmd);
    if (gObserve) return v;
    return (!v && is_god(self)) ? YES : v;
}
static BOOL repl_areEnt(id self, SEL _cmd) {
    BOOL (*o)(id, SEL) = (void *)origFor(self, _cmd); BOOL v = o(self, _cmd);
    if (gObserve) return v;
    return (!v && is_god(self)) ? YES : v;
}
static long repl_signerType(id self, SEL _cmd) {
    long (*o)(id, SEL) = (void *)origFor(self, _cmd); long v = o(self, _cmd);
    if (gObserve) return v;
    return (gHasSigner && is_god(self)) ? gSigner : v;
}
static void swiz(Class c, SEL s, IMP r) {
    if (!c) return; Method m = class_getInstanceMethod(c, s); if (!m) return;
    IMP o = method_setImplementation(m, r);
    gOrig[[NSString stringWithFormat:@"%s:%s", class_getName(c), sel_getName(s)]] = [NSValue valueWithPointer:o];
}

__attribute__((constructor))
static void godmfi_init(void) {
    @autoreleasepool {
        load_pin();
        gOrig = [NSMutableDictionary dictionary];
        Class m = objc_getClass("AMFIPathValidator_macos");
        Class i = objc_getClass("AMFIPathValidator_ios");
        Class cs[2] = { m, i };
        for (int k = 0; k < 2; k++) {
            swiz(cs[k], @selector(validateWithError:), (IMP)repl_validate);
            swiz(cs[k], @selector(isValid), (IMP)repl_isValid);
            swiz(cs[k], @selector(areEntitlementsValidated), (IMP)repl_areEnt);
            swiz(cs[k], @selector(signerType), (IMP)repl_signerType);
        }
        os_log(gLog, "godmfi loaded (macos=%d ios=%d observe=%d pinned=%d debug=%d)",
               m != nil, i != nil, gObserve, gPin != nil, gDebug);
        flog("[godmfi] constructor: macos=%d ios=%d observe=%d pinned=%d", m != nil, i != nil, gObserve, gPin != nil);
    }
}
