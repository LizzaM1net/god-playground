//
//  godmfi_patch — shared amfid code-patch core, used by godmfi-launch (standalone) and fangs
//  (persistent, per-amfid-spawn). Single-shot primitives so fangs can drive retries from its own
//  non-blocking run loop instead of sleeping.
//
#pragma once
#include <mach/mach.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>   // pid_t

#ifdef __cplusplus
extern "C" {
#endif

// Resolve validateWithError:'s slide-invariant offset within AppleMobileFileIntegrity, in THIS
// process. MUST be called before this process dlopen()s godmfi.dylib — that dylib's constructor
// swizzles the method here, after which method_getImplementation returns our own repl_validate.
// img_out receives the MFI image path (its basename locates amfid's load base). 1 = ok, 0 = fail.
int godmfi_resolve_offset(uint64_t *off_out, char *img_out, size_t img_sz);

// Find /usr/libexec/amfid, gently kickstarting it (launchctl kickstart, not -k) if absent.
// Returns pid or -1. Polls up to ~10s.
pid_t godmfi_find_amfid(void);

// amfid's validateWithError: address = amfid's base for `img` + off — but only if that address is
// readable in `task` right now (i.e. amfid finished exec + dyld init). Returns the imp, or 0 if
// the image isn't in amfid's dyld list yet / not readable. Lets a caller poll a freshly spawned
// amfid without blocking.
uint64_t godmfi_amfid_imp(task_t task, uint64_t off, const char *img);

// Single-shot code-patch of amfid's validateWithError: at `imp`: writes a trampoline + a stub that
// dlopen()s `dylib` and routes the verdict through godmfi_decide. Idempotent.
// Returns 0 = patched, 1 = already patched (skipped), -1 = error.
int godmfi_patch_task(task_t task, uint64_t imp, const char *dylib);

#ifdef __cplusplus
}
#endif
