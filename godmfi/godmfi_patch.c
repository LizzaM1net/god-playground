//
//  godmfi_patch — shared amfid code-patch core (see godmfi_patch.h).
//
#include "godmfi_patch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <libproc.h>
#include <objc/runtime.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

extern const uint8_t godmfi_stub_start[];
extern const uint8_t godmfi_stub_params[];

#define MFI "/System/Library/PrivateFrameworks/AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity"
#define LOG(...) fprintf(stderr, "[godmfi] " __VA_ARGS__)

static uint64_t strip_ptr(void *p) {
#if __has_feature(ptrauth_calls)
    return (uint64_t)(uintptr_t)ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return (uint64_t)(uintptr_t)p;
#endif
}

static const char *base_name(const char *p) { const char *s = strrchr(p, '/'); return s ? s + 1 : p; }

// read a NUL-terminated C string from the remote task
static int remote_str(task_t t, uint64_t a, char *out, size_t n) {
    for (size_t i = 0; i < n - 1; i++) {
        uint8_t ch; mach_vm_size_t s = 1;
        if (mach_vm_read_overwrite(t, a + i, 1, (mach_vm_address_t)&ch, &s)) return -1;
        out[i] = ch; if (!ch) return 0;
    }
    out[n - 1] = 0; return 0;
}

int godmfi_resolve_offset(uint64_t *off_out, char *img_out, size_t img_sz) {
    void *h = dlopen(MFI, RTLD_NOW); (void)h;
    Class c = objc_getClass("AMFIPathValidator_macos");
    if (!c) { LOG("AMFIPathValidator_macos not found\n"); return 0; }
    Method m = class_getInstanceMethod(c, sel_registerName("validateWithError:"));
    if (!m) { LOG("validateWithError: not found\n"); return 0; }
    uint64_t limp = strip_ptr((void *)method_getImplementation(m));
    Dl_info info;
    if (!dladdr((void *)limp, &info) || !info.dli_fbase) { LOG("dladdr(imp) failed\n"); return 0; }
    if (!strstr(base_name(info.dli_fname), "AppleMobileFileIntegrity")) {
        LOG("imp resolved into %s, not AMFI — already swizzled? resolve must precede any godmfi.dylib dlopen\n",
            base_name(info.dli_fname));
        return 0;
    }
    *off_out = limp - (uint64_t)(uintptr_t)info.dli_fbase;
    strncpy(img_out, info.dli_fname, img_sz - 1); img_out[img_sz - 1] = 0;
    LOG("resolve: imp=0x%llx base=0x%llx off=0x%llx img=%s\n",
        limp, (uint64_t)(uintptr_t)info.dli_fbase, *off_out, img_out);
    return 1;
}

pid_t godmfi_find_amfid(void) {
    static pid_t pids[16384];
    for (int a = 0; a < 100; a++) {
        int n = proc_listallpids(pids, sizeof(pids));
        if (n < 0) n = 0;
        if (n > (int)(sizeof(pids) / sizeof(pids[0]))) n = sizeof(pids) / sizeof(pids[0]);
        for (int i = 0; i < n; i++) {
            char p[PROC_PIDPATHINFO_MAXSIZE];
            if (pids[i] > 0 && proc_pidpath(pids[i], p, sizeof(p)) > 0 &&
                strcmp(p, "/usr/libexec/amfid") == 0) return pids[i];
        }
        if (a == 0) LOG("amfid not running — kickstarting it...\n");
        system("launchctl kickstart system/com.apple.MobileFileIntegrity >/dev/null 2>&1");
        usleep(100000);
    }
    return -1;
}

// amfid's load base for the image whose basename matches `img` (read from amfid's dyld infos).
static uint64_t amfid_image_base(task_t task, const char *img) {
    struct task_dyld_info di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &cnt)) return 0;
    struct dyld_all_image_infos aii; mach_vm_size_t s = sizeof(aii);
    if (mach_vm_read_overwrite(task, di.all_image_info_addr, sizeof(aii), (mach_vm_address_t)&aii, &s)) return 0;
    for (uint32_t i = 0; i < aii.infoArrayCount; i++) {
        struct dyld_image_info ii; mach_vm_size_t s2 = sizeof(ii);
        if (mach_vm_read_overwrite(task, (mach_vm_address_t)aii.infoArray + i * sizeof(ii), sizeof(ii), (mach_vm_address_t)&ii, &s2)) continue;
        char path[1024];
        if (remote_str(task, (uint64_t)ii.imageFilePath, path, sizeof(path))) continue;
        if (strcmp(base_name(path), base_name(img)) == 0) return (uint64_t)ii.imageLoadAddress;
    }
    return 0;
}

uint64_t godmfi_amfid_imp(task_t task, uint64_t off, const char *img) {
    uint64_t abase = amfid_image_base(task, img);
    if (!abase) return 0;
    uint64_t cand = abase + off;
    uint8_t probe[16]; mach_vm_size_t ps = 16;
    if (mach_vm_read_overwrite(task, cand, 16, (mach_vm_address_t)probe, &ps) != KERN_SUCCESS) return 0;
    return cand;
}

// grant-style: trampoline@0x00, stub@0x40, data@params_off; entry patch -> stub.
int godmfi_patch_task(task_t task, uint64_t imp, const char *dylib) {
    // idempotency: skip if validateWithError: is already our entry-patch
    uint32_t cur[2] = {0, 0}; mach_vm_size_t cs = 8;
    mach_vm_read_overwrite(task, imp, 8, (mach_vm_address_t)cur, &cs);
    if (cur[0] == 0x58000051u && cur[1] == 0xD61F0220u) return 1;

    uint8_t orig[16]; mach_vm_size_t rs = 16;
    if (mach_vm_read_overwrite(task, imp, 16, (mach_vm_address_t)orig, &rs)) { LOG("read imp failed\n"); return -1; }

    mach_vm_address_t page = 0;
    if (mach_vm_allocate(task, &page, vm_page_size, VM_FLAGS_ANYWHERE)) { LOG("alloc failed\n"); return -1; }

    size_t stub_off   = 0x40;
    size_t code_sz    = (size_t)(godmfi_stub_params - godmfi_stub_start);
    size_t params_off = stub_off + code_sz;
    size_t sym_off    = params_off + 32;
    size_t path_off   = sym_off + 16;
    if (path_off + strlen(dylib) + 1 > (size_t)vm_page_size) { LOG("payload too big\n"); return -1; }

    uint8_t *buf = calloc(1, vm_page_size);
    // trampoline @0x00 = orig16 + ldr x17,#8 ; br x17 ; .quad imp+16
    memcpy(buf, orig, 16);
    *(uint32_t *)(buf + 16) = 0x58000051u;
    *(uint32_t *)(buf + 20) = 0xD61F0220u;
    *(uint64_t *)(buf + 24) = imp + 16;
    // stub code @0x40
    memcpy(buf + stub_off, godmfi_stub_start, code_sz);
    // params
    uint64_t *p = (uint64_t *)(buf + params_off);
    p[0] = (uint64_t)(page + path_off);     // path_addr
    p[1] = strip_ptr((void *)&dlopen);      // &dlopen (same VA in amfid)
    p[2] = strip_ptr((void *)&dlsym);       // &dlsym
    p[3] = (uint64_t)page;                  // trampoline @0x00
    strcpy((char *)(buf + sym_off),  "godmfi_decide");
    strcpy((char *)(buf + path_off), dylib);

    int rc = -1;
    if (mach_vm_write(task, page, (vm_offset_t)buf, vm_page_size)) { LOG("write page failed\n"); goto out; }
    if (mach_vm_protect(task, page, vm_page_size, 0, VM_PROT_READ | VM_PROT_EXECUTE)) { LOG("protect page failed\n"); goto out; }

    // entry patch @ imp: ldr x17,#8 ; br x17 ; .quad (page+stub_off)
    uint8_t patch[16];
    *(uint32_t *)(patch + 0) = 0x58000051u;
    *(uint32_t *)(patch + 4) = 0xD61F0220u;
    *(uint64_t *)(patch + 8) = page + stub_off;
    mach_vm_address_t fp = imp & ~((mach_vm_address_t)vm_page_size - 1);
    if (mach_vm_protect(task, fp, vm_page_size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) { LOG("protect imp rw failed\n"); goto out; }
    if (mach_vm_write(task, imp, (vm_offset_t)patch, 16)) { LOG("write imp failed\n"); goto out; }
    mach_vm_protect(task, fp, vm_page_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    LOG("hooked amfid: IMP 0x%llx -> stub 0x%llx (tramp 0x%llx) dylib=%s\n",
        imp, (uint64_t)(page + stub_off), (uint64_t)page, dylib);
    rc = 0;
out:
    free(buf);
    return rc;
}
