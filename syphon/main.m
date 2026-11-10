#include "syphon.h"
#include "exe.h"
#import "PPOptionsLoader.h"
#include <mach/task.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <ptrauth.h>
#include <dlfcn.h>
#include "godmfi_patch.h"

// ---- amfi-verdict-override trajectory --------------------------------------------------------
// A tweak whose .options sets trajectory="amfi-..." is NOT DYLD-injected (amfid, a restricted
// platform binary, strips DYLD_INSERT_LIBRARIES — proven). Instead fangs resolves amfid's
// validateWithError: offset once, keeps the dylib's vnode warm, and code-patches every amfid it
// sees spawn so the stub dlopen()s the dylib and routes the verdict through godmfi_decide.
//
// Pre-warm = avoid re-entrancy. When amfid (patched) dlopen()s our dylib, the kernel asks amfid
// to validate it; if amfid is mid-validateWithError the request re-enters and DEADLOCKS amfid
// (and every process waiting on a code-sign check). The fix is that the dylib's signature must
// already be cached in the kernel BEFORE a patched amfid loads it. fangs warms it by dlopen()'ing
// it itself — but the warm's own validation is served by amfid, so it is only safe to warm
// through an amfid that is NOT yet patched (answers normally) or that already holds this dylib
// (dyld dedups dlopen by path → its stub returns the loaded copy, no new load, no re-entry).
//
// Therefore the invariant: NEVER let a patched amfid perform the FIRST (cold) load of an inode.
//   - amfi_ensure_warm() holds a handle for the CURRENT on-disk inode; on an inode change it
//     dlclose()s the stale handle first (path-dedup would otherwise hand back the old inode).
//   - amfi_try_patch() warms the current inode THROUGH the freshly spawned, still-unpatched amfid,
//     and patches ONLY once that inode is confirmed warm (else it leaves amfid unpatched — safe).
//   - A running amfid keeps whatever inode it first loaded (path-dedup), so a changed file is
//     adopted only on respawn: amfi_watch_reload() schedules a debounced `launchctl kickstart -k`
//     of amfid so a fresh (unpatched) amfid loads the new inode via the warm path above.
// NB update the file by atomic rename (install/mv), never `cp` over the live inode — a cp
// truncates the inode we have mapped and SIGKILLs us, and a dying fangs panics launchd
// (see macos-launchd-sigtrap-fangs-breakpoint).
#define AMFI_MAX 8
static uint64_t g_amfi_off = 0;        // validateWithError: offset within AppleMobileFileIntegrity
static char     g_amfi_img[1024];      // MFI image path (locates amfid's load base)
static int      g_amfi_ready = 0;      // offset resolved + at least one trajectory dylib present
static NSArray<NSString *> *g_amfi_dylibs = nil;  // dylibs to warm + patch amfid with
static void    *g_amfi_handle[AMFI_MAX];          // held dlopen handles (NULL = released / cold)
static ino_t    g_amfi_ino[AMFI_MAX];             // inode we hold warm (what amfid will also load)
static time_t   g_amfi_mtime[AMFI_MAX];           // file mtime when warmed
static volatile pid_t g_amfi_pending = 0;         // a spawned amfid awaiting its code-patch
static int      g_amfi_reload_pending = 0;        // a trajectory dylib changed → amfid must restart

// Current on-disk inode of trajectory dylib i (0 if missing).
static ino_t amfi_disk_ino(unsigned i) {
    struct stat st;
    return (stat([g_amfi_dylibs[i] UTF8String], &st) == 0) ? st.st_ino : 0;
}

// Ensure we hold a warm dlopen handle for the CURRENT on-disk inode of trajectory dylib i. If we
// already hold a DIFFERENT (stale) inode, dlclose it first — dyld dedups dlopen by path, so
// without the dlclose dlopen would hand back the old image and the new inode would stay cold.
// The dlopen's signature check is served by whatever amfid is current, so the caller MUST invoke
// this only when that amfid is safe to ask (unpatched, or already holding this dylib via dedup) —
// i.e. warm-before-patch against a freshly spawned amfid. Returns 1 iff warm for the current inode.
static int amfi_ensure_warm(unsigned i) {
    if (i >= [g_amfi_dylibs count] || i >= AMFI_MAX) return 0;
    const char *p = [g_amfi_dylibs[i] UTF8String];
    ino_t disk = amfi_disk_ino(i);
    if (g_amfi_handle[i]) {
        if (disk != 0 && g_amfi_ino[i] == disk) return 1;     // already warm for the current inode
        dlclose(g_amfi_handle[i]);                            // stale inode → drop (path-dedup)
        g_amfi_handle[i] = NULL; g_amfi_ino[i] = 0; g_amfi_mtime[i] = 0;
        printf("[amfi] %s inode changed — released stale warm handle\n", p); fflush(stdout);
    }
    void *h = dlopen(p, RTLD_NOW);
    if (!h) { printf("[amfi] WARN dlopen failed: %s (%s)\n", p, dlerror()); fflush(stdout); return 0; }
    struct stat st;
    g_amfi_handle[i] = h;
    g_amfi_ino[i]    = (stat(p, &st) == 0) ? st.st_ino : 0;
    g_amfi_mtime[i]  = (stat(p, &st) == 0) ? st.st_mtimespec.tv_sec : 0;
    printf("[amfi] warmed vnode %s (ino %llu)\n", p, (unsigned long long)g_amfi_ino[i]);
    fflush(stdout);
    return g_amfi_handle[i] != NULL && g_amfi_ino[i] != 0;
}

// Resolve the offset (MUST precede any godmfi.dylib dlopen — it swizzles the method locally) and
// warm each trajectory dylib's vnode.
static void amfi_setup(BOOL ammonia) {
    @autoreleasepool {
        g_amfi_dylibs = [PPOptionsLoader trajectoryLibrariesUsingAmmonia:ammonia withPrefix:@"amfi"];
        if ([g_amfi_dylibs count] == 0) { g_amfi_ready = 0; return; }
        if (!g_amfi_ready) {
            if (godmfi_resolve_offset(&g_amfi_off, g_amfi_img, sizeof g_amfi_img)) g_amfi_ready = 1;
            else { printf("[amfi] resolve failed — trajectory disabled\n"); fflush(stdout); return; }
        }
        for (unsigned i = 0; i < [g_amfi_dylibs count] && i < AMFI_MAX; i++) amfi_ensure_warm(i);
    }
}

// Cheap per-tick watch: if a warmed dylib's file changed (new inode or mtime) or vanished, release
// our held handle and flag that amfid must be restarted to adopt the new inode. We do NOT re-warm
// here (that would route the validation through the resident, possibly-patched amfid and could
// re-enter); the re-warm happens safely in amfi_try_patch against the freshly spawned amfid.
static void amfi_watch_reload(void) {
    @autoreleasepool {
        for (unsigned i = 0; i < [g_amfi_dylibs count] && i < AMFI_MAX; i++) {
            if (!g_amfi_handle[i]) continue;
            struct stat st;
            int ok = (stat([g_amfi_dylibs[i] UTF8String], &st) == 0);
            if (!ok || st.st_ino != g_amfi_ino[i] || st.st_mtimespec.tv_sec != g_amfi_mtime[i]) {
                dlclose(g_amfi_handle[i]);
                g_amfi_handle[i] = NULL; g_amfi_ino[i] = 0; g_amfi_mtime[i] = 0;
                g_amfi_reload_pending = 1;
                printf("[amfi] %s changed on disk — released; scheduling amfid restart\n", [g_amfi_dylibs[i] UTF8String]);
                fflush(stdout);
            }
        }
    }
}

// A trajectory dylib changed: the resident amfid still holds the OLD inode (stale but safe). Kick
// amfid so a fresh (unpatched) one loads the NEW inode via amfi_try_patch's warm-before-patch.
// Debounced ≥15s so rapid edits don't trip launchd's respawn throttle (and never raw SIGKILL,
// which does throttle). Clears the flag only once a kickstart is actually issued.
static void amfi_reload_amfid_if_pending(void) {
    if (!g_amfi_reload_pending || !g_amfi_ready) return;
    static uint64_t last_kick_ns = 0;
    uint64_t now_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    if (last_kick_ns && now_ns - last_kick_ns < 15000000000ULL) return;   // ≥15s between kickstarts
    printf("[amfi] restarting amfid to adopt the new dylib inode\n"); fflush(stdout);
    system("launchctl kickstart -k system/com.apple.MobileFileIntegrity >/dev/null 2>&1");
    last_kick_ns = now_ns;
    g_amfi_reload_pending = 0;
}

// One non-blocking attempt to code-patch a (freshly spawned, still-unpatched) amfid. Warms the
// CURRENT inode of every trajectory dylib FIRST — routed through this unpatched amfid, so the
// signature check is answered normally and the inode's verdict lands in the kernel cache. Only
// then, and only if the patch dylib is confirmed warm for its current on-disk inode, do we patch;
// otherwise we leave amfid unpatched (godmfi inactive, but no cold-first-load deadlock).
// Returns 1 if patched/already, 0 if not ready (caller retries next tick).
static int amfi_try_patch(pid_t pid) {
    if (!g_amfi_ready || pid <= 0 || [g_amfi_dylibs count] == 0) return 0;
    for (unsigned i = 0; i < [g_amfi_dylibs count] && i < AMFI_MAX; i++)
        amfi_ensure_warm(i);                   // warm current inode through this unpatched amfid
    if (!g_amfi_handle[0] || g_amfi_ino[0] != amfi_disk_ino(0)) {
        printf("[amfi] patch dylib not warm for current inode — skipping patch of pid=%d\n", pid);
        fflush(stdout);
        return 0;                              // never patch while the current inode is cold
    }
    task_t task = TASK_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS || task == TASK_NULL) return 0;
    int done = 0;
    uint64_t imp = godmfi_amfid_imp(task, g_amfi_off, g_amfi_img);
    if (imp) {
        int r = godmfi_patch_task(task, imp, [[g_amfi_dylibs firstObject] UTF8String]);
        if (r >= 0) { done = 1; printf("[amfi] amfid pid=%d code-patched (r=%d)\n", pid, r); fflush(stdout); }
    }
    mach_port_deallocate(mach_task_self(), task);
    return done;
}

task_t g_task;
mach_port_t g_exc_port;
static volatile sig_atomic_t g_running = 1;
static PPFangsOptions *g_opts;
static time_t g_opts_mtime;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_envp(task_t task, uint64_t addr) {
    char *ptrs[256];
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, sizeof(ptrs),
                                               (mach_vm_address_t)ptrs, &out);
    if (kr != KERN_SUCCESS) { printf("  envp=0x%llx (unreadable)\n", addr); return; }
    int n = out / sizeof(char *);
    for (int i = 0; i < n && ptrs[i]; i++) {
        char buf[4096];
        mach_vm_size_t s = 0;
        kr = mach_vm_read_overwrite(task, (mach_vm_address_t)ptrs[i],
                                     sizeof(buf) - 1, (mach_vm_address_t)buf, &s);
        if (kr == KERN_SUCCESS && s > 0) {
            buf[s < sizeof(buf) ? s : sizeof(buf) - 1] = '\0';
            printf("    %s\n", buf);
        }
    }
}

static void clear_brk_and_reply(mach_port_t thread, mach_msg_header_t *msg) {
    arm_debug_state64_t ds;
    mach_msg_type_number_t dsc = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)&ds, &dsc);
    if (kr == KERN_SUCCESS) {
        for (int i = 0; i <= g_ntarg; i++) ds.__bcr[i] = HW_BRK_DIS;
        thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, dsc);
    }
    send_reply(msg, KERN_SUCCESS);
}

int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    pid_t launchd_pid = 1;
    kern_return_t kr = task_for_pid(mach_task_self(), launchd_pid, &g_task);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "task_for_pid(1): %s\n", mach_error_string(kr)); return 1; }
    printf("[+] attached to launchd (pid %d)\n", launchd_pid);

    void *ps_targ = dlsym(RTLD_DEFAULT, "__posix_spawn");
#if __has_feature(ptrauth_calls)
    ps_targ = ptrauth_strip(ps_targ, ptrauth_key_function_pointer);
#endif
    add_targ(ps_targ, 1, "posix_spawn");
    if (g_ntarg == 0) { fprintf(stderr, "no targets\n"); return 1; }

    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port);
    mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND);

    kr = task_set_exception_ports(g_task,
        EXC_MASK_BREAKPOINT, g_exc_port,
        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "set_exception_ports: %s\n", mach_error_string(kr)); return 1; }

    init_ds_template();
    if (install_hw_breakpoints() < 0) {
        fprintf(stderr, "failed to install hw breakpoints\n");
        return 1;
    }

    printf("[+] listening...\n");
    fflush(stdout);

    g_opts = [PPOptionsLoader loadOptions];
    struct stat opts_st;
    g_opts_mtime = (stat("/opt/pluginplayground/current.options", &opts_st) == 0) ? opts_st.st_mtime : 0;
    printf("[+] options: disablePAC=%d legacyAmmonia=%d pauseInjection=%d\n",
           g_opts.disablePAC, g_opts.useLegacyAmmonia, g_opts.pauseInjection);
    amfi_setup(g_opts.useLegacyAmmonia);
    // Patch the amfid that is already running (the one that blessed us), if any — idempotent.
    if (g_amfi_ready) g_amfi_pending = godmfi_find_amfid();

    while (g_running) {
        union {
            exc_req_t req;
            uint8_t pad[512];
        } msg;

        // Cover launchd pool threads created since the last sweep. Under spawn load mach_msg
        // rarely times out, so the timeout-only re-install never runs and new threads miss their
        // breakpoint; sweep on a short timer regardless of load (install skips mid-step threads).
        static uint64_t aw_last_sweep_ns = 0;
        uint64_t aw_now_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
        if (aw_now_ns - aw_last_sweep_ns >= 15000000ULL) { install_hw_breakpoints(); aw_last_sweep_ns = aw_now_ns; }

        // Hot-reload watch (release handles for on-disk-changed trajectory dylibs), then drain a
        // pending amfid code-patch (one non-blocking attempt/tick; retries until readable).
        amfi_watch_reload();
        amfi_reload_amfid_if_pending();   // debounced amfid restart to adopt a changed dylib inode
        if (g_amfi_pending > 0 && amfi_try_patch(g_amfi_pending)) g_amfi_pending = 0;

        kr = mach_msg(&msg.req.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                      0, sizeof(msg), g_exc_port,
                      100, MACH_PORT_NULL);
        if (kr == MACH_RCV_TIMED_OUT) {
            install_hw_breakpoints();
            struct stat st;
            if (stat("/opt/pluginplayground/current.options", &st) == 0
                && st.st_mtime != g_opts_mtime) {
                g_opts = [PPOptionsLoader loadOptions];
                g_opts_mtime = st.st_mtime;
                printf("[+] options reloaded: disablePAC=%d legacyAmmonia=%d pauseInjection=%d\n",
                       g_opts.disablePAC, g_opts.useLegacyAmmonia, g_opts.pauseInjection);
                amfi_setup(g_opts.useLegacyAmmonia);
            }
            continue;
        }
        if (kr != KERN_SUCCESS) continue;

        mach_port_t thread = msg.req.thread.name;

        if (msg.req.exception == EXC_BREAKPOINT) {
            if (g_opts.pauseInjection) {
                clear_brk_and_reply(thread, &msg.req.head);
                continue;
            }
            arm_thread_state64_t state;
            mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
            if (thread_get_state(thread, ARM_THREAD_STATE64,
                                 (thread_state_t)&state, &sc) != KERN_SUCCESS) {
                clear_brk_and_reply(thread, &msg.req.head);
                continue;
            }
            // The state comes back with pc/lr/sp signed, and without the AMFI boot-arg the accessors
            // below fail authentication (SIGBUS, measured on macOS 27.0). That kills fangs, and
            // launchd then dies on the unhandled breakpoint. We only need the plain addresses.
            arm_thread_state64_ptrauth_strip(state);

            int exc_pid = 0;
            pid_for_task(msg.req.task.name, &exc_pid);
            if (exc_pid != 1) {
                task_t ctask = msg.req.task.name;

                uint64_t path_ptr = state.__x[1];
                char path[PATH_MAX];
                mach_vm_size_t psz = 0;
                kr = mach_vm_read_overwrite(ctask, path_ptr, PATH_MAX - 1,
                        (mach_vm_address_t)path, &psz);
                int path_ok = (kr == KERN_SUCCESS && psz > 0 && path[0] == '/');
                
                PPFangsLibraries *libs = nil;
                
                if (path_ok) {
                    path[psz < PATH_MAX ? psz : PATH_MAX - 1] = '\0';

                    // amfid can't be DYLD-injected (dyld strips DYLD_* from restricted binaries);
                    // schedule a code-patch of this spawning amfid instead. exc_pid IS the amfid pid
                    // (xpcproxy execs amfid in place). The loop patches it once its space is readable.
                    if (g_amfi_ready && strcmp(path, "/usr/libexec/amfid") == 0) {
                        g_amfi_pending = exc_pid;
                        printf("[amfi] amfid spawning pid=%d — scheduled for code-patch\n", exc_pid);
                        fflush(stdout);
                    }

                    libs = [PPOptionsLoader librariesForInsertionUsingAmmonia:g_opts.useLegacyAmmonia
                                                                    toExePath:path];
                    
                    if (![libs libs] || [[libs libs] count] < 1){
                        clear_brk_and_reply(thread, &msg.req.head);
                        continue;
                    }
                    
                    printf("[xpcproxy:%d] path=%s\n", exc_pid, path);
                    print_envp(ctask, state.__x[5]);
                }
                
                fflush(stdout);
                
                if (path_ok) {
                    if (g_opts.disablePAC) {
                        char *new_path = getready_process(path);
                        if (new_path) {
                            if (strcmp(new_path, path) != 0) {
                                size_t new_len = strlen(new_path) + 1;
                                kr = mach_vm_write(ctask, path_ptr,
                                                   (vm_offset_t)new_path,
                                                   (mach_msg_type_number_t)new_len);
                                if (kr == KERN_SUCCESS)
                                    printf("[xpcproxy:%d] -> %s\n", exc_pid, new_path);
                                else
                                    printf("[xpcproxy:%d] redirect write failed: %s\n",
                                           exc_pid, mach_error_string(kr));
                                fflush(stdout);
                            }
                            free(new_path);
                        }
                    }
                    uint64_t envp_addr = state.__x[5];
                    char *env_ptrs[512];
                    mach_vm_size_t env_out = 0;
                    kr = mach_vm_read_overwrite(ctask, envp_addr,
                            sizeof(env_ptrs), (mach_vm_address_t)env_ptrs, &env_out);
                    if (kr == KERN_SUCCESS) {
                        int count = 0;
                        int max = env_out / sizeof(char *);
                        for (int i = 0; i < max && env_ptrs[i]; i++) count++;
                        
                        if (libs) {
                            NSString *libsSingle = [libs libsForDYLD];
                            libsSingle = [NSString stringWithFormat:@"DYLD_INSERT_LIBRARIES=%@", libsSingle];
                            const char *inject = [libsSingle UTF8String];
                            int found = 0;
                            for (int i = 0; i < count && !found; i++) {
                                char buf[512];
                                mach_vm_size_t bs = 0;
                                kern_return_t r = mach_vm_read_overwrite(ctask,
                                        (mach_vm_address_t)env_ptrs[i], sizeof(buf) - 1,
                                        (mach_vm_address_t)buf, &bs);
                                if (r == KERN_SUCCESS && bs > 0) {
                                    buf[bs < sizeof(buf) ? bs : sizeof(buf) - 1] = '\0';
                                    if (strncmp(buf, "DYLD_INSERT_LIBRARIES=", 22) == 0)
                                        found = 1;
                                }
                            }
                            if (!found && count > 0) {
                            size_t inject_len = strlen(inject) + 1;
                            mach_vm_address_t stack_dest =
                                (arm_thread_state64_get_sp(state) - 4096) & ~(mach_vm_address_t)0xF;
                            kr = mach_vm_write(ctask, stack_dest,
                                    (vm_offset_t)inject,
                                    (mach_msg_type_number_t)inject_len);
                            if (kr == KERN_SUCCESS) {
                                uint64_t null_term_addr = envp_addr +
                                    (uint64_t)count * sizeof(char *);
                                unsigned char auxv_buf[4096];
                                mach_vm_size_t auxv_sz = 0;
                                kr = mach_vm_read_overwrite(ctask,
                                        null_term_addr + 8, sizeof(auxv_buf),
                                        (mach_vm_address_t)auxv_buf, &auxv_sz);
                                if (kr == KERN_SUCCESS) {
                                    int auxv_len = 0;
                                    int auxv_max = auxv_sz / 16;
                                    for (int i = 0; i < auxv_max; i++) {
                                        int key = *(int *)(auxv_buf + i * 16);
                                        if (key == 0) { auxv_len = (i + 1) * 16; break; }
                                    }
                                    if (auxv_len > 0) {
                                        mach_vm_write(ctask,
                                                null_term_addr + 8 + 16,
                                                (vm_offset_t)auxv_buf,
                                                (mach_msg_type_number_t)auxv_len);
                                    }
                                }
                                uint64_t new_ptr = stack_dest;
                                uint64_t new_entries[2] = { new_ptr, 0 };
                                kr = mach_vm_write(ctask, null_term_addr,
                                        (vm_offset_t)new_entries, 16);
                                if (kr == KERN_SUCCESS)
                                    printf("[xpcproxy:%d] envp +DYLD_INSERT_LIBRARIES\n",
                                           exc_pid);
                                else
                                    printf("[xpcproxy:%d] envp write failed: %s\n",
                                exc_pid, mach_error_string(kr));
                            } else {
                                printf("[xpcproxy:%d] envp string write failed: %s\n",
                                        exc_pid, mach_error_string(kr));
                            }
                        }
                    }
                }
            }
            arm_debug_state64_t cds;
                mach_msg_type_number_t cdsc = ARM_DEBUG_STATE64_COUNT;
                int brk_disabled = 0;
                if (thread_get_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&cds, &cdsc) == KERN_SUCCESS) {
                    for (int i = 0; i <= g_ntarg; i++) cds.__bcr[i] = HW_BRK_DIS;
                    kern_return_t dkr = thread_set_state(thread, ARM_DEBUG_STATE64,
                                          (thread_state_t)&cds, cdsc);
                    if (dkr == KERN_SUCCESS) {
                        brk_disabled = 1;
                    } else {
                        printf("[xpcproxy:%d] brk disable failed: %s\n",
                               exc_pid, mach_error_string(dkr));
                    }
                }
                send_reply(&msg.req.head, brk_disabled ? KERN_SUCCESS : KERN_FAILURE);
                continue;
            }

            int cur = -1;
            for (int i = 0; i < g_ntarg; i++) {
                if (arm_thread_state64_get_pc(state) == g_targs[i].addr) { cur = i; break; }
            }
            if (cur < 0) {
                int si = find_step(thread);
                if (si >= 0 && arm_thread_state64_get_pc(state) == g_steps[si].ret_addr) {
                    if (state.__x[0] == 0) {
                        pid_t spawned;
                        mach_vm_size_t s = 0;
                        kr = mach_vm_read_overwrite(g_task,
                                g_steps[si].child_pid_addr,
                                sizeof(spawned),
                                (mach_vm_address_t)&spawned, &s);
                        if (kr == KERN_SUCCESS) {
                            printf("xpcproxy found! (pid=%d)\n", spawned);
                            task_t child;
                            kr = task_for_pid(mach_task_self(),
                                    spawned, &child);
                            if (kr == KERN_SUCCESS) {
                                task_set_exception_ports(child,
                                        EXC_MASK_BREAKPOINT,
                                        g_exc_port,
                                        EXCEPTION_DEFAULT
                                        | MACH_EXCEPTION_CODES,
                                        ARM_THREAD_STATE64);
                                install_hw_breakpoints_in(child);
                                mach_port_deallocate(mach_task_self(),
                                                     child);
                            }
                            fflush(stdout);
                        }
                    }
                    fflush(stdout);

                    arm_debug_state64_t ds;
                    mach_msg_type_number_t dsc = ARM_DEBUG_STATE64_COUNT;
                    thread_get_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&ds, &dsc);
                    ds.__bvr[g_steps[si].brk_idx] = 0;
                    ds.__bcr[g_steps[si].brk_idx] = HW_BRK_DIS;
                    ds.__bcr[g_steps[si].entry_idx] = HW_BRK_EN;
                    thread_set_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&ds, dsc);
                    remove_step(si);
                }
                send_reply(&msg.req.head, KERN_SUCCESS);
                continue;
            }

            uint64_t path_ptr = state.__x[g_targs[cur].path_reg];
            char path[PATH_MAX];
            mach_vm_size_t out = 0;
            kr = mach_vm_read_overwrite(g_task, path_ptr, PATH_MAX - 1,
                    (mach_vm_address_t)path, &out);
            if (kr == KERN_SUCCESS) {
                path[out < PATH_MAX ? out : PATH_MAX - 1] = '\0';
                if (strcmp(path, "/usr/libexec/xpcproxy") != 0) {
                    arm_debug_state64_t ds;
                    mach_msg_type_number_t dsc = ARM_DEBUG_STATE64_COUNT;
                    thread_get_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&ds, &dsc);
                    ds.__bcr[cur] = HW_BRK_DIS;
                    thread_set_state(thread, ARM_DEBUG_STATE64,
                                     (thread_state_t)&ds, dsc);
                    fflush(stdout);
                    send_reply(&msg.req.head, KERN_SUCCESS);
                    continue;
                }
            }

            uint64_t child_ptr = state.__x[0];
            int ret_bk = g_ntarg;

            arm_debug_state64_t ds;
            mach_msg_type_number_t dsc = ARM_DEBUG_STATE64_COUNT;
            thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, &dsc);
            ds.__bcr[cur] = HW_BRK_DIS;
            ds.__bvr[ret_bk] = arm_thread_state64_get_lr(state);
            ds.__bcr[ret_bk] = HW_BRK_EN;
            thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&ds, dsc);

            int si = find_step(thread);
            if (si >= 0) remove_step(si);
            add_step(thread, ret_bk);
            si = g_nsteps - 1;
            g_steps[si].entry_idx = cur;
            g_steps[si].ret_addr = arm_thread_state64_get_lr(state);
            g_steps[si].child_pid_addr = child_ptr;

            fflush(stdout);

            kr = send_reply(&msg.req.head, KERN_SUCCESS);
            if (kr != MACH_MSG_SUCCESS)
                printf("[-] send_reply: %s\n", mach_error_string(kr));

        } else {
            send_reply(&msg.req.head, KERN_SUCCESS);
        }
    }

    printf("\n[+] cleaning up...\n");
    clear_hw_breakpoints();
    reset_exception_ports();
    printf("[+] done\n");
    return 0;
}
