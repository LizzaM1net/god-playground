//
//  godmfi-launch <god-signed-binary> [args...]
//
//  Standalone: cert-pin the live amfid, then run a god-signed binary (the target is its own
//  validation trigger). The amfid code-patch itself lives in the shared godmfi_patch module,
//  which fangs also uses for persistent per-spawn patching.
//
//    0. resolve validateWithError:'s offset BEFORE pre-warm (pre-warm swizzles it locally)
//    1. pre-warm godmfi.dylib's vnode (dlopen here while amfid is free -> cs_blob cached, so
//       amfid's later dlopen of it via the stub won't re-enter)
//    2. find the live amfid (kickstart only if absent) + code-patch its validateWithError:
//    3. launch the target; its first validation triggers the stub -> dlopen godmfi -> override
//    4. wait on the target, holding the pre-warm handle, so this stays the target's live parent
//
//  This is also the godmfi LaunchDaemon front (com.pluginplayground.godmfi, KeepAlive): launchd
//  runs `godmfi-launch /opt/pluginplayground/bin/fangs` at boot. Because we wait on the child
//  instead of returning, launchd tracks THIS process for fangs's whole life; if we exited right
//  after spawning, KeepAlive would relaunch us and we would patch (idempotently) and spawn a
//  SECOND fangs. When the target exits we exit with its status and launchd relaunches us.
//
//  Run via sudo.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <spawn.h>
#include <errno.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include "godmfi_patch.h"

extern char **environ;

// Single source of truth: the SAME dylib fangs loads from its tweaks dir (not a second copy).
#define DYLIB "/opt/pluginplayground/tweaks/godmfi.dylib"
#define LOG(...) fprintf(stderr, "[godmfi-launch] " __VA_ARGS__)

int main(int argc, char **argv) {
    if (argc < 2) { LOG("usage: godmfi-launch <god-signed-binary> [args...]\n"); return 2; }

    // 0. resolve validateWithError:'s offset BEFORE pre-warm (pre-warm swizzles it locally)
    uint64_t off = 0; char img[1024];
    if (!godmfi_resolve_offset(&off, img, sizeof img)) return 1;

    // 1. pre-warm godmfi.dylib's vnode (hold the handle until amfid has loaded it)
    void *warm = dlopen(DYLIB, RTLD_NOW);
    LOG("pre-warm dlopen(%s) = %p\n", DYLIB, warm);
    if (!warm) LOG("WARN: %s\n", dlerror());

    pid_t pid = godmfi_find_amfid();
    if (pid < 0) { LOG("no amfid\n"); return 1; }
    LOG("amfid pid=%d\n", pid);

    // 2. acquire amfid's task + patch its validateWithError:. A freshly kickstarted / throttled
    //    amfid may have a task port before its address space is readable, or the pid may flap —
    //    retry, re-finding amfid if the task dies.
    task_t task = TASK_NULL; int patched = 0;
    for (int t = 0; t < 50; t++) {
        if (task == TASK_NULL && task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) task = TASK_NULL;
        if (task != TASK_NULL) {
            uint64_t imp = godmfi_amfid_imp(task, off, img);
            if (imp) {
                int r = godmfi_patch_task(task, imp, DYLIB);
                if (r == 1) LOG("amfid already code-patched — skipping\n");
                if (r >= 0) { patched = 1; break; }
            }
        }
        usleep(100000);
        if (task != TASK_NULL) { mach_port_deallocate(mach_task_self(), task); task = TASK_NULL; }
        pid_t np = godmfi_find_amfid(); if (np > 0) pid = np;
    }
    if (!patched) { LOG("could not resolve/patch amfid (throttled? kill -9 -> launchd throttle, use SIGTERM)\n"); return 1; }

    // 3. launch the target (its first validation triggers the stub -> dlopen -> override)
    pid_t sp;
    if (posix_spawn(&sp, argv[1], NULL, NULL, &argv[1], environ) != 0) { LOG("spawn %s failed\n", argv[1]); return 1; }
    LOG("launched %s (pid %d)\n", argv[1], sp);

    // 4. wait on the target. We stay alive as its parent for its whole life, which both keeps the
    //    pre-warm dlopen handle (`warm`) mapped — so the god dylib's signature stays kernel-cached
    //    and a patched amfid never cold-loads it — and makes us a well-behaved KeepAlive daemon
    //    front (see the header): one godmfi-launch, one fangs. Exit with the target's status.
    int wst = 0;
    while (waitpid(sp, &wst, 0) < 0 && errno == EINTR) { /* retry */ }
    (void)warm;   // held until here on purpose
    int rc = WIFEXITED(wst) ? WEXITSTATUS(wst) : 1;
    LOG("target %d exited (status %d) — releasing.\n", sp, rc);
    return rc;
}
