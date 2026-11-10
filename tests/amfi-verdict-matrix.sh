#!/bin/sh
#
# amfi-verdict-matrix.sh — probe which binaries the godmfi-patched amfid will let run.
#
# It rebuilds a tiny probe program (no payload — it just prints and exits), signs it several
# different ways, runs it, and records whether the kernel/amfid ALLOWED it to execute or DENIED
# it (killed at launch). Each probe is recompiled with a unique NONCE every time, so it has a
# never-before-seen cdhash: that defeats the kernel's per-cdhash code-signing cache and forces a
# FRESH amfid validation on every run (re-signing the same bytes would reuse a cached verdict).
#
# The gate is triggered by *restricted* ("private") entitlements: any validly signed binary with
# no restricted entitlements runs regardless of signer, so those cases are ALLOW baselines. The
# meaningful cases are the ones that embed restricted entitlements — only a genuine god-signed
# binary gets them, because godmfi verifies the signature against the pinned god cert.
#
# Cases (expected results assume the godmfi daemon is RUNNING):
#   1  god key,            no entitlements        -> ALLOW  (valid signature; nothing to gate)
#   2  god key,            private entitlements   -> ALLOW  (godmfi validates + grants)  *** the point
#   3  ad-hoc,             no entitlements        -> ALLOW  (ad-hoc runs; nothing to gate)
#   4  ad-hoc,             private entitlements   -> DENY   (unauthorized restricted ents -> killed)
#   5  impostor key,       no entitlements        -> ALLOW  (valid self-signed; nothing to gate)
#   6  impostor key,       private entitlements   -> DENY   (cert != pin -> not god -> killed)
#   7  god-signed then code-tampered, priv ents   -> DENY   (god cert present but signature invalid)
#
# Cases 5/6 are "embedded a god-looking cert but signed with a DIFFERENT key" — the impostor cert
# shares the god CN yet is a different keypair, so its SHA-256 != the pin and godmfi rejects it at
# the identity check. Case 7 is the stricter one the previous session's fix added: the binary IS
# god-signed (its leaf cert hashes to the pin, so the identity check passes) but the code was
# modified afterwards, so SecStaticCodeCheckValidity fails — possession/integrity, not mere cert
# presence, is the gate. Pre-fix godmfi would have WRONGLY allowed case 7.
#
# Run with sudo (god-signing unlocks the root keychain); it re-execs itself if needed.
# Usage:  sudo tests/amfi-verdict-matrix.sh [case-number ...]      (default: all)
#
set -u

if [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi

OPENSSL="/usr/bin/openssl"                                  # macOS LibreSSL (p12 imports cleanly)
SETUP="/opt/pluginplayground/tools/godmfi-setup.sh"        # installed god identity tool
[ -x "$SETUP" ] || SETUP="$(cd "$(dirname "$0")/.." && pwd)/tools/godmfi-setup.sh"
IMP_CN="AwareMeta God"                                      # same CN as the real identity, diff key

WORK="$(mktemp -d /tmp/godmfi-amfi.XXXXXX)"
IMP_KC="$WORK/impostor.keychain-db"
cleanup() { security delete-keychain "$IMP_KC" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# ---- environment ----------------------------------------------------------------------------
daemon="STOPPED"; pgrep -x fangs >/dev/null 2>&1 && daemon="RUNNING"
god_ok="no"; [ -x "$SETUP" ] && "$SETUP" status 2>/dev/null | grep -qi "present" && god_ok="yes"

echo "godmfi daemon : $daemon"
echo "god identity  : $god_ok   ($SETUP)"
[ "$daemon" = "RUNNING" ] || echo "NOTE: fangs is not running — amfid is unpatched, so every 'private-ents' case will DENY."
echo "legend        : ALLOW = probe executed and printed; DENY = killed by amfid/kernel at launch"
echo "---------------------------------------------------------------------------------------------"

# ---- embedded probe C (written once; recompiled per case with a fresh NONCE) -----------------
cat > "$WORK/probe.c" <<'CEOF'
#include <stdio.h>
#include <unistd.h>
/* _nonce is baked from -DNONCE and kept (used+volatile) so every build differs -> unique cdhash
   -> amfid re-validates instead of returning a cached verdict. */
__attribute__((used)) static volatile unsigned long _nonce = NONCE;
int main(void) {
    printf("RAN label=%s pid=%d uid=%d nonce=%lu\n", LABEL, (int)getpid(), (int)getuid(), _nonce);
    return 0;
}
CEOF

# ---- embedded restricted ("private") entitlements --------------------------------------------
cat > "$WORK/ents.plist" <<'PEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>platform-application</key><true/>
    <key>task_for_pid-allow</key><true/>
    <key>com.apple.system-task-ports</key><true/>
    <key>com.apple.private.thread-set-state</key><true/>
</dict>
</plist>
PEOF
ENTS="$WORK/ents.plist"

# ---- impostor identity (same CN as god, different key; created lazily) -----------------------
imp_ready=0
ensure_impostor() {
    [ "$imp_ready" -eq 1 ] && return 0
    "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$WORK/imp.key" 2>/dev/null
    cat > "$WORK/imp.ext" <<EXT
[ v3 ]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
subjectKeyIdentifier=hash
EXT
    "$OPENSSL" req  -new -key "$WORK/imp.key" -subj "/CN=$IMP_CN" -out "$WORK/imp.csr" 2>/dev/null
    "$OPENSSL" x509 -req -in "$WORK/imp.csr" -signkey "$WORK/imp.key" -days 3650 \
        -extfile "$WORK/imp.ext" -extensions v3 -out "$WORK/imp.crt" 2>/dev/null
    "$OPENSSL" pkcs12 -export -inkey "$WORK/imp.key" -in "$WORK/imp.crt" \
        -name "$IMP_CN" -passout pass:impostor -out "$WORK/imp.p12" 2>/dev/null
    security create-keychain -p impostor "$IMP_KC" >/dev/null 2>&1
    security unlock-keychain  -p impostor "$IMP_KC" >/dev/null 2>&1
    security import "$WORK/imp.p12" -k "$IMP_KC" -P impostor -T /usr/bin/codesign >/dev/null 2>&1
    security set-key-partition-list -S apple-tool:,apple: -s -k impostor "$IMP_KC" >/dev/null 2>&1 || true
    imp_ready=1
}

# ---- signing helpers (each takes <binary> [entitlements-plist]) -------------------------------
sign_god()      { b="$1"; e="${2:-}"; if [ -n "$e" ]; then "$SETUP" sign "$b" "$e" >/dev/null 2>&1; else "$SETUP" sign "$b" >/dev/null 2>&1; fi; }
sign_adhoc()    { b="$1"; e="${2:-}"; codesign -f -s - --generate-entitlement-der ${e:+--entitlements "$e"} "$b" >/dev/null 2>&1; }
sign_impostor() { ensure_impostor; b="$1"; e="${2:-}"; codesign -f -s "$IMP_CN" --keychain "$IMP_KC" --timestamp=none --generate-entitlement-der ${e:+--entitlements "$e"} "$b" >/dev/null 2>&1; }

# Flip one byte inside __TEXT,__text so the cdhash no longer matches the (still-god) signature.
tamper() {
    b="$1"
    toff="$(otool -l "$b" 2>/dev/null | awk '/sectname __text/{t=1} t&&$1=="offset"{print $2; exit}')"
    [ -n "$toff" ] || toff=600
    off=$((toff + 16))
    orig="$(xxd -p -s "$off" -l 1 "$b" 2>/dev/null)"; [ -n "$orig" ] || return 0
    new="$(printf '%02x' $(( 0x$orig ^ 0x5a )))"
    printf "$(printf '\\x%s' "$new")" | dd of="$b" bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
}

# ---- build + run one case --------------------------------------------------------------------
pass=0; fail=0; skipped=0
build() {
    label="$1"
    nonce="$(date +%s)$(jot -r 1 100000 999999 2>/dev/null || echo "$RANDOM$RANDOM")"
    bin="$WORK/probe_${nonce}"
    cc -O0 -o "$bin" -DLABEL="\"$label\"" -DNONCE="${nonce}UL" "$WORK/probe.c" 2>/dev/null || return 1
    echo "$bin"
}

run_case() {  # <num> <label> <god|adhoc|impostor|tamper> <ents-or-empty> <expected>
    num="$1"; label="$2"; method="$3"; ents="$4"; expected="$5"

    case "$method" in god|tamper) [ "$god_ok" = "yes" ] || {
        printf "%-2s  %-30s  expect:%-5s  got:%-5s  %s\n" "$num" "$label" "$expected" "-" "SKIP (no god identity)"
        skipped=$((skipped+1)); return; };; esac

    bin="$(build "$label")" || { printf "%-2s  %-30s  BUILD FAILED\n" "$num" "$label"; fail=$((fail+1)); return; }
    case "$method" in
        god)      sign_god      "$bin" "$ents" ;;
        adhoc)    sign_adhoc    "$bin" "$ents" ;;
        impostor) sign_impostor "$bin" "$ents" ;;
        tamper)   sign_god      "$bin" "$ents"; tamper "$bin" ;;
    esac

    out="$("$bin" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "RAN"; then actual="ALLOW"; else actual="DENY"; fi
    if [ "$actual" = "$expected" ]; then verdict="PASS"; pass=$((pass+1)); else verdict="FAIL"; fail=$((fail+1)); fi
    printf "%-2s  %-30s  expect:%-5s  got:%-5s  %s\n" "$num" "$label" "$expected" "$actual" "$verdict"
}

# Case 2 is the only expectation that depends on the daemon being live.
E2="ALLOW"; [ "$daemon" = "RUNNING" ] || E2="DENY"

want="${*:-1 2 3 4 5 6 7}"
for n in $want; do
    case "$n" in
        1) run_case 1 "god / no-ents"                  god      ""      ALLOW ;;
        2) run_case 2 "god / private-ents"             god      "$ENTS" "$E2" ;;
        3) run_case 3 "ad-hoc / no-ents"               adhoc    ""      ALLOW ;;
        4) run_case 4 "ad-hoc / private-ents"          adhoc    "$ENTS" DENY  ;;
        5) run_case 5 "impostor-key / no-ents"         impostor ""      ALLOW ;;
        6) run_case 6 "impostor-key / private-ents"    impostor "$ENTS" DENY  ;;
        7) run_case 7 "god-signed+tampered / ents"     tamper   "$ENTS" DENY  ;;
        *) echo "unknown case: $n" ;;
    esac
done

echo "---------------------------------------------------------------------------------------------"
echo "pass=$pass fail=$fail skipped=$skipped"
[ "$fail" -eq 0 ]
