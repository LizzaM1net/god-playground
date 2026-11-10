#!/bin/bash
#
# godmfi-setup — generate (once) and store the god code-signing identity in a ROOT-ONLY system
# keychain, write the runtime pin, and god-sign binaries with it. Run with sudo.
#
# Threat model: on a SIP-off machine root is already all-powerful (it can patch amfid directly,
# load a kext, set the boot-arg, replace godmfi). So this does NOT defend the key from root — it
# keeps the PRIVATE key out of reach of NON-root users: the keychain + its password file are
# root:wheel 0600. The pin (cert SHA-256) is public and world-readable. The private key is the
# capability to mint god-signed binaries; that is what must stay root-only.
#
# Usage:
#   sudo tools/godmfi-setup.sh init                 # generate-once identity + write pin (idempotent)
#   sudo tools/godmfi-setup.sh sign <path> [ents]   # god-sign a binary or .app bundle
#   sudo tools/godmfi-setup.sh pin                  # print the pinned cert SHA-256
#   sudo tools/godmfi-setup.sh status               # show identity + pin state
#
set -euo pipefail

# Use the macOS-bundled LibreSSL, NOT whatever openssl is first in $PATH. Under sudo the PATH may
# resolve `openssl` to Homebrew's OpenSSL 3.x/4.x, whose PKCS#12 MAC (SHA-256) `security import`
# can't read ("MAC verification failed during PKCS12 import"). LibreSSL's p12 imports fine.
OPENSSL="${OPENSSL:-/usr/bin/openssl}"
[ -x "$OPENSSL" ] || OPENSSL="$(command -v openssl)"

CN="AwareMeta God"
# Everything godmfi-specific lives in ONE root-only dir under /opt/pluginplayground: the keychain
# (private key), its password, the public cert and the runtime pin. The dylib itself is NOT here —
# it lives in the tweaks dir fangs scans (/opt/pluginplayground/tweaks). This dir must stay
# root:wheel (not user-writable): whoever can rewrite pin.plist redefines the god cert.
SUPPORT="/opt/pluginplayground/godmfi"
KEYCHAIN="$SUPPORT/godmfi.keychain-db"
PINFILE="$SUPPORT/pin.plist"
PWFILE="$SUPPORT/keychain.pass"      # random keychain password, root-only (0600)
CRTFILE="$SUPPORT/god.crt"           # public cert, for reference / pin recompute
DAYS="3650"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

ensure_support() {
    mkdir -p "$SUPPORT"
    chown root:wheel "$SUPPORT"; chmod 0755 "$SUPPORT"
}

# One-time random keychain password, stored root-only so signing can unlock non-interactively.
kc_password() {
    if [ ! -f "$PWFILE" ]; then
        ( umask 077; head -c 32 /dev/urandom | xxd -p -c 64 > "$PWFILE" )
        chown root:wheel "$PWFILE"; chmod 0600 "$PWFILE"
    fi
    cat "$PWFILE"
}

have_identity() {
    [ -f "$KEYCHAIN" ] && security find-certificate -c "$CN" "$KEYCHAIN" >/dev/null 2>&1
}

unlock_kc() {
    local pw; pw="$(cat "$PWFILE")"
    security unlock-keychain -p "$pw" "$KEYCHAIN"
    security set-keychain-settings "$KEYCHAIN"   # no auto-lock / no timeout
}

write_pin() {
    local sha
    sha="$(security find-certificate -c "$CN" -p "$KEYCHAIN" \
           | "$OPENSSL" x509 -noout -fingerprint -sha256 \
           | sed -E 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
    [ ${#sha} -eq 64 ] || { echo "failed to compute cert SHA-256"; exit 1; }
    cat > "$PINFILE" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>pin_mode</key><string>cert_sha256</string>
    <key>cert_sha256</key><string>${sha}</string>
    <!-- observe=true: never override, only log amfid's real verdict (learning/diagnostics) -->
    <key>observe</key><false/>
    <!-- debug=true: append a verbose trail to /tmp/godmfi.log (off for release) -->
    <key>debug</key><false/>
</dict>
</plist>
PL
    chown root:wheel "$PINFILE"; chmod 0644 "$PINFILE"
    echo "$sha"
}

cmd_init() {
    ensure_support
    local pw; pw="$(kc_password)"
    [ -f "$KEYCHAIN" ] || security create-keychain -p "$pw" "$KEYCHAIN"
    chown root:wheel "$KEYCHAIN" 2>/dev/null || true
    chmod 0600 "$KEYCHAIN" 2>/dev/null || true
    unlock_kc

    if have_identity; then
        echo "[=] god identity '$CN' already present in $KEYCHAIN — reusing (pin unchanged)"
    else
        echo "[+] generating god identity '$CN' (EC P-256, codeSigning)"
        local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
        "$OPENSSL" ecparam -name prime256v1 -genkey -noout -out "$tmp/god.key"
        cat > "$tmp/god.ext" <<EXT
[ v3 ]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
subjectKeyIdentifier=hash
EXT
        "$OPENSSL" req  -new -key "$tmp/god.key" -subj "/CN=$CN" -out "$tmp/god.csr"
        "$OPENSSL" x509 -req -in "$tmp/god.csr" -signkey "$tmp/god.key" -days "$DAYS" \
            -extfile "$tmp/god.ext" -extensions v3 -out "$tmp/god.crt"
        # macOS `security import` rejects an empty-password PKCS#12 (MAC verification fails), so
        # use a throwaway password — the p12 is shredded with the temp dir right after import.
        "$OPENSSL" pkcs12 -export -inkey "$tmp/god.key" -in "$tmp/god.crt" \
            -name "$CN" -passout pass:godmfi -out "$tmp/god.p12"
        # import key+cert; let codesign use the key without a UI prompt
        security import "$tmp/god.p12" -k "$KEYCHAIN" -P godmfi \
            -T /usr/bin/codesign -T /usr/bin/security >/dev/null
        security set-key-partition-list -S apple-tool:,apple: -s -k "$pw" "$KEYCHAIN" >/dev/null 2>&1 || true
        cp "$tmp/god.crt" "$CRTFILE"; chown root:wheel "$CRTFILE"; chmod 0644 "$CRTFILE"
        # the private key now lives only inside the root keychain — temp (incl. p12) is shredded
    fi

    local sha; sha="$(write_pin)"
    echo "[+] keychain : $KEYCHAIN (root:wheel 0600)"
    echo "[+] pin      : $PINFILE  -> $sha"
    echo "[+] done. Sign god binaries with:  sudo $0 sign <path> [entitlements.plist]"
}

cmd_import() {
    local p12="${1:?usage: godmfi-setup.sh import <god.p12> [p12-password]}"
    local p12pass="${2:-}"
    [ -f "$p12" ] || { echo "no such p12: $p12"; exit 1; }
    ensure_support
    local pw; pw="$(kc_password)"
    [ -f "$KEYCHAIN" ] || security create-keychain -p "$pw" "$KEYCHAIN"
    chown root:wheel "$KEYCHAIN" 2>/dev/null || true
    chmod 0600 "$KEYCHAIN" 2>/dev/null || true
    unlock_kc
    echo "[+] importing existing identity from $p12 (keeps its pin — no re-signing needed)"
    security import "$p12" -k "$KEYCHAIN" -P "$p12pass" \
        -T /usr/bin/codesign -T /usr/bin/security >/dev/null
    security set-key-partition-list -S apple-tool:,apple: -s -k "$pw" "$KEYCHAIN" >/dev/null 2>&1 || true
    security find-certificate -c "$CN" -p "$KEYCHAIN" > "$CRTFILE" 2>/dev/null || true
    chown root:wheel "$CRTFILE" 2>/dev/null || true; chmod 0644 "$CRTFILE" 2>/dev/null || true
    local sha; sha="$(write_pin)"
    echo "[+] keychain : $KEYCHAIN"
    echo "[+] pin      : $PINFILE  -> $sha"
}

cmd_sign() {
    local target="${1:?usage: godmfi-setup.sh sign <path> [entitlements.plist]}"
    local ents="${2:-}"
    have_identity || { echo "no god identity — run 'sudo $0 init' first"; exit 1; }
    unlock_kc
    local args=(--force --sign "$CN" --keychain "$KEYCHAIN" --timestamp=none --generate-entitlement-der)
    if [ -n "$ents" ]; then
        args+=(--entitlements "$ents")
    else
        # no plist given → keep the target's existing entitlements (don't strip its restricted ones)
        args+=(--preserve-metadata=entitlements)
    fi
    [ -d "$target" ] && args+=(--deep)
    echo "==> god-signing $target${ents:+ with $ents}"
    codesign "${args[@]}" "$target"
    codesign -dvvv "$target" 2>&1 | grep -iE "Authority=|CDHash=|flags=" || true
}

cmd_pin() {
    [ -f "$PINFILE" ] && /usr/libexec/PlistBuddy -c 'Print :cert_sha256' "$PINFILE" || { echo "no pin"; exit 1; }
}

cmd_status() {
    echo "keychain : $KEYCHAIN $( [ -f "$KEYCHAIN" ] && echo present || echo MISSING )"
    echo "identity : $( have_identity && echo "'$CN' present" || echo MISSING )"
    echo "pin file : $PINFILE $( [ -f "$PINFILE" ] && echo present || echo MISSING )"
    [ -f "$PINFILE" ] && echo "pin SHA  : $(cmd_pin)"
}

case "${1:-init}" in
    init)   cmd_init ;;
    import) shift; cmd_import "$@" ;;
    sign)   shift; cmd_sign "$@" ;;
    pin)    cmd_pin ;;
    status) cmd_status ;;
    *) echo "usage: $0 {init|import <p12> [pass]|sign <path> [ents]|pin|status}"; exit 2 ;;
esac
