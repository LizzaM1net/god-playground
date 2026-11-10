#!/bin/sh
set -eu

VERSION="1.1.3"
OUTPUT="${1:-PluginPlayground-${VERSION}.pkg}"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "[+] Building..."
mkdir -p "$SRC/.build"
cmake -S "$SRC" -B "$SRC/.build" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$SRC/.build"

echo "[+] Staging..."
STAGING="$(mktemp -d)"
trap "rm -rf '$STAGING'" EXIT

PKG_ROOT="$STAGING/root/opt/pluginplayground"
mkdir -p "$PKG_ROOT/bin" "$PKG_ROOT/tweaks" "$PKG_ROOT/tools"
mkdir -p "$STAGING/root/Applications"
mkdir -p "$STAGING/root/Library/LaunchDaemons"

cp "$SRC/.build/fangs"          "$PKG_ROOT/bin/"
cp "$SRC/.build/godmfi-launch"  "$PKG_ROOT/bin/"
cp -R "$SRC/.build/configurator.app" "$STAGING/root/Applications/Plugin Playground.app/"

# godmfi cert-pin tweak: the dylib fangs warms + patches amfid with, plus its trajectory options
cp "$SRC/.build/godmfi.dylib"          "$PKG_ROOT/tweaks/"
cp "$SRC/godmfi/godmfi.dylib.options"  "$PKG_ROOT/tweaks/"

# setup tool: the postinstall script runs this to generate the god identity/pin and god-sign fangs
cp "$SRC/tools/godmfi-setup.sh"        "$PKG_ROOT/tools/"

# LaunchDaemon: godmfi-launch -> fangs, RunAtLoad + KeepAlive (started by the postinstall script)
cp "$SRC/installer/com.pluginplayground.godmfi.plist" \
   "$STAGING/root/Library/LaunchDaemons/com.pluginplayground.godmfi.plist"

# Permissions: make the injected binaries/dylib non-writable as staged. Ownership is NOT chowned
# here — chowning to root needs root, and install.sh builds as a normal user. Instead pkgbuild
# records root:wheel via --ownership recommended (below), and the postinstall script re-asserts
# root:wheel + these modes as root at install time. A writable fangs would be root-at-boot and a
# writable godmfi.dylib would be code execution in amfid with no key.
chmod 755 "$PKG_ROOT/bin" "$PKG_ROOT/tweaks" "$PKG_ROOT/tools"
chmod 755 "$PKG_ROOT/bin/fangs" "$PKG_ROOT/bin/godmfi-launch" "$PKG_ROOT/tools/godmfi-setup.sh"
chmod 644 "$PKG_ROOT/tweaks/godmfi.dylib" "$PKG_ROOT/tweaks/godmfi.dylib.options"
chmod 644 "$STAGING/root/Library/LaunchDaemons/com.pluginplayground.godmfi.plist"

# pkg install scripts (preinstall tears down the old instance + restarts amfid; postinstall
# provisions the identity, god-signs fangs, and starts the daemon). Must be executable.
SCRIPTS="$STAGING/scripts"
mkdir -p "$SCRIPTS"
cp "$SRC/installer/scripts/preinstall"  "$SCRIPTS/preinstall"
cp "$SRC/installer/scripts/postinstall" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/preinstall" "$SCRIPTS/postinstall"

echo "[+] Building component package..."
pkgbuild --root "$STAGING/root" \
         --scripts "$SCRIPTS" \
         --ownership recommended \
         --identifier "com.pluginplayground.core" \
         --version "$VERSION" \
         --install-location "/" \
         "$STAGING/PluginPlaygroundCore.pkg" > /dev/null

echo "[+] Building distribution package..."
productbuild --distribution "$SRC/installer/Distribution.xml" \
             --package-path "$STAGING" \
             --resources "$SRC/installer" \
             "$SRC/$OUTPUT"

echo "[+] Created $OUTPUT"
echo "    Install: sudo installer -pkg \"$OUTPUT\" -target /"
open "$SRC/$OUTPUT"
