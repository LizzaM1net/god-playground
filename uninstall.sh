#!/bin/sh
set -u

echo "[-] Uninstalling Plugin Playground..."

if [ "$(id -u)" -ne 0 ]; then
    echo "Elevating privileges to uninstall system-wide files..."
    exec sudo "$0" "$@"
fi

PLIST="/Library/LaunchDaemons/com.pluginplayground.godmfi.plist"
OLD_GRANT_PLIST="/Library/LaunchDaemons/com.pluginplayground.grant.plist"
AMFI="system/com.apple.MobileFileIntegrity"

# 1. Stop the daemon (godmfi-launch + fangs) and clear KeepAlive so they are not relaunched.
echo "Stopping godmfi daemon..."
for p in "$PLIST" "$OLD_GRANT_PLIST"; do
    [ -f "$p" ] || continue
    launchctl bootout system "$p" 2>/dev/null || launchctl unload -w "$p" 2>/dev/null || true
done
launchctl bootout system/com.pluginplayground.godmfi 2>/dev/null || true
launchctl bootout system/com.pluginplayground.grant  2>/dev/null || true

# 2. Gracefully stop any stray fangs (SIGTERM only — it detaches cleanly; never SIGKILL fangs).
if pgrep -x fangs >/dev/null 2>&1; then
    echo "Stopping fangs..."
    pkill -TERM -x fangs 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        pgrep -x fangs >/dev/null 2>&1 || break
        sleep 1
    done
fi

# 3. Restart amfid so it drops the code-patch and reverts to stock verdicts.
echo "Restarting amfid to a clean state..."
launchctl kickstart -k "$AMFI" >/dev/null 2>&1 || true

# 4. Remove the daemon plist, the toolkit (binaries, tweaks, tools, god identity/pin/keychain),
#    the configurator app, logs, and the package receipt.
echo "Removing files..."
rm -f "$PLIST" "$OLD_GRANT_PLIST"
rm -f "/usr/local/bin/godmfi"
rm -rf "/opt/pluginplayground"
rm -rf "/Applications/Plugin Playground.app"
rm -rf "/var/log/pluginplayground"

echo "Forgetting package receipt..."
pkgutil --forget "com.pluginplayground.core" > /dev/null 2>&1 || true

echo "[-] Uninstallation complete."
