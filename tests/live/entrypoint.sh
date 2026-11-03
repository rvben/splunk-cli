#!/bin/sh
set -eu
# This disposable HOME owns the keyring. No host credentials are mounted.
export HOME=/tmp/live-home
export XDG_RUNTIME_DIR=/tmp/live-runtime
umask 077
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
exec dbus-run-session -- sh -ec '
    printf "%s" "disposable-test-keyring" | gnome-keyring-daemon --unlock --components=secrets >/dev/null
    exec python3 /test/check.py
'
