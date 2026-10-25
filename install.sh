#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$root/runtime/python/bin/python3" ]; then
    unset PYTHONHOME PYTHONPATH
    exec "$root/runtime/python/bin/python3" -I -B "$root/installer.py" "$@"
fi
exec python3 "$root/packaging/bootstrap.py" "$@"
