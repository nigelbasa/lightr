#!/usr/bin/env bash
# Build the .deb.
#
# The package ships its own virtualenv under /opt rather than relying
# on system site-packages: a mail engine that stops working because an
# unrelated `pip install` changed a shared dependency is not something
# an operator can debug at 3am.
#
# **Build it on the distribution you will install it on.** The venv
# carries compiled wheels and a site-packages directory named for the
# interpreter's minor version, so a package built on Debian 12 (3.11)
# does not work on a host running 3.12.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/dist/deb-root"
INSTALLED_AT=/opt/lightr/venv

# Which interpreter the bundled venv is built against, and therefore
# which one the package depends on. Ubuntu 22.04's python3 is 3.10, so
# there it has to be python3.12 from deadsnakes -- and the package must
# then depend on python3.12, not on python3.
PYTHON="${LIGHTR_PYTHON:-python3}"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$($PYTHON -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
fi

if ! command -v nfpm >/dev/null; then
  echo "nfpm is not installed: https://nfpm.goreleaser.com/install/" >&2
  exit 1
fi

# The package declares an interpreter dependency. Building with an
# older one produces a package apt will refuse to install, which is a
# confusing way to find out.
if ! command -v "$PYTHON" >/dev/null; then
  echo "$PYTHON is not installed. Set LIGHTR_PYTHON to the interpreter to bundle." >&2
  exit 1
fi

"$PYTHON" - <<'GUARD'
import sys
if sys.version_info[:2] < (3, 11):
    sys.exit(
        f"this interpreter is {sys.version_info.major}.{sys.version_info.minor}; "
        "Lightr needs 3.11+. On Ubuntu 22.04: add ppa:deadsnakes/ppa, install "
        "python3.12-venv, and build with LIGHTR_PYTHON=python3.12."
    )
GUARD

# Depend on the interpreter that was actually used, by its package
# name: python3.12 on a host where python3 is 3.10, plain python3 where
# the system one is already new enough.
PYTHON_VERSION="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
SYSTEM_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo none)"
if [ "$PYTHON_VERSION" = "$SYSTEM_VERSION" ]; then
  PYTHON_DEPENDS="python3 (>= $PYTHON_VERSION)"
else
  PYTHON_DEPENDS="python$PYTHON_VERSION"
fi
export PYTHON_DEPENDS
echo "Bundling $PYTHON ($PYTHON_VERSION); the package will depend on: $PYTHON_DEPENDS"

rm -rf "$STAGE" "$ROOT/dist/lightr"
mkdir -p "$STAGE/opt/lightr" "$ROOT/dist"

"$PYTHON" -m venv "$STAGE/opt/lightr/venv"
"$STAGE/opt/lightr/venv/bin/pip" install --quiet --upgrade pip
"$STAGE/opt/lightr/venv/bin/pip" install --quiet "$ROOT[sqlite,postgres,imap,ldap]"

# venv writes an absolute shebang, and the path it was built at is not
# the path it will be installed at -- so every console script in here
# points into a staging directory that will not exist on the target.
# Nothing catches this until the package is installed and `lightr`
# reports "no such file or directory".
for script in "$STAGE/opt/lightr/venv/bin/"*; do
  [ -f "$script" ] || continue
  head -c2 "$script" 2>/dev/null | grep -q '#!' || continue
  sed -i "1s|^#!.*python.*|#!$INSTALLED_AT/bin/python3|" "$script"
done
sed -i "s|^home = .*|home = $(dirname "$(command -v "$PYTHON")")|" \n  "$STAGE/opt/lightr/venv/pyvenv.cfg"

# A launcher on PATH that uses the bundled interpreter.
cat > "$ROOT/dist/lightr" <<'LAUNCHER'
#!/bin/sh
exec /opt/lightr/venv/bin/lightr "$@"
LAUNCHER
chmod +x "$ROOT/dist/lightr"

VERSION="$VERSION" PYTHON_DEPENDS="$PYTHON_DEPENDS" nfpm package \
  --config "$ROOT/nfpm.yaml" \
  --packager deb \
  --target "$ROOT/dist/"

PACKAGE="$(ls -1t "$ROOT"/dist/*.deb | head -1)"
echo "Built: $PACKAGE"

# Check the thing that was built, not the thing that was intended.
# Every maintainer script runs as root on somebody else's server.
for script in "$ROOT"/packaging/debian/*; do
  sh -n "$script" || { echo "$script does not parse" >&2; exit 1; }
done

echo
echo "Contents:"
dpkg-deb --contents "$PACKAGE" | awk '{print $1, $6}' | grep -v '/opt/lightr/venv/' | head -40
echo "  ... and $(dpkg-deb --contents "$PACKAGE" | grep -c '/opt/lightr/venv/') files in the bundled venv"

echo
dpkg-deb --info "$PACKAGE" | sed -n '/Depends/,/Description/p'

# A shebang still pointing at the staging directory would break every
# command in the package.
if dpkg-deb --fsys-tarfile "$PACKAGE" | tar -xO ./opt/lightr/venv/bin/lightr 2>/dev/null \
   | head -1 | grep -q "$STAGE"; then
  echo "the bundled scripts still point at the build directory" >&2
  exit 1
fi

echo
echo "Install with:  apt install $PACKAGE"
