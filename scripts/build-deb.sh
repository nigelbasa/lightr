#!/usr/bin/env bash
# Build the .deb.
#
# The package ships its own virtualenv under /opt rather than relying
# on system site-packages: a mail engine that stops working because an
# unrelated `pip install` changed a shared dependency is not something
# an operator can debug at 3am.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/dist/deb-root"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(python3 -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
fi

if ! command -v nfpm >/dev/null; then
  echo "nfpm is not installed: https://nfpm.goreleaser.com/install/" >&2
  exit 1
fi

rm -rf "$STAGE" "$ROOT/dist/lightr"
mkdir -p "$STAGE/opt/lightr" "$ROOT/dist"

python3 -m venv "$STAGE/opt/lightr/venv"
"$STAGE/opt/lightr/venv/bin/pip" install --quiet --upgrade pip
"$STAGE/opt/lightr/venv/bin/pip" install --quiet "$ROOT[sqlite,postgres,imap,ldap]"

# A launcher on PATH that uses the bundled interpreter.
cat > "$ROOT/dist/lightr" <<'LAUNCHER'
#!/bin/sh
exec /opt/lightr/venv/bin/lightr "$@"
LAUNCHER
chmod +x "$ROOT/dist/lightr"

VERSION="$VERSION" nfpm package \
  --config "$ROOT/nfpm.yaml" \
  --packager deb \
  --target "$ROOT/dist/"

echo "Built: $(ls -1 "$ROOT"/dist/*.deb)"
