#!/usr/bin/env bash
#
# Cross-compile nhcx-gateway.
#
#   ./scripts/build.sh                  # every default target, packaged into ./dist
#   ./scripts/build.sh linux/amd64      # one target
#   MODE=compile ./scripts/build.sh     # binaries only, no archives
#   VERSION=v1.2.3 ./scripts/build.sh   # stamp an explicit version
#
# Pure Go with CGO off, so every target builds from any host.

set -euo pipefail
cd "$(dirname "$0")/.."

DEFAULT_TARGETS=(
  linux/amd64 linux/arm64 linux/arm linux/386
  darwin/amd64 darwin/arm64
  windows/amd64 windows/arm64 windows/386
  freebsd/amd64 freebsd/arm64
)

if [ "$#" -gt 0 ]; then
  read -r -a TARGET_LIST <<<"$*"
elif [ -n "${TARGETS:-}" ]; then
  read -r -a TARGET_LIST <<<"${TARGETS}"
else
  TARGET_LIST=("${DEFAULT_TARGETS[@]}")
fi

MODE="${MODE:-release}"
DIST="${DIST:-dist}"
NAME="nhcx-gateway"

if [ -z "${VERSION:-}" ]; then
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
fi
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}"

echo "${NAME} ${VERSION} (${COMMIT}) — ${MODE} build of ${#TARGET_LIST[@]} target(s)"
mkdir -p "$DIST"

for target in "${TARGET_LIST[@]}"; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  bin="$NAME"
  [ "$goos" = "windows" ] && bin="$NAME.exe"
  stage="$DIST/${NAME}_${VERSION}_${goos}_${goarch}"
  rm -rf "$stage"
  mkdir -p "$stage"

  echo "  → $target"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$stage/$bin" .

  if [ "$MODE" = "compile" ]; then
    continue
  fi
  cp README.md config.sample.json "$stage/"
  # Launcher scripts: serve / serve-hidden / stop / update for the platform.
  if [ "$goos" = "windows" ]; then
    cp scripts/pkg/windows/*.bat "$stage/"
  else
    cp scripts/pkg/unix/*.sh "$stage/"
    chmod +x "$stage"/*.sh
  fi
  (
    cd "$DIST"
    base="$(basename "$stage")"
    if [ "$goos" = "windows" ]; then
      rm -f "$base.zip"
      if command -v zip >/dev/null 2>&1; then
        zip -qr "$base.zip" "$base"
      else
        python3 -c "import shutil,sys; shutil.make_archive(sys.argv[1], 'zip', '.', sys.argv[1])" "$base"
      fi
    else
      tar -czf "$base.tar.gz" "$base"
    fi
    rm -rf "$base"
  )
done

if [ "$MODE" = "release" ]; then
  (cd "$DIST" && shasum -a 256 -- *.tar.gz *.zip 2>/dev/null > SHA256SUMS || true)
  echo "packaged into ./$DIST"
fi
