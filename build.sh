#!/usr/bin/env bash
# Cross-compiles aiexpose for every supported target from a single machine.
#
# Two build choices here exist because of endpoint protection, not because of
# size or speed:
#
#   * The default build embeds no detection rules. See --offline below.
#
#   * Symbols are NOT stripped. A stripped Go binary has the shape antivirus
#     heuristics associate with packed malware, and this tool already looks
#     suspicious enough by what it does. The extra 4 MB buys a binary anyone
#     can inspect, which is the right trade for a security tool.
#
#   * -trimpath makes the build reproducible. Building the same source with the
#     same Go version on any machine produces byte-identical output, so a user
#     whose antivirus quarantined a download can rebuild and confirm the hash
#     rather than take our word for it. `./build.sh --check-reproducible`
#     proves it.
set -euo pipefail

VERSION="${VERSION:-0.19.5}"
OUT="${OUT:-dist}"
TAGS="${TAGS:-}"
# The offline binaries carry a distinct filename. They differ from the default
# build byte for byte, so sharing a name would make --verify ambiguous and let
# someone publish one checksum for two different executables.
SUFFIX="${SUFFIX:-}"

# The default build embeds no rules and is what users should download. The
# --offline build embeds them and works with no network, at the cost of a string
# table that antivirus quarantines: measured on a Windows machine running
# Kaspersky and Defender, the bundled binary was deleted within seconds while
# the default one ran normally.
for arg in "$@"; do
  case "$arg" in
    --offline) TAGS="bundled"; OUT="${OUT}-offline"; SUFFIX="_offline" ;;
    --check-reproducible) CHECK=1 ;;
  esac
done

targets=(
  "linux amd64" "linux arm64"
  "darwin amd64" "darwin arm64"
  "windows amd64" "windows arm64"
)

build_all() {
  local dest="$1"
  rm -rf "$dest" && mkdir -p "$dest"
  for t in "${targets[@]}"; do
    read -r goos goarch <<< "$t"
    name="aiexpose_${VERSION}_${goos}_${goarch}${SUFFIX}"
    [ "$goos" = "windows" ] && name="${name}.exe"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath ${TAGS:+-tags "$TAGS"} -o "$dest/$name" ./cmd/aiexpose
  done
}

if [ "${CHECK:-0}" = "1" ]; then
  echo "building twice to confirm the release is reproducible"
  build_all "${OUT}.a" >/dev/null
  build_all "${OUT}.b" >/dev/null
  ( cd "${OUT}.a" && sha256sum * ) | sed 's#\.a/##' > /tmp/aiexpose-sums-a
  ( cd "${OUT}.b" && sha256sum * ) | sed 's#\.b/##' > /tmp/aiexpose-sums-b
  if diff -q /tmp/aiexpose-sums-a /tmp/aiexpose-sums-b >/dev/null; then
    echo "reproducible: both builds are byte-identical"
    rm -rf "${OUT}.a" "${OUT}.b"
  else
    echo "NOT reproducible - do not publish this release" >&2
    diff /tmp/aiexpose-sums-a /tmp/aiexpose-sums-b >&2 || true
    exit 1
  fi
fi

build_all "$OUT"
( cd "$OUT" && sha256sum * > SHA256SUMS )

echo
ls -lh "$OUT"
echo
echo "go version: $(go version)"
echo "checksums:  $OUT/SHA256SUMS"
echo
echo "Publish SHA256SUMS with the release, and sign the Windows and macOS"
echo "binaries before uploading. See RELEASING.md."
if [ -n "$TAGS" ]; then
  echo
  echo "NOTE: this is the offline build. Do not make it the default download;"
  echo "      antivirus quarantines it. See ANTIVIRUS.md."
fi
