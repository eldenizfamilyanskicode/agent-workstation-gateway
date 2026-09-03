#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: scripts/package-release.sh <vMAJOR.MINOR.PATCH> <source-sha> <new-output-directory>" >&2
  exit 2
fi

version=$1
source_sha=$2
output=$3
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "release version must be vMAJOR.MINOR.PATCH" >&2; exit 2 ;;
esac
if ! printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  echo "release version must be canonical" >&2
  exit 2
fi
if ! printf '%s\n' "$source_sha" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "source SHA must be lowercase 40-hex" >&2
  exit 2
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$(git -C "$repo" rev-parse HEAD)" != "$source_sha" ]; then
  echo "source SHA does not match HEAD" >&2
  exit 1
fi
if [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "release packaging requires a clean tree" >&2
  exit 1
fi
if [ -e "$output" ]; then
  echo "output path already exists" >&2
  exit 1
fi

for command in go git tar zip sha256sum touch; do
  command -v "$command" >/dev/null 2>&1 || { echo "missing release tool: $command" >&2; exit 1; }
done

release=${version#v}
epoch=$(git -C "$repo" show -s --format=%ct "$source_sha")
work=$(mktemp -d "${TMPDIR:-/tmp}/awg-release.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)

windows="awg_${release}_windows_amd64"
linux="awg_${release}_linux_amd64"
mkdir -p "$work/$windows" "$work/$linux"

gateway_ldflags="-s -w -X main.gatewayVersion=$version -X main.gatewaySourceSHA=$source_sha"
control_ldflags="-s -w -X main.controlVersion=$version -X main.controlSourceSHA=$source_sha"
broker_ldflags="-s -w -X main.gatewaySourceSHA=$source_sha"

(cd "$repo" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$gateway_ldflags" -o "$work/$windows/awg.exe" ./cmd/awg)
(cd "$repo" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$broker_ldflags" -o "$work/$windows/awg-broker.exe" ./cmd/awg-broker)
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$gateway_ldflags" -o "$work/$linux/awg" ./cmd/awg)
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$broker_ldflags" -o "$work/$linux/awg-broker" ./cmd/awg-broker)
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags "$control_ldflags" -o "$output/awg-control_${release}_linux_amd64" ./cmd/awg-control)

cp "$repo/LICENSE" "$repo/README.md" "$repo/config/examples/v1/windows-install.json" "$work/$windows/"
cp "$repo/LICENSE" "$repo/README.md" "$repo/config/examples/v1/linux-install.json" "$work/$linux/"
chmod 0755 "$work/$windows/awg.exe" "$work/$windows/awg-broker.exe" \
  "$work/$linux/awg" "$work/$linux/awg-broker" "$output/awg-control_${release}_linux_amd64"
chmod 0644 "$work/$windows/LICENSE" "$work/$windows/README.md" "$work/$windows/windows-install.json" \
  "$work/$linux/LICENSE" "$work/$linux/README.md" "$work/$linux/linux-install.json"
find "$work/$windows" "$work/$linux" -exec touch -d "@$epoch" {} +
touch -d "@$epoch" "$output/awg-control_${release}_linux_amd64"

(cd "$work" && zip -X -q -9 -r "$output/$windows.zip" "$windows")
tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$work" -czf "$output/$linux.tar.gz" "$linux"

LC_ALL=C sha256sum "$output"/awg_* "$output"/awg-control_* | sed 's#  .*/#  #' > "$output/SHA256SUMS"
cat "$output/SHA256SUMS"
