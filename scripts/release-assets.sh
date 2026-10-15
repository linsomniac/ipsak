#!/bin/sh
# Generate the files GoReleaser ships beside the binary: shell completions,
# third-party license notices, and the Debian copyright file. Output goes to
# build/, which .goreleaser.yaml reads.
set -eu

out=build
rm -rf "$out"
mkdir -p "$out/completions"

go build -o "$out/ipsak" ./cmd/ipsak
"$out/ipsak" completion bash >"$out/completions/ipsak.bash"
"$out/ipsak" completion zsh >"$out/completions/_ipsak"
"$out/ipsak" completion fish >"$out/completions/ipsak.fish"
"$out/ipsak" completion powershell >"$out/completions/ipsak.ps1"
rm "$out/ipsak"

notice() {
	printf '\n%s\n%s\n\n' "$1" "$(printf '%s' "$1" | tr -c '\n' '=')"
	cat "$2"
}

# AIDEV-NOTE: the static binary embeds the Go standard library and every
# dependency module, and their BSD, MIT and Apache licenses require shipping
# their notices with binaries. A module without a license file fails the build.
# Go's own license is a committed copy because Nix's Go omits GOROOT/LICENSE.
# A module released without a license file gets the upstream text committed
# at packaging/licenses/<module path>/LICENSE.
{
	printf 'ipsak is dedicated to the public domain under CC0-1.0. Its binaries\n'
	printf 'also contain the following software, under the licenses below.\n'
	notice "Go standard library" packaging/go-LICENSE
	for goos in linux darwin windows; do
		GOOS=$goos go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/ipsak
	done | sort -u | while read -r module dir; do
		found=
		for file in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "packaging/licenses/${module%@*}/LICENSE"; do
			[ -f "$file" ] || continue
			notice "$module ($(basename "$file"))" "$file"
			found=1
		done
		if [ -z "$found" ]; then
			echo "release-assets: no license file for $module in $dir" >&2
			exit 1
		fi
	done
} >"$out/THIRD_PARTY_LICENSES.txt"

# Debian machine-readable copyright format: license text lines are indented
# one space, and blank lines become " .".
{
	cat <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ipsak
Upstream-Contact: Sean Reifschneider <sean@realgo.com>
Source: https://github.com/linsomniac/ipsak

Files: *
Copyright: Sean Reifschneider
License: CC0-1.0
Comment: The ipsak binary also contains the Go standard library and Go
 modules under their own licenses; see
 /usr/share/doc/ipsak/THIRD_PARTY_LICENSES.txt.

License: CC0-1.0
EOF
	sed -e 's/^$/./' -e 's/^/ /' LICENSE
} >"$out/copyright"
