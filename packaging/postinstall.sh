#!/bin/sh
# deb postinst and rpm %post: grant CAP_NET_RAW so raw-socket commands
# (ping's raw fallback, mtu, pathwatch, IPv6 ipconflict) work without sudo.
# AIDEV-NOTE: this runs on every install and upgrade because replacing the
# binary drops its file capabilities. It must never fail the transaction.
if command -v setcap >/dev/null 2>&1 && setcap cap_net_raw+ep /usr/bin/ipsak; then
	exit 0
fi
echo "ipsak: could not grant CAP_NET_RAW; raw-socket commands will need sudo" >&2
