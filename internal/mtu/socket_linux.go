package mtu

import (
	"net"

	"golang.org/x/sys/unix"
)

func dontFragment(conn *net.IPConn, ipv6 bool) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
		} else {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
