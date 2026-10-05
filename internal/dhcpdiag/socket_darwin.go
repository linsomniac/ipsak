package dhcpdiag

import (
	"golang.org/x/sys/unix"
	"net"
)

func bindBroadcast(conn *net.UDPConn, iface net.Interface) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var e error
	err = raw.Control(func(fd uintptr) {
		e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
		if e == nil {
			e = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
		}
	})
	if err != nil {
		return err
	}
	return e
}
