//go:build linux || darwin

package hostnet

import (
	"golang.org/x/sys/unix"
	"net"
)

func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var controlErr error
	err = raw.Control(func(fd uintptr) { controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1) })
	if err != nil {
		return err
	}
	return controlErr
}
