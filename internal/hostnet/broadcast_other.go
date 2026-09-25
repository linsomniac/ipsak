//go:build !linux && !darwin

package hostnet

import (
	"fmt"
	"net"
	"runtime"
)

func enableBroadcast(*net.UDPConn) error {
	return fmt.Errorf("wake is unsupported on %s; supported systems are Linux and macOS", runtime.GOOS)
}
