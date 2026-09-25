//go:build !linux && !darwin

package mtu

import (
	"fmt"
	"net"
)

func dontFragment(*net.IPConn, bool) error {
	return fmt.Errorf("MTU discovery is supported on Linux and macOS")
}
