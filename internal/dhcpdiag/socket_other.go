//go:build !linux && !darwin

package dhcpdiag

import (
	"fmt"
	"net"
)

func bindBroadcast(*net.UDPConn, net.Interface) error {
	return fmt.Errorf("DHCP probing supports Linux and macOS")
}
