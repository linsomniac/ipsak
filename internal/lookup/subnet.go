package lookup

import (
	"fmt"
	"math/big"
	"net/netip"
)

type Subnet struct {
	CIDR      string `json:"cidr"`
	Network   string `json:"network"`
	Broadcast string `json:"broadcast,omitempty"`
	Netmask   string `json:"netmask"`
	Wildcard  string `json:"wildcard"`
	FirstHost string `json:"first_host"`
	LastHost  string `json:"last_host"`
	Addresses string `json:"addresses"`
	Usable    string `json:"usable"`
	IPVersion int    `json:"ip_version"`
}

func Calculate(cidr string) (Subnet, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return Subnet{}, fmt.Errorf("invalid CIDR: %w", err)
	}
	p = p.Masked()
	width := p.Addr().BitLen()
	size := new(big.Int).Lsh(big.NewInt(1), uint(width-p.Bits()))
	base := new(big.Int).SetBytes(p.Addr().AsSlice())
	last := new(big.Int).Add(base, new(big.Int).Sub(size, big.NewInt(1)))
	first := new(big.Int).Set(base)
	end := new(big.Int).Set(last)
	usable := new(big.Int).Set(size)
	version := 6
	broadcast := ""
	toAddr := func(n *big.Int) string {
		b := make([]byte, width/8)
		n.FillBytes(b)
		a, _ := netip.AddrFromSlice(b)
		return a.String()
	}
	if width == 32 {
		version = 4
		broadcast = toAddr(last)
		if p.Bits() < 31 {
			first.Add(first, big.NewInt(1))
			end.Sub(end, big.NewInt(1))
			usable.Sub(usable, big.NewInt(2))
		}
	} else if p.Bits() < 127 {
		first.Add(first, big.NewInt(1))
		usable.Sub(usable, big.NewInt(1))
	}
	wild := new(big.Int).Sub(size, big.NewInt(1))
	all := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(width)), big.NewInt(1))
	mask := new(big.Int).Xor(all, wild)
	return Subnet{CIDR: p.String(), Network: p.Addr().String(), Broadcast: broadcast, Netmask: toAddr(mask), Wildcard: toAddr(wild), FirstHost: toAddr(first), LastHost: toAddr(end), Addresses: size.String(), Usable: usable.String(), IPVersion: version}, nil
}
