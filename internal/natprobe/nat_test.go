package natprobe

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mappedPacket(id [12]byte, address netip.AddrPort, xor bool) []byte {
	b := address.Addr().AsSlice()
	p := make([]byte, 28+len(b))
	binary.BigEndian.PutUint16(p, 0x0101)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)-20))
	binary.BigEndian.PutUint32(p[4:], cookie)
	copy(p[8:], id[:])
	kind := uint16(1)
	if xor {
		kind = 0x20
	}
	binary.BigEndian.PutUint16(p[20:], kind)
	binary.BigEndian.PutUint16(p[22:], uint16(4+len(b)))
	p[25] = 1
	if len(b) == 16 {
		p[25] = 2
	}
	port := address.Port()
	if xor {
		port ^= uint16(cookie >> 16)
	}
	binary.BigEndian.PutUint16(p[26:], port)
	copy(p[28:], b)
	if xor {
		for i := range b {
			p[28+i] ^= p[4+i]
		}
	}
	return p
}

func TestSTUNParserFamiliesFallbackAndMalformed(t *testing.T) {
	id := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	for _, addr := range []string{"192.0.2.9:54321", "[2001:db8::5]:40000"} {
		for _, xor := range []bool{true, false} {
			expected := netip.MustParseAddrPort(addr)
			p := mappedPacket(id, expected, xor)
			got, err := parseResponse(p, id)
			if err != nil || got != expected {
				t.Fatal(got, err)
			}
		}
	}
	valid := mappedPacket(id, netip.MustParseAddrPort("192.0.2.1:1234"), true)
	cases := [][]byte{valid[:19], append(append([]byte{}, valid...), 0), append([]byte{}, valid...), append([]byte{}, valid...), append([]byte{}, valid...)}
	cases[2][8] ^= 1
	cases[3][23] = 99
	cases[4][25] = 9
	for _, p := range cases {
		if _, err := parseResponse(p, id); err == nil {
			t.Fatalf("accepted malformed packet %x", p)
		}
	}
	fingerprint := append(append([]byte{}, valid...), []byte{0x80, 0x28, 0, 4, 0, 0, 0, 0}...)
	binary.BigEndian.PutUint16(fingerprint[2:], uint16(len(fingerprint)-20))
	if _, err := parseResponse(fingerprint, id); err == nil {
		t.Fatal("accepted invalid fingerprint")
	}
	errorPacket := make([]byte, 28)
	copy(errorPacket, valid[:20])
	binary.BigEndian.PutUint16(errorPacket, 0x0111)
	binary.BigEndian.PutUint16(errorPacket[2:], 8)
	binary.BigEndian.PutUint16(errorPacket[20:], 9)
	binary.BigEndian.PutUint16(errorPacket[22:], 4)
	errorPacket[26] = 4
	errorPacket[27] = 1
	if _, err := parseResponse(errorPacket, id); err == nil {
		t.Fatal("accepted STUN server error")
	}
}

func fixture(t *testing.T, otherPort bool, wrongFirst bool) (string, *sync.Map) {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	sources := &sync.Map{}
	go func() {
		b := make([]byte, 1024)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			if n != 20 {
				continue
			}
			sources.Store(a.String(), true)
			var id [12]byte
			copy(id[:], b[8:20])
			p := mappedPacket(id, netip.MustParseAddrPort("203.0.113.1:40000"), true)
			if wrongFirst {
				bad := append([]byte{}, p...)
				bad[8] ^= 1
				_, _ = c.WriteToUDP(bad, a)
			}
			if otherPort {
				bad, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e == nil {
					_, _ = bad.WriteToUDP(p, a)
					_ = bad.Close()
				}
				continue
			}
			_, _ = c.WriteToUDP(p, a)
		}
	}()
	return c.LocalAddr().String(), sources
}

func TestSameSocketParallelServersAndPartialFailure(t *testing.T) {
	a, sa := fixture(t, false, true)
	b, sb := fixture(t, false, false)
	r, err := Observe(context.Background(), []string{a, b})
	if err != nil || len(r.Comparisons) != 1 || r.Comparisons[0].Status != "same_observed_mapping" {
		t.Fatal(r, err)
	}
	if r.Observations[0].LocalSocket != r.Observations[1].LocalSocket {
		t.Fatal("different sockets", r)
	}
	var source string
	sa.Range(func(k, v any) bool { source = k.(string); return false })
	if _, ok := sb.Load(source); !ok {
		t.Fatal("server sources differ")
	}
	bad, _ := fixture(t, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	r, err = Observe(ctx, []string{a, bad})
	if err == nil || r.Observations[0].Mapping == "" || r.Observations[1].Mapping != "" || r.Observations[1].Error == "" {
		t.Fatal(r, err)
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := Observe(ctx, []string{"127.0.0.1:3478"})
	if err == nil || time.Since(start) > time.Second {
		t.Fatal(err)
	}
}
