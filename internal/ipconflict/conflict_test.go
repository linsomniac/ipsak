package ipconflict

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
)

func TestARPAdaptersExactArgumentsAndOwnerEvidence(t *testing.T) {
	for _, flavor := range []string{"iputils", "habets"} {
		t.Run(flavor, func(t *testing.T) {
			iface := net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}
			o := Options{Target: "192.0.2.10", Interface: "eth0", Count: 3, Interval: time.Second, Duration: 4 * time.Second}
			r := Result{Target: o.Target, Owners: []Owner{}}
			calls := 0
			runner := func(_ context.Context, name string, args ...string) (localnet.CommandResult, error) {
				calls++
				if name != "arping" {
					t.Fatal(name)
				}
				if calls == 1 {
					if !reflect.DeepEqual(args, []string{"--help"}) {
						t.Fatal(args)
					}
					help := "-I <device> iputils"
					if flavor == "habets" {
						help = "Thomas Habets -i interface"
					}
					return localnet.CommandResult{Stdout: []byte(help)}, nil
				}
				want := []string{"-b", "-I", "eth0", "-c", "3", "-w", "4", "-i", "1", "192.0.2.10"}
				output := "Unicast reply from 192.0.2.10 [02:00:00:00:00:02] 0.123ms\nBroadcast reply from 192.0.2.10 [02:00:00:00:00:03] 0.100ms\nSent 3 probes (3 broadcast(s))\nReceived 2 response(s)\n"
				if flavor == "habets" {
					want = []string{"-i", "eth0", "-c", "3", "-w", "4", "-W", "1.000", "192.0.2.10"}
					output = "60 bytes from 02:00:00:00:00:02 (192.0.2.10): index=0 time=1 msec\n60 bytes from 02:00:00:00:00:03 (192.0.2.10): index=1 time=1 msec\n3 packets transmitted, 2 packets received, 33% unanswered\n"
				}
				if !reflect.DeepEqual(args, want) {
					t.Fatal(args, want)
				}
				return localnet.CommandResult{Stdout: []byte(output), Code: 1}, fmt.Errorf("one probe unanswered")
			}
			if err := probeARP(context.Background(), o, iface, &r, runner); err != nil {
				t.Fatal(err)
			}
			classify(&r)
			if r.Sent != 3 || r.Status != "conflict_evidence" || len(r.Owners) != 2 || calls != 2 {
				t.Fatal(r, calls)
			}
		})
	}
}
func TestARPUnsupportedFractionalIntervalAndMalformedOutput(t *testing.T) {
	o := Options{Count: 3, Interval: 500 * time.Millisecond, Duration: 3 * time.Second}
	r := Result{Target: "192.0.2.1", Owners: []Owner{}}
	calls := 0
	runner := func(context.Context, string, ...string) (localnet.CommandResult, error) {
		calls++
		return localnet.CommandResult{Stdout: []byte("iputils")}, nil
	}
	if err := probeARP(context.Background(), o, net.Interface{Name: "eth0"}, &r, runner); err == nil || !strings.Contains(err.Error(), "whole-second") || calls != 1 {
		t.Fatal(err, calls)
	}
	for _, output := range []string{"", "Sent 0 probes\n", "Unicast reply from 192.0.2.2 [02:00:00:00:00:02]\nSent 3 probes\n", "Unicast reply from 192.0.2.1 [01:00:00:00:00:02]\nSent 3 probes\n"} {
		r.Owners = []Owner{}
		if err := parseARP([]byte(output), "iputils", r.Target, "", &r); err == nil {
			t.Fatal("accepted", output)
		}
	}
}
func TestOwnerClassificationNeverClaimsFree(t *testing.T) {
	r := Result{Owners: []Owner{}}
	classify(&r)
	if r.Status != "inconclusive" {
		t.Fatal(r)
	}
	own := "02:00:00:00:00:01"
	addOwner(&r, own, "fixture", own)
	if len(r.Owners) != 0 {
		t.Fatal(r)
	}
	addOwner(&r, "02:00:00:00:00:02", "fixture", own)
	addOwner(&r, "02:00:00:00:00:02", "fixture", own)
	classify(&r)
	if r.Status != "address_in_use" || r.Owners[0].Observations != 2 {
		t.Fatal(r)
	}
	r.ConfiguredLocally = true
	classify(&r)
	if r.Status != "conflict_evidence" {
		t.Fatal(r)
	}
}

func advertisement(source, destination, target netip.Addr) []byte {
	p := make([]byte, 32)
	p[0] = 136
	p[4] = 0x60
	copy(p[8:24], target.AsSlice())
	p[24] = 2
	p[25] = 1
	copy(p[26:], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(p[2:4], checksum(source, destination, p))
	return p
}
func TestNDPValidatedAdvertisementAndProvenance(t *testing.T) {
	target := netip.MustParseAddr("fe80::10")
	local := netip.MustParseAddr("fe80::1")
	p := advertisement(target, local, target)
	mac, err := parseAdvertisement(p, target, local, target, local, 255, 3, 3)
	if err != nil || mac != "02:00:00:00:00:02" {
		t.Fatal(mac, err)
	}
	for _, test := range []struct {
		name                string
		hop, index          int
		source, destination netip.Addr
	}{{"hop", 64, 3, target, local}, {"interface", 255, 4, target, local}, {"source", 255, 3, netip.IPv6Unspecified(), local}, {"destination", 255, 3, target, netip.MustParseAddr("fe80::99")}} {
		if _, err := parseAdvertisement(p, test.source, test.destination, target, local, test.hop, test.index, 3); err == nil {
			t.Fatal(test.name)
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { b[0] = 135 }, func(b []byte) { b[1] = 1 }, func(b []byte) { b[23] ^= 1 }, func(b []byte) { b[25] = 0 }, func(b []byte) { b[24] = 1 }, func(b []byte) { b[25] = 2 }} {
		copy := bytes.Clone(p)
		mutate(copy)
		clear(copy[2:4])
		binary.BigEndian.PutUint16(copy[2:4], checksum(target, local, copy))
		if _, err := parseAdvertisement(copy, target, local, target, local, 255, 3, 3); err == nil {
			t.Fatal("malformed advertisement accepted", copy)
		}
	}
	bad := bytes.Clone(p)
	bad[3] ^= 1
	if _, err := parseAdvertisement(bad, target, local, target, local, 255, 3, 3); err == nil {
		t.Fatal("bad checksum accepted")
	}
	for n := 0; n < len(p); n++ {
		if _, err := parseAdvertisement(p[:n], target, local, target, local, 255, 3, 3); err == nil {
			t.Fatal("truncated packet accepted", n)
		}
	}
}
func TestNDPSolicitationWireAndCancellation(t *testing.T) {
	target := netip.MustParseAddr("2001:db8::1234:5678")
	source := netip.MustParseAddr("fe80::1")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	p, dst := solicitation(target, source, mac)
	if dst.String() != "ff02::1:ff34:5678" || p[0] != 135 || p[24] != 1 || !bytes.Equal(p[26:], mac) || checksum(source, dst, p) != 0 {
		t.Fatal(dst, p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, Options{Target: "192.0.2.1", Interface: "eth0", Count: 3, Interval: time.Second, Duration: 4 * time.Second}, nil)
	if err != context.Canceled {
		t.Fatal(err)
	}
}
