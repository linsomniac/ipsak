package pcapture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pcapFixture(order binary.ByteOrder, nano bool, link uint32, packets ...[]byte) []byte {
	buf := new(bytes.Buffer)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	binary.Write(buf, order, magic)
	binary.Write(buf, order, uint16(2))
	binary.Write(buf, order, uint16(4))
	binary.Write(buf, order, uint32(0))
	binary.Write(buf, order, uint32(0))
	binary.Write(buf, order, uint32(65535))
	binary.Write(buf, order, link)
	for _, packet := range packets {
		binary.Write(buf, order, uint32(1700000000))
		binary.Write(buf, order, uint32(123))
		binary.Write(buf, order, uint32(len(packet)))
		binary.Write(buf, order, uint32(len(packet)))
		buf.Write(packet)
	}
	return buf.Bytes()
}
func udpPacket() []byte {
	p := make([]byte, 14+20+8)
	copy(p[:6], []byte{0, 1, 2, 3, 4, 5})
	copy(p[6:12], []byte{2, 3, 4, 5, 6, 7})
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x45
	binary.BigEndian.PutUint16(p[16:18], 28)
	p[23] = 17
	copy(p[26:30], net.IPv4(192, 0, 2, 1).To4())
	copy(p[30:34], net.IPv4(192, 0, 2, 2).To4())
	binary.BigEndian.PutUint16(p[34:36], 12345)
	binary.BigEndian.PutUint16(p[36:38], 53)
	binary.BigEndian.PutUint16(p[38:40], 8)
	return p
}
func options() Options {
	return Options{Count: 10, ScanLimit: 100, Snaplen: 256, Duration: 100 * time.Millisecond}
}

func TestPCAPByteOrdersAndBoundedDecode(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			r, err := NewReader(bytes.NewReader(pcapFixture(order, nano, 1, udpPacket())))
			if err != nil {
				t.Fatal(err)
			}
			record, err := r.Next()
			if err != nil {
				t.Fatal(err)
			}
			p := Decode(r.LinkType, record)
			if p.Protocol != "udp" || p.Source != "192.0.2.1" || p.DestinationPort != 53 || p.Error != "" {
				t.Fatal(p)
			}
			if _, err := r.Next(); err != io.EOF {
				t.Fatal(err)
			}
		}
	}
}
func TestPCAPMalformedHeadersAndRecords(t *testing.T) {
	valid := pcapFixture(binary.LittleEndian, false, 1, udpPacket())
	for _, mutate := range []func([]byte){func(b []byte) { copy(b[:4], []byte{10, 13, 13, 10}) }, func(b []byte) { b[4] = 3 }, func(b []byte) { binary.LittleEndian.PutUint32(b[16:20], 1<<20) }, func(b []byte) { binary.LittleEndian.PutUint32(b[20:24], 999) }} {
		b := bytes.Clone(valid)
		mutate(b)
		if _, err := NewReader(bytes.NewReader(b)); err == nil {
			t.Fatal("invalid header accepted")
		}
	}
	for _, mutate := range []func([]byte){func(b []byte) { binary.LittleEndian.PutUint32(b[32:36], 65536) }, func(b []byte) { binary.LittleEndian.PutUint32(b[36:40], 1) }, func(b []byte) { binary.LittleEndian.PutUint32(b[28:32], 1000000) }} {
		b := bytes.Clone(valid)
		mutate(b)
		r, err := NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Next(); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
	r, _ := NewReader(bytes.NewReader(valid[:len(valid)-1]))
	if _, err := r.Next(); err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
}
func TestPCAPLinksFragmentsAndFilters(t *testing.T) {
	ether := udpPacket()
	ip := ether[14:]
	for _, fixture := range []struct {
		link uint32
		data []byte
	}{{1, ether}, {101, ip}, {0, append(make([]byte, 4), ip...)}, {113, append(append(make([]byte, 14), 0x08, 0), ip...)}, {276, append(append([]byte{0x08, 0}, make([]byte, 18)...), ip...)}} {
		p := Decode(fixture.link, Record{Data: fixture.data, Original: uint32(len(fixture.data))})
		if p.Protocol != "udp" || !((Filter{Protocol: "udp", Host: "192.0.2.2", Port: 53}).Match(p)) || (Filter{Protocol: "tcp"}).Match(p) {
			t.Fatal(p)
		}
	}
	fragment := bytes.Clone(ether)
	fragment[20] = 0
	fragment[21] = 1
	p := Decode(1, Record{Data: fragment, Original: uint32(len(fragment))})
	if !p.Fragment || p.SourcePort != 0 || p.Detail != "noninitial fragment" {
		t.Fatal(p)
	}
	for n := 0; n < len(ether); n++ {
		_ = Decode(1, Record{Data: ether[:n], Original: uint32(len(ether))})
	}
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[6] = 17
	binary.BigEndian.PutUint16(v6[4:6], 8)
	copy(v6[8:24], net.ParseIP("2001:db8::1").To16())
	copy(v6[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(v6[42:44], 5353)
	binary.BigEndian.PutUint16(v6[44:46], 8)
	p = Decode(101, Record{Data: v6, Original: 48})
	if p.Protocol != "udp" || p.Source != "2001:db8::1" || p.DestinationPort != 5353 {
		t.Fatal(p)
	}
}

func TestPCAPTCPARPAndVLANEvidence(t *testing.T) {
	tcp := append(bytes.Clone(udpPacket()[:34]), make([]byte, 20)...)
	binary.BigEndian.PutUint16(tcp[16:18], 40)
	tcp[23] = 6
	binary.BigEndian.PutUint16(tcp[34:36], 12345)
	binary.BigEndian.PutUint16(tcp[36:38], 443)
	tcp[46] = 0x50
	tcp[47] = 0x12
	p := Decode(1, Record{Data: tcp, Original: uint32(len(tcp))})
	if p.Protocol != "tcp" || p.Detail != "SYN,ACK" || p.DestinationPort != 443 {
		t.Fatal(p)
	}
	vlan := append(bytes.Clone(tcp[:12]), 0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 0x08, 0)
	vlan = append(vlan, tcp[14:]...)
	p = Decode(1, Record{Data: vlan, Original: uint32(len(vlan))})
	if p.Protocol != "tcp" || p.DestinationPort != 443 || p.Error != "" {
		t.Fatal(p)
	}
	arp := make([]byte, 42)
	copy(arp[:12], tcp[:12])
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)
	binary.BigEndian.PutUint16(arp[14:16], 1)
	binary.BigEndian.PutUint16(arp[16:18], 0x0800)
	arp[18] = 6
	arp[19] = 4
	binary.BigEndian.PutUint16(arp[20:22], 2)
	copy(arp[22:28], []byte{2, 0, 0, 0, 0, 1})
	copy(arp[28:32], []byte{192, 0, 2, 1})
	copy(arp[38:42], []byte{192, 0, 2, 2})
	p = Decode(1, Record{Data: arp, Original: 42})
	if p.Protocol != "arp" || p.Source != "192.0.2.1" || p.SourceMAC != "02:00:00:00:00:01" || !strings.Contains(p.Detail, "is at") {
		t.Fatal(p)
	}
}
func TestPCAPIPv6ExtensionsFragmentsAndMalformedLengths(t *testing.T) {
	p := make([]byte, 56)
	p[0] = 0x60
	p[6] = 0
	binary.BigEndian.PutUint16(p[4:6], 16)
	copy(p[8:24], net.ParseIP("2001:db8::1").To16())
	copy(p[24:40], net.ParseIP("2001:db8::2").To16())
	p[40] = 17
	binary.BigEndian.PutUint16(p[50:52], 5353)
	binary.BigEndian.PutUint16(p[52:54], 8)
	decoded := Decode(101, Record{Data: p, Original: 56})
	if decoded.Protocol != "udp" || decoded.DestinationPort != 5353 || decoded.Error != "" {
		t.Fatal(decoded)
	}
	p[6] = 44
	decoded = Decode(101, Record{Data: p, Original: 56})
	if !decoded.Fragment || decoded.DestinationPort != 5353 {
		t.Fatal(decoded)
	}
	p[43] = 8
	decoded = Decode(101, Record{Data: p, Original: 56})
	if decoded.DestinationPort != 0 || decoded.Detail != "noninitial fragment" {
		t.Fatal(decoded)
	}
	p[6] = 0
	p[41] = 255
	decoded = Decode(101, Record{Data: p, Original: 56})
	if decoded.Error == "" {
		t.Fatal("oversize extension accepted")
	}
	bad := udpPacket()
	bad[14] = 0x44
	if d := Decode(1, Record{Data: bad, Original: uint32(len(bad))}); d.Error == "" {
		t.Fatal("bad IHL accepted")
	}
	bad = udpPacket()
	bad[39] = 1
	if d := Decode(1, Record{Data: bad, Original: uint32(len(bad))}); d.Error == "" {
		t.Fatal("bad UDP length accepted")
	}
}
func TestCaptureOfflineFilteredAtomicOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcap")
	output := filepath.Join(dir, "matched.pcap")
	packet := udpPacket()
	other := bytes.Clone(packet)
	binary.BigEndian.PutUint16(other[36:38], 80)
	os.WriteFile(input, pcapFixture(binary.LittleEndian, false, 1, packet, other), 0600)
	o := options()
	o.Read = input
	o.Write = output
	o.Filter.Port = 53
	r, err := Run(context.Background(), o, nil)
	if err != nil || r.Scanned != 2 || r.Matched != 1 || r.Output != output {
		t.Fatal(r, err)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Next(); err != io.EOF {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(output); st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	if _, err = Run(context.Background(), o, nil); err == nil {
		t.Fatal("overwrote existing output")
	}
	data, _ := os.ReadFile(output)
	bad := bytes.Clone(data)
	bad = append(bad, 1)
	os.WriteFile(input, bad, 0600)
	o.Force = true
	if _, err = Run(context.Background(), o, nil); err == nil {
		t.Fatal("accepted truncated record")
	}
	after, _ := os.ReadFile(output)
	if !bytes.Equal(data, after) {
		t.Fatal("failed capture replaced existing output")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ipsak-") {
			t.Fatal("temporary leaked")
		}
	}
}

func TestCaptureProcessHelper(t *testing.T) {
	mode := os.Getenv("IPSAK_CAPTURE_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "fail":
		os.Stdout.Write(pcapFixture(binary.LittleEndian, false, 1, udpPacket()))
		os.Stderr.WriteString("fixture failure")
		os.Exit(7)
	case "overflow":
		os.Stdout.Write(pcapFixture(binary.LittleEndian, false, 1))
		os.Stderr.Write(bytes.Repeat([]byte("x"), 10000))
	case "wait":
		os.Stdout.Write(pcapFixture(binary.LittleEndian, false, 1))
	case "packet":
		os.Stdout.Write(pcapFixture(binary.LittleEndian, false, 1, udpPacket()))
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}
func TestCaptureDiagnosticCopyRemainsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &stderrBuffer{cancel: cancel}
	// Hide Reader.WriteTo so io.Copy exercises the destination's method set.
	_, err := io.Copy(b, struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 10000))})
	if err == nil || !b.overflow || b.buffer.Len() > 8192 || ctx.Err() == nil {
		t.Fatalf("error=%v overflow=%v size=%d canceled=%v", err, b.overflow, b.buffer.Len(), ctx.Err())
	}
}
func helperCommand(ctx context.Context, _ string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureProcessHelper$")
}
func fixtureInterface(name string) (*net.Interface, error) {
	return &net.Interface{Name: name, Index: 1}, nil
}
func TestCaptureSubprocessFailureCancellationAndOverflow(t *testing.T) {
	for _, mode := range []string{"fail", "overflow", "wait", "packet"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("IPSAK_CAPTURE_HELPER", mode)
			o := options()
			o.Interface = "fixture"
			o.Duration = 300 * time.Millisecond
			if mode != "wait" {
				o.Duration = 5 * time.Second
			}
			if mode == "packet" {
				o.Count = 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := run(ctx, o, nil, helperCommand, fixtureInterface)
			if mode == "fail" {
				if err == nil || r.Matched != 1 || !strings.Contains(err.Error(), "fixture failure") {
					t.Fatal(r, err)
				}
			} else if mode == "overflow" {
				if err == nil || !strings.Contains(err.Error(), "limit") {
					t.Fatal(r, err)
				}
			} else if err != nil {
				t.Fatal(r, err)
			} else if mode == "wait" && r.Stop != "duration" {
				t.Fatal(r)
			}
		})
	}
}
func TestCaptureParentCancellationAndScanLimit(t *testing.T) {
	t.Setenv("IPSAK_CAPTURE_HELPER", "wait")
	o := options()
	o.Interface = "fixture"
	o.Duration = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := run(ctx, o, nil, helperCommand, fixtureInterface)
	if err != context.DeadlineExceeded {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "input")
	os.WriteFile(path, pcapFixture(binary.LittleEndian, false, 1, udpPacket(), udpPacket()), 0600)
	o = options()
	o.Read = path
	o.Count = 1
	o.ScanLimit = 1
	o.Filter.Port = 80
	r, err := Run(context.Background(), o, nil)
	if err != nil || r.Stop != "scan_limit" || r.Scanned != 1 || r.Matched != 0 {
		t.Fatal(r, err)
	}
}
