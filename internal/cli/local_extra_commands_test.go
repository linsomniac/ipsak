package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linsomniac/ipsak/internal/lookup"
)

func localReport(t *testing.T, out, command string) lookup.Report {
	t.Helper()
	var r lookup.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Command != command || r.SchemaVersion != 1 || len(r.Sections) == 0 {
		t.Fatal(err, out)
	}
	return r
}
func localPCAP() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(0xa1b2c3d4))
	binary.Write(&b, binary.LittleEndian, uint16(2))
	binary.Write(&b, binary.LittleEndian, uint16(4))
	for _, n := range []uint32{0, 0, 65535, 101, 1700000000, 0, 28, 28} {
		binary.Write(&b, binary.LittleEndian, n)
	}
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[3] = 28
	packet[9] = 17
	copy(packet[12:16], []byte{192, 0, 2, 1})
	copy(packet[16:20], []byte{192, 0, 2, 2})
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	packet[25] = 8
	b.Write(packet)
	return b.Bytes()
}
func TestLocalExtraValidationAndHelp(t *testing.T) {
	for _, name := range []string{"capture", "dhcp", "ipconflict", "discover"} {
		out, stderr, code := invoke(name, "--help")
		if code != 0 || out == "" || stderr != "" {
			t.Fatal(name, out, stderr, code)
		}
	}
	for _, args := range [][]string{{"capture", "--count", "0"}, {"capture", "--read", "x", "--interface", "eth0"}, {"capture", "--protocol", "invalid"}, {"capture", "--port", "0"}, {"capture", "--read", "-"}, {"dhcp", "--probe"}, {"dhcp", "--probe", "--interface", "eth0", "--lease-file", "x"}, {"dhcp", "--duration", "0"}, {"ipconflict", "192.0.2.1"}, {"ipconflict", "224.0.0.1", "--interface", "eth0"}, {"ipconflict", "fe80::1%eth1", "--interface", "eth0"}, {"discover", "--type", "invalid"}, {"discover", "-4", "-6"}, {"discover", "--duration", "0"}} {
		out, stderr, code := invoke(append(args, "--json")...)
		if code != 2 || out != "" || stderr == "" {
			t.Fatal(args, code, out, stderr)
		}
	}
}
func TestLocalCaptureOfflineJSONPlainAndOutputSafety(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.pcap")
	output := filepath.Join(dir, "output.pcap")
	if err := os.WriteFile(input, localPCAP(), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := invoke("capture", "--read", input, "--write", output, "--json")
	if code != 0 || stderr != "" {
		t.Fatal(code, out, stderr)
	}
	r := localReport(t, out, "capture")
	if r.Sections[0].Status != "ok" || !strings.Contains(out, `"protocol": "udp"`) {
		t.Fatal(out)
	}
	out, stderr, code = invoke("capture", "--read", input, "--plain")
	if code != 0 || !strings.Contains(out, "192.0.2.1") || strings.Contains(out, "\x1b") {
		t.Fatal(code, out, stderr)
	}
	out, stderr, code = invoke("capture", "--read", input, "--write", output, "--json")
	if code != 1 || stderr == "" {
		t.Fatal(code, out, stderr)
	}
	localReport(t, out, "capture")
}
func TestLocalDHCPFileEvidenceAndOperationalFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease")
	os.WriteFile(path, []byte("ADDRESS=192.0.2.10\nSERVER_ADDRESS=192.0.2.1\nDNS=192.0.2.53\nLIFETIME=3600\n"), 0600)
	out, stderr, code := invoke("dhcp", "--lease-file", path, "--json")
	if code != 0 || stderr != "" {
		t.Fatal(code, out, stderr)
	}
	r := localReport(t, out, "dhcp")
	if r.Sections[0].Status != "ok" || !strings.Contains(out, "local_lease_record") {
		t.Fatal(out)
	}
	for _, args := range [][]string{{"capture", "--read", path + "missing"}, {"dhcp", "--lease-file", path + "missing"}} {
		out, stderr, code := invoke(append(args, "--json")...)
		if code != 1 || stderr == "" {
			t.Fatal(args, code, out, stderr)
		}
		localReport(t, out, args[0])
	}
}
func TestLocalExtraCancellationProducesJSON(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"capture", "--duration", "1.5"}, {"dhcp", "--duration", "2"}, {"ipconflict", "192.0.2.1", "--interface", "eth0", "--duration", "4", "--interval", "1"}, {"discover", "--duration", "2"}} {
		var out, stderr bytes.Buffer
		code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
		if code != 130 {
			t.Fatal(args, code, out.String(), stderr.String())
		}
		r := localReport(t, out.String(), args[0])
		if r.Sections[0].Status != "error" {
			t.Fatal(r)
		}
	}
}
