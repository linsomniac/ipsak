package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/linsomniac/ipsak/internal/hostnet"
	"github.com/linsomniac/ipsak/internal/lookup"
)

func TestHostCommandValidation(t *testing.T) {
	for _, args := range [][]string{
		{"sockets", "--protocol", "sctp"}, {"sockets", "--port", "65536"},
		{"route", "192.0.2.0/24"}, {"route", "0.0.0.0"}, {"route", "224.0.0.1"}, {"route", "255.255.255.255"},
		{"interfaces", "--sample", "0"}, {"interfaces", "--sample", "10ms"}, {"interfaces", "--sample", "1m"},
		{"neighbors", "-4", "-6"},
		{"wake", "00:11:22:33:44:55", "--count", "0"}, {"wake", "00:11:22:33:44:55", "--destination", "::1"},
		{"wake", "00:11:22:33:44:55", "--interval", "1ms"}, {"wake", "ff:ff:ff:ff:ff:ff"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, stderr bytes.Buffer
			code := Execute(context.Background(), append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
			if code != 2 || out.Len() != 0 {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, &out, &stderr)
			}
		})
	}
}

func TestHostCanceledJSON(t *testing.T) {
	for _, args := range [][]string{{"sockets"}, {"route", "127.0.0.1"}, {"interfaces"}, {"neighbors"}, {"wake", "00:11:22:33:44:55"}} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out, stderr bytes.Buffer
		code := Execute(ctx, append(args, "--json"), strings.NewReader(""), &out, &stderr, "test")
		var report lookup.Report
		if code != 130 || json.Unmarshal(out.Bytes(), &report) != nil || report.Command != args[0] || len(report.Sections) != 1 || report.Sections[0].Status != "error" {
			t.Fatalf("%v exit=%d stdout=%s stderr=%s", args, code, &out, &stderr)
		}
	}
}

func TestWakeCommandJSON(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	args := []string{"wake", "00:11:22:33:44:55", "--destination", "127.0.0.1", "--port", strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port), "--count", "2", "--interval", "10ms", "--json"}
	var out, stderr bytes.Buffer
	code := Execute(context.Background(), args, strings.NewReader(""), &out, &stderr, "test")
	var report struct {
		Command  string `json:"command"`
		Sections []struct {
			Status string             `json:"status"`
			Data   hostnet.WakeReport `json:"data"`
		} `json:"sections"`
	}
	if code != 0 || json.Unmarshal(out.Bytes(), &report) != nil || report.Command != "wake" || len(report.Sections) != 1 || report.Sections[0].Data.Sent != 2 {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, &out, &stderr)
	}
	if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	want, _ := hostnet.MagicPacket(args[1])
	for range 2 {
		b := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(b)
		if err != nil || !bytes.Equal(b[:n], want) {
			t.Fatalf("packet=%x err=%v", b[:n], err)
		}
	}
}
