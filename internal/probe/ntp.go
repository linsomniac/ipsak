package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

const ntpEpoch = int64(2208988800)
const ntpEra = int64(1) << 32

type NTPResult struct {
	Server           string    `json:"server"`
	RemoteAddress    string    `json:"remote_address,omitempty"`
	Version          int       `json:"version"`
	Leap             int       `json:"leap"`
	Stratum          int       `json:"stratum"`
	KissCode         string    `json:"kiss_code,omitempty"`
	ReferenceID      string    `json:"reference_id,omitempty"`
	ClientSent       time.Time `json:"client_sent"`
	ServerReceived   time.Time `json:"server_received"`
	ServerSent       time.Time `json:"server_sent"`
	ClientReceived   time.Time `json:"client_received"`
	OffsetMS         float64   `json:"offset_ms"`
	DelayMS          float64   `json:"delay_ms"`
	RootDelayMS      float64   `json:"root_delay_ms"`
	RootDispersionMS float64   `json:"root_dispersion_ms"`
	PrecisionSeconds float64   `json:"precision_seconds"`
	Authenticated    bool      `json:"authenticated"`
	Valid            bool      `json:"valid"`
	ClockChanged     bool      `json:"clock_changed"`
	Note             string    `json:"note"`
}

func putNTP(b []byte, t time.Time) {
	binary.BigEndian.PutUint32(b, uint32(t.Unix()+ntpEpoch))
	binary.BigEndian.PutUint32(b[4:], uint32((uint64(t.Nanosecond())<<32)/1000000000))
}

// An NTP timestamp has no era number. Select the era nearest the local clock,
// requiring that clock to be within half an era (about 68 years) of true time.
func readNTP(b []byte, near time.Time) time.Time {
	seconds := int64(binary.BigEndian.Uint32(b))
	nearSeconds := near.Unix() + ntpEpoch
	era := (nearSeconds - seconds + ntpEra/2) / ntpEra
	if nearSeconds-seconds+ntpEra/2 < 0 {
		era = (nearSeconds - seconds - ntpEra/2 + 1) / ntpEra
	}
	ns := (uint64(binary.BigEndian.Uint32(b[4:])) * 1000000000) >> 32
	return time.Unix(seconds+era*ntpEra-ntpEpoch, int64(ns)).UTC()
}

func parseNTP(packet, request []byte, t1, t4 time.Time) (NTPResult, error) {
	r := NTPResult{ClientSent: t1.UTC(), ClientReceived: t4.UTC(), Note: "Unauthenticated single-sample estimate; era assumes local clock within 68 years of true time"}
	if len(packet) < 48 || len(packet) > 4096 {
		return r, fmt.Errorf("invalid NTP packet length %d", len(packet))
	}
	r.Version = int((packet[0] >> 3) & 7)
	r.Leap = int(packet[0] >> 6)
	r.Stratum = int(packet[1])
	if r.Version != 3 && r.Version != 4 {
		return r, fmt.Errorf("unsupported NTP version %d", r.Version)
	}
	if packet[0]&7 != 4 {
		return r, fmt.Errorf("NTP response is not server mode")
	}
	if len(request) < 48 || !bytes.Equal(packet[24:32], request[40:48]) {
		return r, fmt.Errorf("NTP origin timestamp mismatch")
	}
	r.ReferenceID = fmt.Sprintf("%x", packet[12:16])
	if r.Stratum == 0 {
		r.KissCode = string(packet[12:16])
		return r, fmt.Errorf("NTP Kiss-o'-Death: %q", r.KissCode)
	}
	if r.Leap == 3 || r.Stratum > 15 {
		return r, fmt.Errorf("NTP server is unsynchronized (leap %d, stratum %d)", r.Leap, r.Stratum)
	}
	if bytes.Equal(packet[32:40], make([]byte, 8)) || bytes.Equal(packet[40:48], make([]byte, 8)) {
		return r, fmt.Errorf("NTP response has a zero receive or transmit timestamp")
	}
	r.ServerReceived = readNTP(packet[32:40], t4)
	r.ServerSent = readNTP(packet[40:48], t4)
	if r.ServerSent.Before(r.ServerReceived) {
		return r, fmt.Errorf("NTP transmit timestamp precedes receive timestamp")
	}
	r.RootDelayMS = float64(int32(binary.BigEndian.Uint32(packet[4:8]))) * 1000 / 65536
	r.RootDispersionMS = float64(binary.BigEndian.Uint32(packet[8:12])) * 1000 / 65536
	r.PrecisionSeconds = math.Ldexp(1, int(int8(packet[3])))
	delay := t4.Sub(t1) - r.ServerSent.Sub(r.ServerReceived)
	if delay < -time.Microsecond {
		return r, fmt.Errorf("invalid negative NTP round-trip delay")
	}
	if delay < 0 {
		delay = 0
	}
	r.DelayMS = float64(delay) / float64(time.Millisecond)
	r.OffsetMS = (float64(r.ServerReceived.Sub(t1)) + float64(r.ServerSent.Sub(t4))) / float64(2*time.Millisecond)
	r.Valid = true
	return r, nil
}

func NTP(ctx context.Context, address string) (NTPResult, error) {
	r := NTPResult{Server: address}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if err != nil {
		return r, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	request := make([]byte, 48)
	request[0] = 4<<3 | 3
	t1 := time.Now()
	putNTP(request[40:], t1)
	if _, err = conn.Write(request); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return r, err
	}
	packet := make([]byte, 4097)
	n, err := conn.Read(packet)
	t4 := time.Now()
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return r, err
	}
	r, err = parseNTP(packet[:n], request, t1, t4)
	r.Server = address
	r.RemoteAddress = conn.RemoteAddr().String()
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	return r, err
}
