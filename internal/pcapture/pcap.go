// Package pcapture reads bounded classic PCAP and captures using tcpdump.
package pcapture

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

type Reader struct {
	r                 io.Reader
	order             binary.ByteOrder
	nano              bool
	Snaplen, LinkType uint32
	Header            [24]byte
}
type Record struct {
	At         time.Time
	Original   uint32
	Data       []byte
	WireHeader [16]byte
}

func NewReader(r io.Reader) (*Reader, error) {
	p := &Reader{r: r}
	if _, err := io.ReadFull(r, p.Header[:]); err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}
	switch string(p.Header[:4]) {
	case "\xd4\xc3\xb2\xa1":
		p.order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4":
		p.order = binary.BigEndian
	case "\x4d\x3c\xb2\xa1":
		p.order = binary.LittleEndian
		p.nano = true
	case "\xa1\xb2\x3c\x4d":
		p.order = binary.BigEndian
		p.nano = true
	case "\x0a\x0d\x0d\x0a":
		return nil, fmt.Errorf("pcapng is unsupported; convert to classic pcap with tcpdump -r INPUT -w OUTPUT")
	default:
		return nil, fmt.Errorf("invalid classic pcap magic")
	}
	if p.order.Uint16(p.Header[4:6]) != 2 || p.order.Uint16(p.Header[6:8]) != 4 {
		return nil, fmt.Errorf("unsupported pcap version")
	}
	p.Snaplen = p.order.Uint32(p.Header[16:20])
	p.LinkType = p.order.Uint32(p.Header[20:24]) & 0xffff
	if p.Snaplen == 0 || p.Snaplen > 65535 {
		return nil, fmt.Errorf("pcap snaplen must be 1–65535 bytes")
	}
	switch p.LinkType {
	case 0, 1, 12, 101, 108, 113, 276:
	default:
		return nil, fmt.Errorf("unsupported pcap link type %d", p.LinkType)
	}
	return p, nil
}
func (p *Reader) Next() (Record, error) {
	r := Record{}
	if _, err := io.ReadFull(p.r, r.WireHeader[:]); err != nil {
		return r, err
	}
	h := r.WireHeader[:]
	seconds, fraction, captured, original := p.order.Uint32(h[:4]), p.order.Uint32(h[4:8]), p.order.Uint32(h[8:12]), p.order.Uint32(h[12:16])
	unit := uint32(1000000)
	if p.nano {
		unit = 1000000000
	}
	if fraction >= unit {
		return r, fmt.Errorf("invalid pcap timestamp fraction")
	}
	if captured > p.Snaplen || captured > 65535 || captured > original {
		return r, fmt.Errorf("invalid pcap captured/original lengths")
	}
	r.At = time.Unix(int64(seconds), int64(fraction)*int64(1000000000/unit)).UTC()
	r.Original = original
	r.Data = make([]byte, captured)
	_, err := io.ReadFull(p.r, r.Data)
	return r, err
}
