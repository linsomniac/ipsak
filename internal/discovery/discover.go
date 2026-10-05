package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/linsomniac/ipsak/internal/localnet"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Options struct {
	Interfaces, Types []string
	Duration          time.Duration
	IPv4, IPv6        bool
}

func (o Options) Validate() error {
	if o.Duration < time.Second || o.Duration > 30*time.Second {
		return fmt.Errorf("duration must be 1s–30s")
	}
	if o.IPv4 && o.IPv6 {
		return fmt.Errorf("choose only one of --ipv4 or --ipv6")
	}
	if len(o.Interfaces) > 8 || len(o.Types) > 16 {
		return fmt.Errorf("at most eight interfaces and sixteen service types")
	}
	for _, name := range o.Interfaces {
		if err := localnet.ValidInterfaceName(name); err != nil {
			return err
		}
	}
	for _, typ := range o.Types {
		if _, err := ServiceType(typ); err != nil {
			return err
		}
	}
	return nil
}

type Result struct {
	Services   []Service `json:"services"`
	Interfaces []string  `json:"interfaces"`
	Queries    int       `json:"queries_sent"`
	Ignored    int       `json:"ignored_packets"`
	Dropped    uint64    `json:"dropped_updates"`
	Limited    bool      `json:"limited"`
	Errors     []string  `json:"errors"`
	Note       string    `json:"note"`
}

func (r Result) CompactLines() []string {
	lines := []string{fmt.Sprintf("%d services · %d multicast queries · %s", len(r.Services), r.Queries, strings.Join(r.Interfaces, ", "))}
	for _, s := range r.Services {
		state := "resolved"
		if !s.Complete {
			state = "incomplete"
		}
		lines = append(lines, fmt.Sprintf("%s · %s · %s · %s", s.Name, s.Type, s.Interface, state), "  "+strings.Join(s.Endpoints, ", "))
		if len(s.TXT) > 0 {
			lines = append(lines, "  "+strings.Join(s.TXT, " · "))
		}
	}
	return append(lines, r.Errors...)
}

type multicastSocket struct {
	close func() error
	read  func([]byte) (int, int, int, *net.UDPAddr, error)
	write func([]byte) error
}

func openMulticast(iface net.Interface, v6 bool) (multicastSocket, error) {
	network := "udp4"
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	if v6 {
		network = "udp6"
		group = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353, Zone: iface.Name}
	}
	conn, err := net.ListenMulticastUDP(network, &iface, group)
	if err != nil {
		return multicastSocket{}, err
	}
	s := multicastSocket{close: conn.Close}
	if v6 {
		p := ipv6.NewPacketConn(conn)
		if err = p.SetControlMessage(ipv6.FlagHopLimit|ipv6.FlagInterface, true); err == nil {
			err = p.SetMulticastInterface(&iface)
		}
		if err == nil {
			err = p.SetMulticastHopLimit(255)
		}
		if err == nil {
			err = p.SetMulticastLoopback(true)
		}
		if err != nil {
			conn.Close()
			return s, err
		}
		s.read = func(b []byte) (int, int, int, *net.UDPAddr, error) {
			n, cm, a, e := p.ReadFrom(b)
			if e != nil {
				return n, 0, 0, nil, e
			}
			peer, _ := a.(*net.UDPAddr)
			if cm == nil {
				return n, 0, 0, peer, nil
			}
			return n, cm.HopLimit, cm.IfIndex, peer, nil
		}
		s.write = func(b []byte) error {
			_, e := p.WriteTo(b, &ipv6.ControlMessage{IfIndex: iface.Index, HopLimit: 255}, group)
			return e
		}
	} else {
		p := ipv4.NewPacketConn(conn)
		if err = p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagInterface, true); err == nil {
			err = p.SetMulticastInterface(&iface)
		}
		if err == nil {
			err = p.SetMulticastTTL(255)
		}
		if err == nil {
			err = p.SetMulticastLoopback(true)
		}
		if err != nil {
			conn.Close()
			return s, err
		}
		s.read = func(b []byte) (int, int, int, *net.UDPAddr, error) {
			n, cm, a, e := p.ReadFrom(b)
			if e != nil {
				return n, 0, 0, nil, e
			}
			peer, _ := a.(*net.UDPAddr)
			if cm == nil {
				return n, 0, 0, peer, nil
			}
			return n, cm.TTL, cm.IfIndex, peer, nil
		}
		s.write = func(b []byte) error {
			_, e := p.WriteTo(b, &ipv4.ControlMessage{IfIndex: iface.Index}, group)
			return e
		}
	}
	return s, nil
}

type interfaceResult struct {
	services         []Service
	queries, ignored int
	dropped          uint64
	limited          bool
	errors           []string
}

func browseInterface(ctx context.Context, iface net.Interface, o Options, publish func(interfaceResult)) interfaceResult {
	r := interfaceResult{services: []Service{}, errors: []string{}}
	sockets := []multicastSocket{}
	has4, has6 := false, false
	addrs, err := iface.Addrs()
	if err != nil {
		r.errors = append(r.errors, err.Error())
		return r
	}
	for _, address := range addrs {
		ip, _, e := net.ParseCIDR(address.String())
		if e == nil {
			if ip.To4() != nil {
				has4 = true
			} else {
				has6 = true
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		if v6 && (o.IPv4 || !has6) || !v6 && (o.IPv6 || !has4) {
			continue
		}
		s, e := openMulticast(iface, v6)
		if e != nil {
			r.errors = append(r.errors, fmt.Sprintf("%s IPv%d: %v", iface.Name, map[bool]int{true: 6, false: 4}[v6], e))
		} else {
			sockets = append(sockets, s)
		}
	}
	if len(sockets) == 0 {
		if len(r.errors) == 0 {
			r.errors = append(r.errors, iface.Name+": no address in selected family")
		}
		return r
	}
	return browseSockets(ctx, iface, o, sockets, r, publish)
}
func browseSockets(ctx context.Context, iface net.Interface, o Options, sockets []multicastSocket, r interfaceResult, publish func(interfaceResult)) interfaceResult {
	c := newCache(o.Types)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var dropped atomic.Uint64
	type datagram struct {
		bytes            []byte
		hop, index, port int
		err              error
	}
	packets := make(chan datagram, 64)
	for _, s := range sockets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buffer := make([]byte, 9001)
			for {
				n, hop, index, peer, err := s.read(buffer)
				if err != nil {
					select {
					case packets <- datagram{err: err}:
					case <-ctx.Done():
					}
					return
				}
				if peer == nil || peer.IP.IsUnspecified() || peer.IP.IsMulticast() {
					continue
				}
				packet := datagram{bytes: append([]byte(nil), buffer[:n]...), hop: hop, index: index, port: peer.Port}
				select {
				case packets <- packet:
				default:
					dropped.Add(1)
				}
			}
		}()
	}
	stop := context.AfterFunc(ctx, func() {
		for _, s := range sockets {
			s.close()
		}
	})
	defer func() {
		cancel()
		for _, s := range sockets {
			s.close()
		}
		stop()
		wg.Wait()
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	type sentQuestion struct {
		count int
		at    time.Time
	}
	sent := map[string]sentQuestion{}
	processed := 0
	sendQueries := func() {
		questions := []dns.Question{}
		now := time.Now()
		for _, q := range c.questions() {
			key := fmt.Sprintf("%s/%d", q.Name, q.Qtype)
			old := sent[key]
			if old.count >= 2 || old.count > 0 && now.Sub(old.at) < time.Second {
				continue
			}
			if len(sent) >= 256 && old.count == 0 {
				r.limited = true
				continue
			}
			questions = append(questions, q)
			sent[key] = sentQuestion{old.count + 1, now}
			if len(questions) == 20 {
				break
			}
		}
		if len(questions) == 0 {
			return
		}
		msg := &dns.Msg{Question: questions}
		wire, e := msg.Pack()
		if e != nil {
			r.errors = append(r.errors, e.Error())
			return
		}
		for _, s := range sockets {
			if e := s.write(wire); e != nil {
				r.errors = append(r.errors, e.Error())
			} else {
				r.queries++
			}
		}
	}
	sendQueries()
	lastUpdate := time.Time{}
	for ctx.Err() == nil && processed < 4096 {
		select {
		case <-ctx.Done():
		case <-ticker.C:
			sendQueries()
			if publish != nil && time.Since(lastUpdate) >= 200*time.Millisecond {
				snapshot := r
				snapshot.services = c.services(iface.Name, time.Now())
				snapshot.errors = append([]string(nil), r.errors...)
				snapshot.dropped = dropped.Load()
				snapshot.limited = snapshot.limited || c.limited
				publish(snapshot)
				lastUpdate = time.Now()
			}
		case packet := <-packets:
			if packet.err != nil {
				if ctx.Err() == nil {
					r.errors = append(r.errors, packet.err.Error())
				}
				cancel()
				continue
			}
			processed++
			if err := c.apply(packet.bytes, packet.port, packet.hop, packet.index, iface.Index, time.Now()); err != nil {
				r.ignored++
			}
		}
	}
	r.services = c.services(iface.Name, time.Now())
	r.limited = r.limited || c.limited || processed >= 4096
	r.dropped = dropped.Load()
	return r
}
func Run(parent context.Context, o Options, emit func(Result)) (r Result, err error) {
	r = Result{Services: []Service{}, Interfaces: []string{}, Errors: []string{}, Note: "mDNS/DNS-SD observations on selected interfaces; incomplete instances retain partial data. Silence does not establish that no services exist. TXT data is untrusted advertisement content."}
	if err = o.Validate(); err != nil {
		return r, err
	}
	if err = parent.Err(); err != nil {
		return r, err
	}
	if len(o.Types) == 0 {
		o.Types = []string{"_http._tcp", "_https._tcp", "_ssh._tcp", "_ipp._tcp"}
	}
	o.Types = append([]string(nil), o.Types...)
	for i, typ := range o.Types {
		o.Types[i], _ = ServiceType(typ)
	}
	ifaces, err := localnet.Interfaces(o.Interfaces, true)
	if err != nil {
		return r, err
	}
	ctx, cancel := context.WithTimeout(parent, o.Duration)
	defer cancel()
	type response struct {
		index  int
		result interfaceResult
		done   bool
	}
	results := make(chan response, len(ifaces))
	for i, iface := range ifaces {
		r.Interfaces = append(r.Interfaces, iface.Name)
		go func() {
			result := browseInterface(ctx, iface, o, func(row interfaceResult) {
				select {
				case results <- response{i, row, false}:
				default:
				}
			})
			results <- response{i, result, true}
		}()
	}
	rows := make([]interfaceResult, len(ifaces))
	finished := 0
	for finished < len(ifaces) {
		item := <-results
		if item.done {
			finished++
		}
		rows[item.index] = item.result
		r.Services = []Service{}
		r.Errors = []string{}
		r.Queries = 0
		r.Ignored = 0
		r.Dropped = 0
		r.Limited = false
		for _, row := range rows {
			r.Services = append(r.Services, row.services...)
			r.Errors = append(r.Errors, row.errors...)
			r.Queries += row.queries
			r.Ignored += row.ignored
			r.Dropped += row.dropped
			r.Limited = r.Limited || row.limited
		}
		sort.Slice(r.Services, func(i, j int) bool {
			if r.Services[i].Interface != r.Services[j].Interface {
				return r.Services[i].Interface < r.Services[j].Interface
			}
			return r.Services[i].Instance < r.Services[j].Instance
		})
		if len(r.Services) > 256 {
			r.Services = r.Services[:256]
			r.Limited = true
		}
		if emit != nil {
			snapshot := r
			snapshot.Services = append([]Service(nil), r.Services...)
			snapshot.Interfaces = append([]string(nil), r.Interfaces...)
			snapshot.Errors = append([]string(nil), r.Errors...)
			emit(snapshot)
		}
	}
	if parent.Err() != nil {
		return r, parent.Err()
	}
	if len(r.Errors) > 0 {
		return r, fmt.Errorf("one or more multicast interfaces failed; partial observations retained")
	}
	return r, nil
}
