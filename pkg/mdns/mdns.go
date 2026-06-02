// Package mdns provides an optional, dependency-light multicast-DNS / DNS-SD
// responder so the SMB server advertises itself on the local link. It announces
// the standard Bonjour service types Finder browses for:
//
//   - _smb._tcp        the SMB service on the server's port (makes the server
//     appear under "Network" in macOS Finder, etc.)
//   - _device-info._tcp  a model string (only when a Time Machine share exists)
//   - _adisk._tcp      the Apple "auto disk" record advertising each Time
//     Machine share as a backup target, e.g.
//     sys=waMa=0,adVF=0x100
//     dk0=adVN=<share>,adVF=0x82
//
// It binds the mDNS group address (224.0.0.251:5353) with SO_REUSEADDR so it
// coexists with a system Avahi/mDNSResponder, announces on start, and answers
// matching queries. No external mDNS daemon is required.
package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

const (
	multicastIPv4 = "224.0.0.251"
	mdnsPort      = 5353
	defaultTTL    = 120 // seconds
)

// ShareInfo names a share to advertise and whether it is a Time Machine target.
type ShareInfo struct {
	Name        string
	TimeMachine bool
}

// Responder advertises the SMB server over mDNS / DNS-SD.
type Responder struct {
	instance string   // DNS-SD instance label (e.g. "GOSMB")
	host     string   // host name, e.g. "GOSMB.local."
	port     uint16   // SMB TCP port
	ips      []net.IP // IPv4 addresses advertised in A records
	model    string   // _device-info model (empty => no _device-info service)
	tmShares []string // Time Machine share names (for _adisk)
	debug    int

	answers []dnsmessage.Resource // every record we own

	conn    *ipv4.PacketConn
	ifaces  []net.Interface
	closeCh chan struct{}
	wg      sync.WaitGroup
}

// New builds a responder for the given server identity, SMB port, advertised
// IPs and shares. _adisk/_device-info records are emitted only when at least
// one share is a Time Machine target.
func New(serverName string, port int, ips []net.IP, shares []ShareInfo, debug int) *Responder {
	r := &Responder{
		instance: dnsLabel(serverName),
		port:     uint16(port),
		debug:    debug,
	}
	r.host = r.instance + ".local."
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			r.ips = append(r.ips, ip4)
		}
	}
	for _, s := range shares {
		if s.TimeMachine {
			r.tmShares = append(r.tmShares, s.Name)
		}
	}
	if len(r.tmShares) > 0 {
		// The model macOS shows for a Time Machine network target; matches the
		// AAPL model the SMB layer advertises and Apple's Time Capsule profile.
		r.model = "TimeCapsule6"
	}
	return r
}

// Start opens the multicast socket, joins the group on every usable interface,
// announces the records and begins answering queries.
func (r *Responder) Start() error {
	r.buildAnswers()

	lc := net.ListenConfig{Control: reuseControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("%s:%d", multicastIPv4, mdnsPort))
	if err != nil {
		return fmt.Errorf("mdns: listen: %w", err)
	}
	p := ipv4.NewPacketConn(pc)
	group := &net.UDPAddr{IP: net.ParseIP(multicastIPv4)}

	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if err := p.JoinGroup(&ifi, group); err == nil {
			r.ifaces = append(r.ifaces, ifi)
		}
	}
	if len(r.ifaces) == 0 {
		pc.Close()
		return fmt.Errorf("mdns: no multicast-capable interfaces")
	}
	_ = p.SetMulticastTTL(255)
	_ = p.SetMulticastLoopback(true)

	r.conn = p
	r.closeCh = make(chan struct{})
	r.wg.Add(2)
	go func() { defer r.wg.Done(); r.serve() }()
	go func() { defer r.wg.Done(); r.announce() }()

	if r.debug > 0 {
		svcs := []string{"_smb._tcp"}
		if r.model != "" {
			svcs = append(svcs, "_device-info._tcp")
		}
		if len(r.tmShares) > 0 {
			svcs = append(svcs, fmt.Sprintf("_adisk._tcp(%s)", strings.Join(r.tmShares, ",")))
		}
		log.Printf("[mDNS] advertising %s.local on %d iface(s): %s", r.instance, len(r.ifaces), strings.Join(svcs, " "))
	}
	return nil
}

// Stop sends goodbye records (TTL 0) and closes the socket.
func (r *Responder) Stop() {
	if r.closeCh == nil {
		return
	}
	close(r.closeCh)
	r.sendGoodbye()
	if r.conn != nil {
		r.conn.Close()
	}
	r.wg.Wait()
}

// buildAnswers precomputes every resource record we own.
func (r *Responder) buildAnswers() {
	var res []dnsmessage.Resource

	// A records for the host (unique => cache-flush).
	for _, ip := range r.ips {
		var a [4]byte
		copy(a[:], ip.To4())
		res = append(res, rr(r.host, dnsmessage.TypeA, true, &dnsmessage.AResource{A: a}))
	}

	var types []string

	// _smb._tcp — the SMB service itself.
	types = append(types, "_smb._tcp.local.")
	res = append(res, r.service("_smb._tcp.local.", r.port, nil)...)

	if r.model != "" {
		// _device-info._tcp — model string (port 0 per Apple convention).
		types = append(types, "_device-info._tcp.local.")
		res = append(res, r.service("_device-info._tcp.local.", 0, []string{"model=" + r.model})...)
	}

	if len(r.tmShares) > 0 {
		// _adisk._tcp — Time Machine auto-disk advertisement.
		txt := []string{"sys=waMa=0,adVF=0x100"}
		for i, name := range r.tmShares {
			txt = append(txt, fmt.Sprintf("dk%d=adVN=%s,adVF=0x82", i, name))
		}
		types = append(types, "_adisk._tcp.local.")
		res = append(res, r.service("_adisk._tcp.local.", r.port, txt)...)
	}

	// Service-type enumeration (_services._dns-sd._udp.local).
	for _, t := range types {
		res = append(res, rr("_services._dns-sd._udp.local.", dnsmessage.TypePTR, false,
			&dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(t)}))
	}

	r.answers = res
}

// service returns the PTR/SRV/TXT triple for one DNS-SD service type.
func (r *Responder) service(serviceType string, port uint16, txt []string) []dnsmessage.Resource {
	instance := r.instance + "." + serviceType // e.g. "GOSMB._smb._tcp.local."
	if len(txt) == 0 {
		txt = []string{""} // DNS-SD: a service with no keys still carries one empty TXT string
	}
	return []dnsmessage.Resource{
		rr(serviceType, dnsmessage.TypePTR, false, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(instance)}),
		rr(instance, dnsmessage.TypeSRV, true, &dnsmessage.SRVResource{Port: port, Target: dnsmessage.MustNewName(r.host)}),
		rr(instance, dnsmessage.TypeTXT, true, &dnsmessage.TXTResource{TXT: txt}),
	}
}

// serve answers incoming multicast queries.
func (r *Responder) serve() {
	buf := make([]byte, 9000)
	for {
		n, _, _, err := r.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-r.closeCh:
				return
			default:
				continue
			}
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil || msg.Header.Response {
			continue
		}
		ans := r.match(msg.Questions)
		if len(ans) == 0 {
			continue
		}
		out := dnsmessage.Message{
			Header:  dnsmessage.Header{Response: true, Authoritative: true},
			Answers: ans,
		}
		if b, err := out.Pack(); err == nil {
			r.send(b)
		}
	}
}

// match collects the records that answer the given questions, pulling in the
// SRV/TXT/A that accompany any matched service PTR so resolution completes in
// one round-trip.
func (r *Responder) match(questions []dnsmessage.Question) []dnsmessage.Resource {
	var out []dnsmessage.Resource
	seen := map[string]bool{}
	add := func(res dnsmessage.Resource) {
		key := res.Header.Name.String() + "/" + res.Header.Type.String()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, res)
	}
	for _, q := range questions {
		qname := strings.ToLower(q.Name.String())
		for _, a := range r.answers {
			if strings.ToLower(a.Header.Name.String()) != qname {
				continue
			}
			if q.Type != dnsmessage.TypeALL && q.Type != a.Header.Type {
				continue
			}
			add(a)
			// For a service PTR, also return the instance's SRV/TXT and host A.
			if ptr, ok := a.Body.(*dnsmessage.PTRResource); ok && a.Header.Type == dnsmessage.TypePTR {
				for _, extra := range r.recordsFor(ptr.PTR.String()) {
					add(extra)
				}
				for _, hostRec := range r.recordsFor(r.host) {
					add(hostRec)
				}
			}
		}
	}
	return out
}

// recordsFor returns every owned record whose name matches.
func (r *Responder) recordsFor(name string) []dnsmessage.Resource {
	var out []dnsmessage.Resource
	for _, a := range r.answers {
		if strings.EqualFold(a.Header.Name.String(), name) {
			out = append(out, a)
		}
	}
	return out
}

// announce multicasts the full record set a few times on start (RFC 6762 §8.3).
func (r *Responder) announce() {
	out := dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true, Authoritative: true},
		Answers: r.answers,
	}
	b, err := out.Pack()
	if err != nil {
		log.Printf("[mDNS] pack announcement: %v", err)
		return
	}
	for i := 0; i < 3; i++ {
		select {
		case <-r.closeCh:
			return
		default:
		}
		r.send(b)
		select {
		case <-r.closeCh:
			return
		case <-time.After(time.Second):
		}
	}
}

// sendGoodbye multicasts the records with TTL 0 so caches drop us promptly.
func (r *Responder) sendGoodbye() {
	if r.conn == nil || len(r.answers) == 0 {
		return
	}
	bye := make([]dnsmessage.Resource, len(r.answers))
	copy(bye, r.answers)
	for i := range bye {
		bye[i].Header.TTL = 0
	}
	out := dnsmessage.Message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: bye}
	if b, err := out.Pack(); err == nil {
		r.send(b)
	}
}

// send multicasts a packed message on every joined interface.
func (r *Responder) send(buf []byte) {
	dst := &net.UDPAddr{IP: net.ParseIP(multicastIPv4), Port: mdnsPort}
	for i := range r.ifaces {
		cm := &ipv4.ControlMessage{IfIndex: r.ifaces[i].Index}
		if _, err := r.conn.WriteTo(buf, cm, dst); err != nil && r.debug >= 5 {
			log.Printf("[mDNS] send on %s: %v", r.ifaces[i].Name, err)
		}
	}
}

func rr(name string, typ dnsmessage.Type, cacheFlush bool, body dnsmessage.ResourceBody) dnsmessage.Resource {
	class := dnsmessage.ClassINET
	if cacheFlush {
		class = dnsmessage.Class(0x8000 | uint16(dnsmessage.ClassINET))
	}
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  typ,
			Class: class,
			TTL:   defaultTTL,
		},
		Body: body,
	}
}

// dnsLabel reduces a server name to a safe single DNS label.
func dnsLabel(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '-' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			b.WriteRune(c)
		}
	}
	out := b.String()
	if out == "" {
		out = "SMBServer"
	}
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// reuseControl enables address/port reuse on the listening socket so the mDNS
// group port (5353) can be bound alongside a system responder (Avahi /
// mDNSResponder). The actual setsockopt is platform-specific (see
// reuse_unix.go / reuse_windows.go) so it is only applied where the OS supports
// it; on any other platform setReuseAddr is a no-op and binding simply proceeds
// without the option.
func reuseControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = setReuseAddr(fd)
	}); err != nil {
		return err
	}
	return serr
}
