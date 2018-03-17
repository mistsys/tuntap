// Package tuntap provides a portable interface to create and use
// TUN/TAP virtual network interfaces.
//
// Note that while this package lets you create the interface and pass
// packets to/from it, it does not provide an API to configure the
// interface. Interface configuration is a very large topic and should
// be dealt with separately.
package tuntap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"unsafe"
)

type DevKind int

const (
	// Receive/send layer routable 3 packets (IP, IPv6...). Notably,
	// you don't receive link-local multicast with this interface
	// type.
	DevTun DevKind = iota
	// Receive/send Ethernet II frames. You receive all packets that
	// would be visible on an Ethernet link, including broadcast and
	// multicast traffic.
	DevTap
)

const (
	// various ethernet protocols, using the same names as linux does
	ETH_P_IP   uint16 = 0x0800
	ETH_P_IPV6 uint16 = 0x86dd
)

type Packet struct {
	// The raw bytes of the Ethernet payload (for DevTun) or the full
	// Ethernet frame (for DevTap).
	Body []byte
	// The Ethernet type of the packet. Commonly seen values are
	// 0x8000 for IPv4 and 0x86dd for IPv6.
	Protocol uint16
	// True if the packet was too large to be read completely.
	Truncated bool
}

type Interface struct {
	name string
	file *os.File
}

// Disconnect from the tun/tap interface.
//
// If the interface isn't configured to be persistent, it is
// immediately destroyed by the kernel.
func (t *Interface) Close() error {
	return t.file.Close()
}

// The name of the interface. May be different from the name given to
// Open(), if the latter was a pattern.
func (t *Interface) Name() string {
	return t.name
}

// Read a single packet from the kernel.
func (t *Interface) ReadPacket(buffer []byte) (Packet, error) {
	n, err := t.file.Read(buffer)
	if err != nil {
		return Packet{}, err
	}

	pkt := Packet{Body: buffer[4:n]}
	pkt.Protocol = binary.BigEndian.Uint16(buffer[2:4])
	flags := *(*uint16)(unsafe.Pointer(&buffer[0]))
	pkt.Truncated = (flags&flagTruncated != 0)
	return pkt, nil
}

// free 1600 byte buffers
var buffers = sync.Pool{New: func() interface{} { return new([1600]byte) }}

// Send a single packet to the kernel.
func (t *Interface) WritePacket(pkt Packet) error {
	// If only we had writev(), I could do zero-copy here...
	// At least we will manage the buffer so we don't cause the GC extra work
	buf := buffers.Get().(*[1600]byte)

	binary.BigEndian.PutUint16(buf[2:4], pkt.Protocol)
	copy(buf[4:], pkt.Body)
	n := 4 + len(pkt.Body)
	a, err := t.file.Write(buf[:n])
	buffers.Put(buf)
	if err != nil {
		return err
	}
	if a != n {
		return io.ErrShortWrite
	}
	return nil
}

// Open connects to the specified tun/tap interface.
//
// If the specified device has been configured as persistent, this
// simply looks like a "cable connected" event to observers of the
// interface. Otherwise, the interface is created out of thin air.
//
// ifPattern can be an exact interface name, e.g. "tun42", or a
// pattern containing one %d format specifier, e.g. "tun%d". In the
// latter case, the kernel will select an available interface name and
// create it.
//
// Returns a TunTap object with channels to send/receive packets, or
// nil and an error if connecting to the interface failed.
func Open(ifPattern string, kind DevKind) (*Interface, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifName, err := createInterface(file, ifPattern, kind)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &Interface{ifName, file}, nil
}

// query parts of Packets
// NOTE: think whether this wouldn't be better done with a interface and two implemenations, one for each protocol

// return the destination IP
func (p *Packet) DIP() net.IP {
	switch p.Protocol {
	case ETH_P_IP:
		return net.IP(p.Body[16:20])
	case ETH_P_IPV6:
		return net.IP(p.Body[24:40])
	}
	return net.IP{}
}

// return the source IP
func (p *Packet) SIP() net.IP {
	switch p.Protocol {
	case ETH_P_IP:
		return net.IP(p.Body[12:16])
	case ETH_P_IPV6:
		return net.IP(p.Body[8:24])
	}
	return net.IP{}
}

// return the 6-bit DSCP field
func (p *Packet) DSCP() int {
	switch p.Protocol {
	case ETH_P_IP:
		return int(p.Body[1] >> 2)
	case ETH_P_IPV6:
		return int((p.Body[0]&0x0f)<<2 | (p.Body[1]&0xf0)>>6)
	}
	return 0
}

// return the IP protocol, the offset to the IP datagram payload, and true if the payload is from a non-first fragment
// returns 0,0,false if parsing fails or the IPv6 header 59 (no-next-header) is found
func (p *Packet) IPProto() (uint8, int, bool) {
	fragment := false
	switch p.Protocol {
	case ETH_P_IP:
		fragment = (p.Body[6]&0x1f)|p.Body[7] != 0
		return p.Body[9], int(p.Body[0]&0xf) << 2, fragment
	case ETH_P_IPV6:
		// finding the IP protocol in the case of IPv6 is slightly messy. we have to scan down the IPv6 header chain and find the last one
		next := p.Body[6]
		at := 40
		for true {
			if at+4 > len(p.Body) {
				// off the end of the body. there must have been a garbage value somewhere
				return 0, 0, false
			}
			switch next {
			case 0, // hop-by-hop
				43, // routing extension
				60: // destination options extension
				// skip over this header and continue to the next one
				next = p.Body[at]
				at += 8 + int(p.Body[at+1])*8
			case 44: // fragment extension
				next = p.Body[at]
				at += 8
				fragment = p.Body[at+2]|(p.Body[at+3]&0xf8) != 0
			case 51: // AH header (it is likely that the next proto is ESP, but just in case it isn't we might as well decode it)
				next = p.Body[at]
				at += 8 + int(p.Body[at+1])*4 // note unlike most IPv6 headers the length of AH is in 4-byte units
			case 59: // no next header
				return 0, len(p.Body), fragment
			default:
				return next, at, fragment
			}
		}
	}
	return 0, 0, false
}

// returns ipproto, icmp type, icmp code, if this is an ICMP packet, or 0,_,_ if it isn't
func (p *Packet) ICMPType() (int, int, int) {
	proto, at, frag := p.IPProto()
	if !frag {
		switch proto {
		case 1: // IPv4 ICMP
			if at+4 <= len(p.Body) {
				return 1, int(p.Body[at]), int(p.Body[at+1])
			}
		case 58: // ICMP6
			// the header is identical in layout, but the values of the fields are very different
			if at+4 <= len(p.Body) {
				return 58, int(p.Body[at]), int(p.Body[at+1])
			}
		}
	}
	return 0, 0, 0
}

func (p *Packet) String() string {
	s := fmt.Sprintf("%v -> %v", p.SIP(), p.DIP())
	dscp := p.DSCP()
	if dscp != 0 {
		s += ", DSCP " + strconv.Itoa(dscp)
	}
	return s
}
