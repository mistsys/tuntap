//-----------------------------------------------------------------------------
/*

Copyright Juniper Networks Inc. 2022-2022. All rights reserved.

*/
//-----------------------------------------------------------------------------

package tuntap

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

//-----------------------------------------------------------------------------

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)
	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

//-----------------------------------------------------------------------------

func createInterface(ifPattern string, kind DevKind) (*Interface, error) {

	if kind != DevTun && kind != DevTap {
		return nil, fmt.Errorf("tuntap: unsupported tuntap interface type %d", int(kind))
	}

	ifName := "/dev/" + ifPattern
	var fd int
	var err error

	if strings.Contains(ifName, "%d") {
		for i := 0; i < 256; i++ {
			fd, err = unix.Open(fmt.Sprintf(ifName, i), os.O_RDWR, 0)
			if err == nil {
				ifName = fmt.Sprintf(ifName, i)
				break
			}
		}
	} else {
		fd, err = unix.Open(ifName, os.O_RDWR, 0)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "tuntap: can't open %s", ifName)
	}

	if kind == DevTun {
		// Disable extended modes
		if err = unix.IoctlSetPointerInt(fd, TUNSLMODE, 0); err != nil {
			return nil, errors.Wrapf(err, "tuntap: can't clear TUNSLMODE on %s", ifName)
		}
		if err = unix.IoctlSetPointerInt(fd, TUNSIFHEAD, 0); err != nil {
			return nil, errors.Wrapf(err, "tuntap: can't clear TUNSIFHEAD on %s", ifName)
		}
	}

	if kind == DevTap {
		// TODO
	}

	file := os.NewFile(uintptr(fd), ifName)
	return &Interface{ifName, file}, nil
}

//-----------------------------------------------------------------------------

func ioctl(fd int, req uint, arg uintptr) error {
	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if err != 0 {
		return fmt.Errorf("(%d) %s", err, unix.ErrnoName(err))
	}
	return nil
}

func isIPv4(ip net.IP) bool {
	return ip.To4().To16().Equal(ip)
}

func in6SockAddr(buf []byte, ip net.IP) {
	if ip == nil {
		return
	}
	// uint8 sin6_len, length of this struct
	buf[0] = sizeofIn6SockAddr
	// uint8 sin6_family, AF_INET6
	buf[1] = unix.AF_INET6
	// uint16 sin6_port, Transport layer port #
	nativeEndian.PutUint16(buf[2:], 0)
	// uint32 sin6_flowinfo, IP6 flow information
	nativeEndian.PutUint32(buf[4:], 0)
	// [16]byte sin6_addr, IP6 address
	copy(buf[8:], ip)
	// uint32 sin6_scope_id, scope zone index
	nativeEndian.PutUint32(buf[24:], 0)
}

func in6AddrLifetime(buf []byte) {
	ofs := 0
	// time_t ia6t_expire, valid lifetime expiration time
	ofs += sizeofTime
	// time_t ia6t_preferred, preferred lifetime expiration time
	ofs += sizeofTime
	// u_int32_t ia6t_vltime, valid lifetime
	nativeEndian.PutUint32(buf[ofs:], ND6_INFINITE_LIFETIME)
	ofs += 4
	// u_int32_t ia6t_pltime, prefix lifetime
	nativeEndian.PutUint32(buf[ofs:], ND6_INFINITE_LIFETIME)
	ofs += 4
}

// AddAddress adds an IP address to the tunnel interface.
func (t *Interface) AddAddress(ip net.IP, subnet *net.IPNet) error {

	if isIPv4(ip) {
		return errors.New("ipv4 addresses not supported")
	}

	// build the in6_aliasreq structure
	var ifra [sizeofIn6AliasReq]byte

	ifName := path.Base(t.Name())
	copy(ifra[:IFNAMSIZ], []byte(ifName))
	ofs := IFNAMSIZ
	// ifra_addr
	in6SockAddr(ifra[ofs:], ip)
	ofs += sizeofIn6SockAddr
	// ifra_dstaddr
	in6SockAddr(ifra[ofs:], nil)
	ofs += sizeofIn6SockAddr
	// ifra_prefixmask
	in6SockAddr(ifra[ofs:], net.IP(subnet.Mask))
	ofs += sizeofIn6SockAddr
	// ifra_flags
	nativeEndian.PutUint32(ifra[ofs:], 0)
	ofs += sizeofInt
	// ifra_lifetime
	in6AddrLifetime(ifra[ofs:])
	ofs += sizeofIn6AddrLifetime
	// ifra_vhid
	nativeEndian.PutUint32(ifra[ofs:], 0)
	ofs += sizeofInt

	// do the ioctl
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}

	err = ioctl(fd, SIOCAIFADDR_IN6, uintptr(unsafe.Pointer(&ifra)))
	if err != nil {
		return err
	}

	return unix.Close(fd)

}

// SetMTU sets the tunnel interface MTU size.
func (t *Interface) SetMTU(mtu int) error {
	// build the ifreq structure
	var ifreq [sizeofIfreq]byte
	ifName := path.Base(t.Name())
	copy(ifreq[:IFNAMSIZ], []byte(ifName))
	nativeEndian.PutUint32(ifreq[IFNAMSIZ:], uint32(mtu)) // sizeof(int) == 4
	// do the ioctl
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// Up sets the tunnel interface to the UP state.
func (t *Interface) Up() error {
	// build the ifreq structure
	var ifreq [sizeofIfreq]byte
	ifName := path.Base(t.Name())
	copy(ifreq[:IFNAMSIZ], []byte(ifName))
	// get the interface flags
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifreq)))
	if err != nil {
		return err
	}
	// set the interface flags
	flagsLo := nativeEndian.Uint16(ifreq[IFNAMSIZ:])
	flagsLo |= unix.IFF_UP
	nativeEndian.PutUint16(ifreq[IFNAMSIZ:], flagsLo)
	err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifreq)))
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func (t *Interface) IPv6SLAAC(ctrl bool) error {
	return errors.New("TODO")
}

// IPv6Forwarding enables/disables ipv6 forwarding for the interface.
func (t *Interface) IPv6Forwarding(ctrl bool) error {
	return errors.New("TODO")
}

// IPv6 enables/disable ipv6 for the interface.
func (t *Interface) IPv6(ctrl bool) error {
	return errors.New("TODO")
}

// GetAddrList returns the IP addresses (as bytes) associated with the interface.
func (t *Interface) GetAddrList() ([][]byte, error) {
	// get the net.Interface using the tunnel name
	itf, err := net.InterfaceByName(path.Base(t.Name()))
	if err != nil {
		return nil, err
	}
	// get the ip address list for the interface
	addrList, err := itf.Addrs()
	if err != nil {
		return nil, err
	}
	// parse the address strings and convert to bytes
	addrs := [][]byte{}
	for _, addr := range addrList {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		if isIPv4(ip) {
			// it's an IPv4 address- just use the 4 bytes
			ip = ip.To4()
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

//-----------------------------------------------------------------------------
