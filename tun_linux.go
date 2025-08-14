//-----------------------------------------------------------------------------
/*

Copyright Juniper Networks Inc. 2015-2022. All rights reserved.

*/
//-----------------------------------------------------------------------------

package tuntap

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//-----------------------------------------------------------------------------

func createInterface(ifPattern string, kind DevKind) (*Interface, error) {
	// Note there is a complication because in go, if a device node is opened,
	// go sets it to use nonblocking I/O. However a /dev/net/tun doesn't work
	// with epoll until after the TUNSETIFF ioctl has been done. So we open
	// the unix fd directly, do the ioctl, then put the fd in nonblocking mode,
	// an then finally wrap it in a os.File, which will see the nonblocking mode
	// and add the fd to the pollable set, so later on when we Read() from it
	// blocked the calling thread in the kernel.
	// See
	//   https://github.com/golang/go/issues/30426
	// which got exposed in go 1.13 by the fix to
	//   https://github.com/golang/go/issues/30624

	const TUN = "/dev/net/tun"

	fd, err := unix.Open(TUN, os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "tuntap: Can't open %s", TUN)
	}

	var req ifReq
	copy(req.Name[:15], ifPattern)
	switch kind {
	case DevTun:
		req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	case DevTap:
		req.Flags = unix.IFF_TAP
	default:
		panic(fmt.Sprintf("tuntap: Unknown tuntap interface type %d", int(kind)))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return nil, errors.Wrapf(errno, "tuntap: Can't ioctl(TUNSETIFF) on %s", TUN)
	}
	ifName := string(req.Name[:])
	if idx := strings.IndexByte(ifName, 0); idx >= 0 {
		ifName = ifName[:idx]
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, errors.Wrapf(err, "tuntap: Can't set nonblocking mode on fd %q", TUN)
	}

	// now that we've done the ioctl and the fd is in nonblocking mode we can create an *os.File to wrap it,
	// and the fd will operate properly with go's runtime net poller/epoll(2).
	file := os.NewFile(uintptr(fd), TUN)

	return &Interface{ifName, file}, nil
}

//-----------------------------------------------------------------------------

// AddAddress adds an IP address to the tunnel interface.
func (t *Interface) AddAddress(ip net.IP, subnet *net.IPNet) error {
	iface, err := netlink.LinkByName(t.Name())
	if err != nil {
		return err
	}
	err = netlink.AddrAdd(iface, &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: subnet.Mask}})
	if err != nil {
		return err
	}
	return nil
}

// SetMTU sets the tunnel interface MTU size.
func (t *Interface) SetMTU(mtu int) error {
	iface, err := netlink.LinkByName(t.Name())
	if err != nil {
		return err
	}
	err = netlink.LinkSetMTU(iface, mtu)
	if err != nil {
		return err
	}
	return nil
}

// Up sets the tunnel interface to the UP state.
func (t *Interface) Up() error {
	iface, err := netlink.LinkByName(t.Name())
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(iface)
	if err != nil {
		return err
	}
	return nil
}

func boolToByte(x bool) byte {
	if x {
		return 1
	}
	return 0
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func (t *Interface) IPv6SLAAC(ctrl bool) error {
	k := boolToByte(ctrl)
	return ioutil.WriteFile("/proc/sys/net/ipv6/conf/"+t.Name()+"/autoconf", []byte{k}, 0)
}

// IPv6Forwarding enables/disables ipv6 forwarding for the interface.
func (t *Interface) IPv6Forwarding(ctrl bool) error {
	k := boolToByte(ctrl)
	return ioutil.WriteFile("/proc/sys/net/ipv6/conf/"+t.Name()+"/forwarding", []byte{k}, 0)
}

// IPv6 enables/disable ipv6 for the interface.
func (t *Interface) IPv6(ctrl bool) error {
	k := boolToByte(!ctrl)
	return ioutil.WriteFile("/proc/sys/net/ipv6/conf/"+t.Name()+"/disable_ipv6", []byte{k}, 0)
}

// GetAddrList returns the IP addresses (as bytes) associated with the interface.
func (t *Interface) GetAddrList() ([][]byte, error) {
	iface, err := netlink.LinkByName(t.Name())
	if err != nil {
		return nil, err
	}
	nladdrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	addrs := [][]byte{}
	for _, ipn := range nladdrs {
		ip := ipn.IP
		if ip.To4().To16().Equal(ip) {
			// it's an IPv4 address- just use the 4 bytes
			ip = ip.To4()
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

//-----------------------------------------------------------------------------
