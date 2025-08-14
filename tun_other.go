//go:build !linux && !freebsd

package tuntap

import (
	"net"
)

func createInterface(ifPattern string, kind DevKind) (*Interface, error) {
	panic("tuntap: Not implemented on this platform")
}

// IPv6SLAAC enables/disables stateless address auto-configuration (SLAAC) for the interface.
func (t *Interface) IPv6SLAAC(ctrl bool) error {
	panic("tuntap: Not implemented on this platform")
}

// IPv6Forwarding enables/disables ipv6 forwarding for the interface.
func (t *Interface) IPv6Forwarding(ctrl bool) error {
	panic("tuntap: Not implemented on this platform")
}

// IPv6 enables/disable ipv6 for the interface.
func (t *Interface) IPv6(ctrl bool) error {
	panic("tuntap: Not implemented on this platform")
}

// AddAddress adds an IP address to the tunnel interface.
func (t *Interface) AddAddress(ip net.IP, subnet *net.IPNet) error {
	panic("tuntap: Not implemented on this platform")
}

// SetMTU sets the tunnel interface MTU size.
func (t *Interface) SetMTU(mtu int) error {
	panic("tuntap: Not implemented on this platform")
}

// Up sets the tunnel interface to the UP state.
func (t *Interface) Up() error {
	panic("tuntap: Not implemented on this platform")
}

// GetAddrList returns the IP addresses (as bytes) associated with the interface.
func (t *Interface) GetAddrList() ([][]byte, error) {
	panic("tuntap: Not implemented on this platform")
}
