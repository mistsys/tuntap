//-----------------------------------------------------------------------------
/*

Copyright Juniper Networks Inc. 2022-2022. All rights reserved.

*/
//-----------------------------------------------------------------------------

package tuntap

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

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
		if err = unix.IoctlSetPointerInt(fd, reqTUNSLMODE, 0); err != nil {
			return nil, errors.Wrapf(err, "tuntap: can't clear TUNSLMODE on %s", ifName)
		}
		if err = unix.IoctlSetPointerInt(fd, reqTUNSIFHEAD, 0); err != nil {
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

// AddAddress adds an IP address to the tunnel interface.
func (t *Interface) AddAddress(ip net.IP, subnet *net.IPNet) error {
	return errors.New("TODO")
}

// SetMTU sets the tunnel interface MTU size.
func (t *Interface) SetMTU(mtu int) error {
	return errors.New("TODO")
}

// Up sets the tunnel interface to the UP state.
func (t *Interface) Up() error {
	return errors.New("TODO")
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

//-----------------------------------------------------------------------------
