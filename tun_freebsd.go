package tuntap

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func createInterface(ifPattern string, kind DevKind) (*Interface, error) {

	if kind != DevTun {
		if kind == DevTap {
			return nil, fmt.Errorf("tuntap: tap devices not supported")
		}
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

	// Disable extended modes
	if err = unix.IoctlSetPointerInt(fd, reqTUNSLMODE, 0); err != nil {
		return nil, errors.Wrapf(err, "tuntap: can't clear TUNSLMODE on %s", ifName)
	}
	if err = unix.IoctlSetPointerInt(fd, reqTUNSIFHEAD, 0); err != nil {
		return nil, errors.Wrapf(err, "tuntap: can't clear TUNSIFHEAD on %s", ifName)
	}

	file := os.NewFile(uintptr(fd), ifName)
	return &Interface{ifName, file}, nil
}
