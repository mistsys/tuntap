package tuntap

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

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

	fd, err := unix.Open(TUN, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "tuntap: Can't open %s", TUN)
	}

	var req ifReq
	copy(req.Name[:15], ifPattern)
	switch kind {
	case DevTun:
		req.Flags = unix.IFF_TUN
	case DevTap:
		req.Flags = unix.IFF_TAP
	default:
		panic(fmt.Sprintf("tuntamp: Unknown tuntap interface type %d", int(kind)))
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return nil, errors.Wrapf(errno, "tuncap: Can't ioctl(TUNSETIFF) on %s", TUN)
	}
	ifName := string(req.Name[:])
	if idx := strings.IndexByte(ifName, 0); idx >= 0 {
		ifName = ifName[:idx]
	}

	err = unix.SetNonblock(fd, true)
	if err != nil {
		unix.Close(fd)
		return nil, errors.Wrapf(err, "tuncap: Can't set nonblocking mode on fd %q", TUN)
	}

	// now that we've done the ioctl and the fd is in nonblocking mode we can create an *os.File to wrap it,
	// and the fd will operate properly with go's runtime net poller/epoll(2).
	file := os.NewFile(uintptr(fd), TUN)

	return &Interface{ifName, file}, nil
}
