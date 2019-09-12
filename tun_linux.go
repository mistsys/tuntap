package tuntap

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func createInterface(file *os.File, ifPattern string, kind DevKind) (string, error) {
	var req ifReq
	req.Flags = 0
	copy(req.Name[:15], ifPattern)
	switch kind {
	case DevTun:
		req.Flags |= iffTun
	case DevTap:
		req.Flags |= iffTap
	default:
		panic("Unknown interface type")
	}
	fd := file.Fd()
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TUNSETIFF), uintptr(unsafe.Pointer(&req)))

	//  calling File.Fd() changes file to be blocking, so we change it back so it continues to play well with the go runtime
	syscall.SetNonblock(int(fd), true)

	if err != 0 {
		return "", err
	}
	return strings.TrimRight(string(req.Name[:]), "\x00"), nil
}
