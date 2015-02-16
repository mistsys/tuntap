// +build !linux

package tuntap

import (
	"os"
)

const flagTruncated = 0

func createInterface(f *os.File, ifPattern string, kind DevKind) (string, error) {
	panic("Not implemented on this platform")
}
