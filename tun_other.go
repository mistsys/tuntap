// +build !linux

package tuntap

const flagTruncated = 0

func createInterface(ifPattern string, kind DevKind) (*Interface, error) {
	panic("tuntap: Not implemented on this platform")
}
