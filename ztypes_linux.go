// Created by cgo -godefs - DO NOT EDIT
// cgo -godefs=true types_linux.go

package tuntap

const (
	flagTruncated = 0x1
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}
