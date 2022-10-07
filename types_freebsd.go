//go:build ignore

// run "bash ./mkdefs.sh"

package tuntap

/*
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_tun.h>
#include <net/if_tap.h>
*/
import "C"

const flagTruncated = 0

const (
	// tun
	reqTUNSDEBUG  = C.TUNSDEBUG
	reqTUNGDEBUG  = C.TUNGDEBUG
	eqTUNSIFINFO  = C.TUNSIFINFO
	reqTUNGIFINFO = C.TUNGIFINFO
	reqTUNSLMODE  = C.TUNSLMODE
	//reqTUNGIFNAME = C.TUNGIFNAME
	reqTUNSIFMODE = C.TUNSIFMODE
	reqTUNSIFPID  = C.TUNSIFPID
	reqTUNSIFHEAD = C.TUNSIFHEAD
	reqTUNGIFHEAD = C.TUNGIFHEAD
	// tap
	reqTAPSDEBUG   = C.TAPSDEBUG
	reqTAPGDEBUG   = C.TAPGDEBUG
	reqTAPSIFINFO  = C.TAPSIFINFO
	reqTAPGIFINFO  = C.TAPGIFINFO
	//reqTAPGIFNAME  = C.TAPGIFNAME
	reqTAPSVNETHDR = C.TAPSVNETHDR
	reqTAPGVNETHDR = C.TAPGVNETHDR
)
