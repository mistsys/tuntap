//go:build ignore

// run "bash ./mkdefs.sh"

package tuntap

/*
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_tun.h>
*/
import "C"

const flagTruncated = 0

const (
	reqTUNSDEBUG  = C.TUNSDEBUG
	reqTUNGDEBUG  = C.TUNGDEBUG
	reqTUNSIFINFO = C.TUNSIFINFO
	reqTUNGIFINFO = C.TUNGIFINFO
	reqTUNSLMODE  = C.TUNSLMODE
	//reqTUNGIFNAME = C.TUNGIFNAME
	reqTUNSIFMODE = C.TUNSIFMODE
	reqTUNSIFPID  = C.TUNSIFPID
	reqTUNSIFHEAD = C.TUNSIFHEAD
	reqTUNGIFHEAD = C.TUNGIFHEAD
)
