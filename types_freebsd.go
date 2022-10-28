//go:build ignore

// run "bash ./mkdefs.sh"

package tuntap

/*
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if_tun.h>
#include <net/if_tap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
*/
import "C"

const flagTruncated = 0
const ifreqSize = C.sizeof_struct_ifreq
const ifNameSize = C.IFNAMSIZ
const in6AliasReqSize = C.sizeof_struct_in6_aliasreq
const in6SockAddrSize = C.sizeof_struct_sockaddr_in6
const in6AddrLifetime = C.sizeof_struct_in6_addrlifetime
const sizeofInt = C.sizeof_int

const (
	SIOCDIFADDR_IN6 = C.SIOCDIFADDR_IN6
	SIOCAIFADDR_IN6 = C.SIOCAIFADDR_IN6

	// tun
	TUNSDEBUG  = C.TUNSDEBUG
	TUNGDEBUG  = C.TUNGDEBUG
	TUNSIFINFO = C.TUNSIFINFO
	TUNGIFINFO = C.TUNGIFINFO
	TUNSLMODE  = C.TUNSLMODE
	//TUNGIFNAME = C.TUNGIFNAME
	TUNSIFMODE = C.TUNSIFMODE
	TUNSIFPID  = C.TUNSIFPID
	TUNSIFHEAD = C.TUNSIFHEAD
	TUNGIFHEAD = C.TUNGIFHEAD
	// tap
	TAPSDEBUG  = C.TAPSDEBUG
	TAPGDEBUG  = C.TAPGDEBUG
	TAPSIFINFO = C.TAPSIFINFO
	TAPGIFINFO = C.TAPGIFINFO
	//TAPGIFNAME  = C.TAPGIFNAME
	TAPSVNETHDR = C.TAPSVNETHDR
	TAPGVNETHDR = C.TAPGVNETHDR
)
