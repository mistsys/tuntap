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
#include <netinet6/nd6.h>
*/
import "C"

const flagTruncated = 0

const sizeofInt = C.sizeof_int
const sizeofTime = C.sizeof_time_t
const sizeofIfreq = C.sizeof_struct_ifreq
const sizeofIn6AliasReq = C.sizeof_struct_in6_aliasreq
const sizeofIn6SockAddr = C.sizeof_struct_sockaddr_in6
const sizeofIn6AddrLifetime = C.sizeof_struct_in6_addrlifetime
const sizeofNdIfInfo = C.sizeof_struct_nd_ifinfo

const (
	IFNAMSIZ                 = C.IFNAMSIZ
	ND6_INFINITE_LIFETIME    = C.ND6_INFINITE_LIFETIME
	SIOCDIFADDR_IN6          = C.SIOCDIFADDR_IN6
	SIOCAIFADDR_IN6          = C.SIOCAIFADDR_IN6
	ND6_IFF_DONT_SET_IFROUTE = C.ND6_IFF_DONT_SET_IFROUTE
	ND6_IFF_AUTO_LINKLOCAL   = C.ND6_IFF_AUTO_LINKLOCAL
	ND6_IFF_NO_RADR          = C.ND6_IFF_NO_RADR
	ND6_IFF_NO_PREFER_IFACE  = C.ND6_IFF_NO_PREFER_IFACE
	ND6_IFF_NO_DAD           = C.ND6_IFF_NO_DAD
	SIOCSIFINFO_FLAGS        = C.SIOCSIFINFO_FLAGS

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
