#ifndef _VIND_H_
#define _VIND_H_


#include <stdint.h>

#define FLAG_ACTIVE             0x00000001


#define NT_UNIXSRV          0x000001
#define NT_INETSRV          0x000010
#define NT_CLIENT           0x000100
#define NT_PROXY            0x001000
#define NT_VOD              0x010000
#define NT_SHARE            0x100000
//#define NT_CDN3RD           0x400000

#define NT_DNSSERVER        0x200000
#define NT_TCPSERVER        0x400000



#define NIDSIZE                 32
#define FIDSIZE                 16
#define LICENSESIZE             16
#define BLOCKSIZE               16384
#define MAXMSGSIZE              64*1024

#define NS_CONNECTING       1
#define NS_NORMAL           2
#define NS_INVALID          3
#define NS_ACTIVE           4
#define NS_DISUSE           5

#ifndef MAX
#define MAX(a, b)  ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b)  ((a) < (b) ? (a) : (b))
#endif

#define INT2PTR(x) (void *)(size_t)(x)
#define PTR2INT(x) (int)(size_t)(x)

#define MAXFILEDESC             100000

//List of NSMP commands

#define CMD_LOGIN_DNS_REQ       0x00000401
#define CMD_LOGIN_DNS_RES       0x80000401
#define CMD_REPORT_DNS_REQ      0x00000403
#define CMD_REPORT_DNS_RES      0x80000403

//Convert char to an integer
#define CTOI(c) (c <= '9' ? (c >= '0' && c <= '9' ? c-0x30: 0) \
        : (c >= 'a' && c <= 'f' ? c-0x57: 0))
//#define printf(FMT, ...) 
//include the common header files
//
#include "threads.h"

#endif  /* vind.h */

