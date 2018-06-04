
#ifndef _MSG_H
#define _MSG_H
#include <time.h>
#include <stdint.h>

typedef struct dnsmsg_s {
    uint32_t  size;
    time_t    send_time;
    int       resends;

    int       forward;
    uint8_t   dst[7];
    int       origin;
    int       reserved;

#pragma pack(1)
    struct _dns_pdu {
        //Message header
        uint32_t len;  
        uint32_t cmd;  
        uint32_t seq;

        //Message body
        union {
            struct { /* CMD_STARTUP */
                uint8_t   nodeid[8];
                uint32_t  type;
                uint32_t  mask;
                uint32_t  ip;
                uint16_t  isp;
                uint8_t   reserved[8];
            } startup_req;
            #define startupreq  body.startup_req
            struct { /* CMD_STARTUP_RESP */
                uint8_t   status;
                uint8_t   reserved[8];
            } startup_res;
            #define startupres  body.startup_res
            #define statusres   body.startup_res

            struct {
                uint32_t  links;
                uint32_t  width;
                uint16_t  cpus;
                uint16_t  memorys;
                uint8_t   reserved[8];

            } status_req;
            #define statusreq  body.status_req
        } body;
    }pdu;
#pragma pack()

} dnsmsg_t;

#endif /* msg.h */
