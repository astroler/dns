/*************************************************************************
  File Name   :    obj.h
Author      :    sunzg
Mail        :    suclinux@gmail.com
Created Time:    2016年11月01日 星期二 14时56分12秒
 *************************************************************************/

#ifndef __obj_h
#define __obj_h

#include "vind.h"
#include "msg.h"
#include "arch.h"
//#include "store.h"

#include <pthread.h>
#include <gdsl.h>
#include <hiredis/hiredis.h>

#define CMDLEN  1256

#define RES_NUM     4
#define NAME_KEY_LEN 20

#define IPLEN   16

typedef struct 
{
    void            *ev;
    void            *wk;
    void            *ca;
} wobj_t;

typedef struct
{
    void            *evbase;
    gdsl_queue_t     registration;
    pthread_mutex_t  reglock;

    int              notify_send;
    int              notify_recv;

    wobj_t          *notify_event;
    uint32_t         flag;
    pthread_t        thread;
} worker_t;

typedef struct
{
    uint8_t          nid[NIDSIZE+1];
    uint32_t          nodetype;

    time_t           interaction;
    int              fd;
    int              flag;

    int              type;
    int              isp;
    char             host[16];
    uint16_t         port;


    gdsl_list_t      recv_queue;
    gdsl_list_t      send_queue;

    uint8_t         *recv_incomplete;
    int              received;
    int              recvnum;
    int              datalen;
    //Being sending and number of bytes sent
    uint8_t         *send_incomplete;
    int              besent;
    int              sentsum;
    int              magic;

    pthread_mutex_t  access_lock;
    uint32_t         status;

    void            *core;
    //event
    wobj_t          *pdev;
    //void            *pdev;
    struct timeval   tv;
} caccess_t;
typedef struct {
    uint8_t     id[9];
    uint8_t     rdbhost[16];
    int         rdbport;
    int         rdbc;
    uint8_t     rdbkey[128];
    int         listen;
	uint16_t    nameport;
    uint16_t    httpport;
} config_t;

typedef struct {
    // node id 8 bytes.
    char          id[9];
    // node ip address.
    char          ip[16];
    // node serve port.
    short         port;

    // interactin probe handle, http get info.
    char          url[256];
    // 0 unuse, 1 inuse.
    uint8_t       inuse;
    // node status 0 in serve, 1 unserve.
    uint16_t      status;
    // last update timestamp.
    uint64_t      timekey;
    // probe type 1 survival probe, 2 interaction probe, 3 none probe.
    uint32_t      probekey;
    // weights in guides, default 0.
    int           weights;
    // node probe cycle, use second.
    int           cycle;

    // threshold, M
    uint16_t      threshold;
    uint16_t      cputilization;
    uint16_t      memorylization;
} snode_t;



typedef struct {
    
    uint32_t      status;
    // update time 
    time_t      time;
    // node id 8 bytes.
    uint8_t       id[NIDSIZE];
    // node serve isp
    char          *isp;
    // node Business tye
    uint32_t      btype;
    // node ip code
    char          *ip_code; 
    // node ip address.
    char          *ip;
    // node serve port.
    short         port;

    // interactin probe handle, http get info.
    char          *url;
    // Maximum link
    uint32_t      links;
    // The largest bandwidth
    uint32_t      width;
    // CPU usage percentage
    uint32_t      cpus;
    // Memorys usage percentage
    uint32_t      memorys;
    // 0 unuse, 1 inuse.
    uint32_t       inuse;
    // weights in guides, default 0.
    uint8_t       weights;
    // probe type 1 tcp, 2 http, 3 no need.
    uint8_t       ptype;
    // update cycle
    uint16_t      cycle;
    // group address
    void          *store;
} node_t;

typedef struct {
    // 1 A , 2 CNAME, 3 NS, 4 revers proxy.
    uint32_t      name_type;
    
    // bussiness type.
    uint32_t      btype;
    // 0 unuse, 1 inuse.
    uint8_t       inuse;
    // Domain name.
    char         *name;
    time_t        time;
} name_t;

typedef struct {
    // result ip`s num.
    uint32_t    num;
    // select guiding method 
    // value 1 is method one, 2 is method two , anynum is method 3 
    uint32_t    gtype;
    uint32_t    ttl;
} type_t;

typedef struct {
    // Business status, 0 unuse, 1 inuse.
    int           inuse;
    // Domain keyworld.
    char          *name_key;
    // use save to name`s value
    char          *domain_tmp;
    
    name_t        *name_tmp;
    node_t        *node_tmp;

    // use save to id
    //uint8_t       id_tmp[NIDSIZE];
    // bussiness type 
    uint32_t      btype;
    uint32_t      type;
    // Subname count.
    int           count;
    int           ttl;
    // type struct
    type_t        t_attribute; 
    // Subname list.
    gdsl_list_t   names;
    // Probe node list.
    gdsl_list_t   nodes;
    // save res cmd "keys cdn:dns:business:2:*"
    gdsl_list_t   name_keys;
    gdsl_list_t   node_keys;
    time_t        uptime;
} ngroup_t;

typedef struct store_s {
    // Stort wether in service, 0 not ready, 1 ready.
    uint8_t        status;
    // Keyword for hash, 0 use fentity to guide, sentity update info.
    // 1 use sentity to guide, fentity update info.
    int        keypad;
    //node count
    uint32_t       count;
    ngroup_t*      group_tmp;     
    // Mutex var, a eime one is update data, second use to guide.
    int            fen_status;
    gdsl_list_t    fentity;
    int            sen_status;
    gdsl_list_t    sentity;

#if 0
    void*        (*inuse)    (void *);
    char*        (*map)      (void *, const char *);
    uint32_t     (*banlance) (void *, uint32_t *, uint32_t *);
#endif

    threadpool_t *pools;

    void         *pvind;
} store_t;

typedef struct {
        char        *code;
        char        *isp;
} code_isp_t;

typedef struct
{
    uint8_t          nodeid[NIDSIZE+1];

    config_t        *pconf; 

    redisContext    *rdbconn;
    pthread_mutex_t  rdlock;


    void            *logic;

    store_t         *store;

    threadpool_t    *pools; 
    /* All accesses */
    gdsl_hash_t      accesses;
    /* Node with type in group */
    gdsl_hash_t      groups;
    gdsl_queue_t     registration;

    pthread_mutex_t  cnlock;
    pthread_mutex_t  objlock;
    pthread_mutex_t  reglock;


    worker_t        *workers[4];
    
} content_t;

typedef struct
{
    uint8_t          nid[NIDSIZE+1];
    uint8_t          addr[16];
    uint32_t         ip;
    uint16_t         port;
    int              type;

    uint32_t         status;

    uint32_t         links;
    uint32_t         width;
    uint16_t         cpus;
    uint16_t         memorys;


    uint8_t          inuse;

    caccess_t       *access;
} inode_t;

typedef struct {
    int              group;
    int              immediate;
    int              count;

    gdsl_list_t      childs;
} cgroup_t;

/* core.c */
    content_t *
content_init(content_t *cn, const char *name, const char *config);
    void
free_content(content_t *cn);

    void
release_content(content_t *cn);

    void 
wevent_active(content_t *cn, caccess_t *ca);

    void
core_dispatch(content_t *cn, caccess_t *ca);

/* access.c */
    caccess_t *
new_caccess(void *cn, int fd, const char *host, int port, int type);

    void
release_caccess(caccess_t *ca);
    cgroup_t *
cgroup_create (int group, int immediate);
    void 
cgroup_destroy (cgroup_t *cg);

    inode_t *
cnode_create(const char *nid, uint32_t uip, int type);
    void
cnode_destroy(inode_t *nd);
/* msg.c */
    dnsmsg_t *
new_msg(int size);
    void
free_msg(dnsmsg_t *msg);

static int oneStep (void *e, gdsl_location_t l, void *arg);

#endif
