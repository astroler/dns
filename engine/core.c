/*************************************************************************
  File Name   :    engine/core.c
Author      :    sunzg
Mail        :    suclinux@gmail.com
Created Time:    2016年11月01日 星期二 16时58分47秒
 *************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include <gdsl.h>
#include <event.h>
#include <evhttp.h>
#include <evdns.h>

#include "obj.h"
#include "msg.h"
#include "redis.h"
#include "threads.h"
#include "probe.h"

    static 
config_t *new_config(const char *file);
    void
free_content(content_t *cn);
    int 
vindns_create(content_t *cn, short port);
    caccess_t *
vind_server(content_t *cn, const char *host, int port);
    void
core_cmd_login(content_t *cn, caccess_t *ca, dnsmsg_t *req);
    void
core_cmd_report(content_t *cn, caccess_t *ca, dnsmsg_t *req);

//////////////////////////////////////////////////////////////////////////
//
static void* keyHash (caccess_t *ca)
{ return INT2PTR(ca->fd); }
static void* ikeyHash (cgroup_t *cg)
{ return INT2PTR(cg->group); }

 static int hashHash(int k)
{ return k; }
 static int compHash (int *pk, int k)
{ return *pk != k; }

    content_t *
content_init(content_t *cn, const char *name, const char *config)
{
    if (!cn) {
        fprintf(stderr, "Create content error\n");
        goto error;
    }

    if (archive_init ("./", name, ATLOG, (cbsink_t)NULL, (void*)NULL)) {
        fprintf(stderr, "Archive init error\n");
        goto error;
    }
    LOG(LOG_LEVEL_NOTICE, "Archive init success.\n");

    if (!(cn->pconf = new_config(config))) {
        LOG(LOG_LEVEL_ERROR, "Parse config error.\n");
        goto error;
    }
    LOG(LOG_LEVEL_NOTICE, "Config init success.\n");

    pthread_mutex_init(&cn->rdlock, NULL);
    pthread_mutex_init(&cn->cnlock, NULL);
    cn->accesses = gdsl_hash_alloc(NULL, NULL, NULL, 
            (gdsl_key_func_t)keyHash, 
            (gdsl_hash_func_t)hashHash, 
            (gdsl_hash_comp_t)compHash, 200);
    cn->groups = gdsl_hash_alloc(NULL, NULL, NULL,
            (gdsl_key_func_t)ikeyHash,
            (gdsl_hash_func_t)hashHash,
            (gdsl_hash_comp_t)compHash, 200);
    cn->registration = gdsl_queue_alloc(NULL, NULL, NULL);

    LOG(LOG_LEVEL_NOTICE, "Data structure init success.\n");

    if (!new_redis(cn->pconf->rdbhost, cn->pconf->rdbport, cn->pconf->rdbkey, cn->pconf->rdbc))
        goto error;

    if (!(cn->pools = threads_create(10, 10000, 0))) {
        LOG(LOG_LEVEL_ERROR, "create task pools error.\n");
        goto error;
    }
    if ( 0 == new_probe( (void*)0 )){
        LOG(LOG_LEVEL_ERROR, "probe  init failured.\n");
        goto error;
    }
    usleep(1000);
#if 0
    if (!(cn->store = (store_t *)new_store(cn))) {
        LOG(LOG_LEVEL_ERROR, "create cache store error.\n");
        goto error;
    }
#endif
    if (-1 == register_init(cn)) {
        LOG(LOG_LEVEL_ERROR, "register init failured.\n");
        goto error;
    }

    if (-1 == vindns_create(cn, (short)cn->pconf->nameport))
        goto error;

    if (NULL == vind_server(cn, "127.0.0.1", cn->pconf->listen))
        goto error;

    return cn;

error:
    return NULL;
}
    void
free_content(content_t *cn)
{
    if (cn) {
        if (cn->pools) {
            threads_destroy(cn->pools, 0);
            pthread_mutex_destroy(&cn->rdlock);
            pthread_mutex_destroy(&cn->rdlock);
        }
        if (cn->accesses)
            gdsl_hash_free(cn->accesses);

        if (cn->registration)
            gdsl_queue_free(cn->registration);
        if (cn->rdbconn)
            redisFree(cn->rdbconn);

        free(cn);
        cn = NULL;
    }
}
    static void 
del_char(char* str,char ch)
{
    char *p = str;
    char *q = str;
    while(*q) {
        if (*q !=ch)
            *p++ = *q;
        q++;
    }

    *p = 0;
}
    static config_t *
new_config(const char *file)
{
    FILE  *fp = NULL;
    char   buf[256] = {0};
    struct hostent      *he;
    struct in_addr **addr_list;
    
    config_t *pconf = (config_t *)calloc(sizeof(config_t), sizeof(char));

    if (!pconf) {
        LOG(LOG_LEVEL_ERROR, "Parse confile error.\n");
        return NULL;
    }
    pconf->nameport = 53;
    pconf->listen   = 6589; 
    pconf->rdbport  = 6379;
    pconf->httpport = 6989;


    pconf->rdbc = 0;
    memcpy(pconf->rdbhost,"127.0.0.1", strlen("127.0.0.1"));
    memcpy(pconf->rdbkey, "cdn@Redis", strlen("cdn@Redis"));
    printf("\n");
    fp = fopen(file, "r");
    while (NULL != fgets(buf, sizeof(buf), fp)) {
        char key[32] = {0};
        sscanf(buf, "%s[^=]", key);

        if (!strlen(key) || key[0] == '\n' || key[0] == '#') continue;

        del_char(key, '=');

        if (strstr(buf, "Nodeid") && strlen(key) == strlen("Nodeid")) {
            sscanf(buf, "%*[^=]=%s", pconf->id);
            printf("\tNodeid    : %s\n", pconf->id);
        }
        else if (strstr(buf, "Redis") && strlen(key) == strlen("Redis")) {
            memset(pconf->rdbhost, 0, strlen(pconf->rdbhost));
            sscanf(buf, "%*[^=]=%s", pconf->rdbhost);
#if 1
            if ((he = gethostbyname(pconf->rdbhost)))
            {
                addr_list = (struct in_addr **)he->h_addr_list;
                memset(pconf->rdbhost, 0, strlen(pconf->rdbhost));
                strncpy(pconf->rdbhost, 
                        inet_ntoa(*addr_list[0]), 
                        strlen(inet_ntoa(*addr_list[0])));
            }
#endif
            printf("\tRedisIP   : %s\n", pconf->rdbhost);
        }
        else if (strstr(buf, "RedisPort")&& strlen(key) == strlen("RedisPort")) {
            char tmp[8] = {0};
            sscanf(buf, "%*[^=]=%s", tmp);
            pconf->rdbport = atoi(tmp);
            printf("\tRedisPort : %d\n", pconf->rdbport);
        }
        else if (strstr(buf, "RedisKey")&& strlen(key) == strlen("RedisKey")) {
            memset(pconf->rdbkey, 0, strlen(pconf->rdbkey));
            sscanf(buf, "%*[^=]=%s", pconf->rdbkey);
            printf("\tRedisKey  : %s\n", pconf->rdbkey);
        }
        else if (strstr(buf, "RedisDb")&& strlen(key) == strlen("RedisDb")) {
            char tmp[8] = {0};
            sscanf(buf, "%*[^=]=%s", tmp);
            pconf->rdbc = atoi(tmp);
            printf("\tRedisDb   : %d\n", atoi(tmp));
        }

        else if (strstr(buf, "Listen")&& strlen(key) == strlen("Listen")) {
            char tmp[8] = {0};
            sscanf(buf, "%*[^=]=%s", tmp);
            pconf->listen = atoi(tmp);
            printf("\tListen    : %d\n", atoi(tmp));
        }
        else if (strstr(buf, "NamePort")&& strlen(key) == strlen("NamePort")) {
            char tmp[8] = {0};
            sscanf(buf, "%*[^=]=%s", tmp);
            pconf->nameport = atoi(tmp);
            printf("\tNamePort  : %d\n", atoi(tmp));
        }
#if 1
        else if (strstr(buf, "Httpport")&& strlen(key) == strlen("Httpport")) {
            char tmp[8] = {0};
            sscanf(buf, "%*[^=]=%s", tmp);
            pconf->httpport = atoi(tmp);
            printf("\tHttpPort  : %d\n", atoi(tmp));
        }
#endif
        memset(buf, 0, sizeof(buf));
    }
    fclose(fp);
    printf("\n");
    return pconf;
}

    void
wevent_active(content_t *cn, caccess_t *ca)
{
    worker_t *wk = NULL;
    if (NULL == ca || NULL == cn) {
        LOG(LOG_LEVEL_INFO, "Find a ca null\n");
        return ;
    }

    pthread_mutex_lock(&ca->access_lock);
    if (ca->fd == -1) {
        ca->flag &= ~FLAG_ACTIVE;
        pthread_mutex_unlock(&ca->access_lock);
        LOG(LOG_LEVEL_INFO, "Find ca fd == -1\n");
        return ;
    }
    if (ca->pdev)
        wk = ca->pdev->wk;
    else {
        if (ca->nodetype == NT_DNSSERVER) {
            LOG(LOG_LEVEL_DEBUG, "Add dns server.\n");
            wk = cn->workers[0];
        }
        else {
            LOG(LOG_LEVEL_DEBUG, "Add a normal server.\n");
            wk = cn->workers[ca->fd % 3];
        }
    }
    pthread_mutex_unlock(&ca->access_lock);
    LOG(LOG_LEVEL_DEBUG, "wk %p, wk->registration %p, active , size %lu\n", wk, wk->registration, gdsl_queue_get_size(wk->registration));
    pthread_mutex_lock(&wk->reglock);
//    if (!(ca->flag & FLAG_ACTIVE)) {
        ca->flag |= FLAG_ACTIVE;

        gdsl_queue_insert(wk->registration, INT2PTR(ca->fd));
//    }
    pthread_mutex_unlock(&wk->reglock);

    if (!(wk->flag & FLAG_ACTIVE) && wk->notify_send) {
        wk->flag |= FLAG_ACTIVE;

        if (write(wk->notify_send, " ", 1) != 1) {
            wk->flag &= ~FLAG_ACTIVE;
        }
    }

    return ;
}
    int 
vindns_create(content_t *cn, short port)
{
    evutil_socket_t sock;
    struct sockaddr_in my_addr;

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        LOG(LOG_LEVEL_ERROR, "dns_start error end.\n");
        return -1;
    }

    evutil_make_socket_nonblocking(sock);
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&my_addr, sizeof(my_addr))<0) {
        LOG(LOG_LEVEL_ERROR, "bind dns port %u error.\n", port);
        return -1;
    }

    caccess_t *ca = new_caccess((void *)cn, sock, "127.0.0.1", (uint16_t)port, NT_DNSSERVER);
//    evdns_add_server_port_with_base(base, sock, 0, evdns_server_callback, (void *)NULL);

    pthread_mutex_lock(&cn->objlock);
    gdsl_hash_insert(cn->accesses, ca);
    pthread_mutex_unlock(&cn->objlock);

    ca->status = NS_NORMAL;

    wevent_active(cn, ca);
    LOG(LOG_LEVEL_DEBUG, "DNS Server init success.\n");
    return 0;
}
    caccess_t *
vind_server(content_t *cn, const char *host, int port)
{
    evutil_socket_t sock;
    struct sockaddr_in my_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        LOG(LOG_LEVEL_ERROR, "server create error.\n");
        goto end;
    }

    evutil_make_socket_nonblocking(sock);

    memset((uint8_t *)&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

#if 0
    self.sin_family = AF_INET;
    self.sin_port = htons(port);
    self.sin_addr.s_addr = inet_addr(host);
    self.sin_addr.s_addr = inet_addr(host);
#endif
    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval)) == -1)
    {
        LOG(LOG_LEVEL_ERROR, "set SO_REUSEADDR socket option - (%d) %s.\n", errno, strerror(errno));
        goto end;
    }

    if (bind(sock, (struct sockaddr*)&my_addr, sizeof(my_addr))<0) {
        LOG(LOG_LEVEL_ERROR, "bind server port %d error.\n", port);
        goto end;
    }

    if (listen(sock, 600) < 0)
    {
        LOG(LOG_LEVEL_ERROR, "listen the socket - (%d) %s.\n", errno, strerror(errno));
        goto end;
    }

    caccess_t *ca = new_caccess((void *)cn, sock, host, (uint16_t)port, NT_TCPSERVER);

    pthread_mutex_lock(&cn->objlock);
    gdsl_hash_insert(cn->accesses, ca);
    pthread_mutex_unlock(&cn->objlock);

    ca->status = NS_NORMAL;

    wevent_active(cn, ca);

    LOG(LOG_LEVEL_DEBUG, "Local Server init success.\n");

    return ca;
end:
    if (sock)
        close(sock);
    return NULL;
}
    void
core_dispatch(content_t *cn, caccess_t *ca)
{
    if (!ca) return ;

    if (ca->status == NS_INVALID) {
        goto disuse;
    }
    int i = 0;
    dnsmsg_t *req = NULL, *res = NULL;
    uint32_t cmd = 0;

    while (++i < 10) {

        pthread_mutex_lock(&ca->access_lock);
        req = res = gdsl_list_remove_head(ca->recv_queue);
        pthread_mutex_unlock(&ca->access_lock);

        if (!req) break;

        cmd = ntohl(req->pdu.cmd);

        switch(cmd) {
        case CMD_LOGIN_DNS_REQ:
            LOG(LOG_LEVEL_DEBUG, "Find DNS REQ.\n");
            core_cmd_login(cn, ca, req);
            break;
        case CMD_LOGIN_DNS_RES:
            break;
        case CMD_REPORT_DNS_REQ:
            LOG(LOG_LEVEL_DEBUG, "Find DNS report.\n");
            core_cmd_report(cn, ca, req);
            break;
        case CMD_REPORT_DNS_RES:
            break;
        default:
            break;

        }
        free(req);
        req = NULL;
    }

    return ;
disuse:
    release_caccess(ca);
}
    static unsigned long 
search_child (inode_t *cc, char* nid) 
{ 
    if (cc == NULL ) {
        LOG(LOG_LEVEL_DEBUG, "Find a null cc inlist.\n");
        return 0;
    }
    return memcmp(cc->nid, nid, NIDSIZE);
}

    dnsmsg_t *
create_resmsg(int cmd, uint8_t status, int seq, int size)
{
    dnsmsg_t *msg = new_msg(size);

    msg->pdu.len = ntohl(21);
    msg->pdu.cmd = ntohl(cmd);
    msg->pdu.seq = seq;

    msg->pdu.startupres.status = status;
    memset(msg->pdu.startupres.reserved, 0, 8);
    return msg;
}
    void
core_cmd_login(content_t *cn, caccess_t *ca, dnsmsg_t *req)
{
    cgroup_t *cg = NULL;
    inode_t *cc = NULL;
    uint8_t  status = 1;
    int type = ntohl(req->pdu.startupreq.type);
    memcpy(ca->nid, req->pdu.startupreq.nodeid, NIDSIZE);
    pthread_mutex_lock(&cn->objlock);
    cg = gdsl_hash_search(cn->groups, INT2PTR(type));
    if (!cg) {
        gdsl_hash_insert(cn->groups, (cg = cgroup_create(type, 1)));
        LOG(LOG_LEVEL_DEBUG, "Create a hash table, insert hash cg %p\n", cg);
    }

    cc = gdsl_list_search(cg->childs, (gdsl_compare_func_t)search_child, ca->nid);

    if (!cc) {
        gdsl_list_insert_tail(cg->childs, (cc = cnode_create(ca->nid, ntohl(req->pdu.startupreq.ip), type)));
        printf("insert list cc %p, id %s\n", cc, cc->nid);
        cc->access = ca;
        cc->status = 1;
    }
    else { //login yet.
        status = 3;
        ca->status = NS_DISUSE;
    }

    pthread_mutex_unlock(&cn->objlock);
    LOG(LOG_LEVEL_DEBUG, "Find a child %s.\n", inet_ntoa(*(struct in_addr *)&cc->ip));
    ca->type = type;

    dnsmsg_t *res = create_resmsg(CMD_LOGIN_DNS_RES, status, req->pdu.seq, sizeof(dnsmsg_t));

    pthread_mutex_lock(&ca->access_lock);
    gdsl_list_insert_tail(ca->send_queue, res);
    pthread_mutex_unlock(&ca->access_lock);

    wevent_active(cn, ca);

}
    void
core_cmd_report(content_t *cn, caccess_t *ca, dnsmsg_t *req)
{
    LOG(LOG_LEVEL_DEBUG, "cmd report\n");
    cgroup_t *cg = NULL;
    inode_t *cc = NULL;
    //int type = ntohl(req->pdu.startupreq.type);
    //memcpy(ca->nid, req->pdu.startupreq.nodeid, NIDSIZE);
    pthread_mutex_lock(&cn->objlock);
    cg = gdsl_hash_search(cn->groups, INT2PTR(ca->type));
    if (!cg) {
        LOG(LOG_LEVEL_DEBUG, "Hash not found ca %p, type %d.\n", ca, ca->type);
        pthread_mutex_unlock(&cn->objlock);
        goto end;
    }
//    if (!cg) gdsl_hash_insert(cn->groups, (cg = cgroup_create(type, 1)));

    cc = gdsl_list_search(cg->childs, (gdsl_compare_func_t)search_child, ca->nid);
    if (!cc) {
        LOG(LOG_LEVEL_DEBUG, "List not found ca %p, type %d, id %s\n", ca, ca->type, ca->nid);
        pthread_mutex_unlock(&cn->objlock);
        goto end;
    }
#if 0
    if (!cc) {
        gdsl_list_insert_tail(cg->childs, (cc = cnode_create(ca->nid, ntohl(req->pdu.startupreq.ip), type)));

        cc->access = ca;
        cc->status = 1;
    }
    else { //login yet.

    }
#endif
    pthread_mutex_unlock(&cn->objlock);

    cc->links = ntohl(req->pdu.statusreq.links);
    cc->width = ntohl(req->pdu.statusreq.width);
    cc->cpus  = ntohs(req->pdu.statusreq.cpus);
    cc->memorys = ntohs(req->pdu.statusreq.memorys);

    dnsmsg_t *res = create_resmsg(CMD_REPORT_DNS_RES, 1, req->pdu.seq, sizeof(dnsmsg_t));

    pthread_mutex_lock(&ca->access_lock);
    gdsl_list_insert_tail(ca->send_queue, res);
    pthread_mutex_unlock(&ca->access_lock);

    wevent_active(cn, ca);
end:
    return ;
}
