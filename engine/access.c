/*************************************************************************
    File Name   :    access.c
    Author      :    sunzg
    Mail        :    suclinux@gmail.com
    Created Time:    2016年11月02日 星期三 14时21分22秒
*************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "obj.h"
#include "msg.h"

    caccess_t *
new_caccess(void *cn, int fd, const char *host, int port, int type)
{
    caccess_t *ca = (caccess_t *)calloc(sizeof(caccess_t), sizeof(char));
    if (NULL == ca)
        return NULL;
    ca->recv_queue = gdsl_list_alloc(NULL, NULL, NULL);
    ca->send_queue = gdsl_list_alloc(NULL, NULL, NULL);
    
    pthread_mutex_init(&ca->access_lock, NULL);


    ca->fd   = fd;
    ca->port = (uint16_t)port;
//    if (host)

    ca->nodetype    = type;
    ca->interaction = time(NULL);
    ca->tv.tv_sec   = 3;
    ca->core        = (void *)cn;

    memcpy(ca->host, host, strlen(host));
    //printf("ca->port %u, nodetype 0x%x, type 0x%x, fd %d %d\n", ca->port, ca->nodetype, type, ca->fd, fd);

    return ca;
}

    void
release_caccess(caccess_t *ca)
{
    //printf("[free] accept ca %p, fd %d\n", ca, ca->fd);
    dnsmsg_t *req;
    if (ca) {
        pthread_mutex_destroy(&ca->access_lock);
        if (-1 != ca->fd)
            close(ca->fd), ca->fd = -1;
        if (ca->recv_incomplete)
            free(ca->recv_incomplete);
        if (ca->send_incomplete)
            free(ca->send_incomplete);
        while ((req = gdsl_list_remove_head(ca->send_queue)) != NULL)
            free(req);
        gdsl_list_free(ca->send_queue);

        while (!gdsl_list_is_empty(ca->recv_queue))
            free(gdsl_list_remove_head(ca->recv_queue));
        gdsl_list_free(ca->recv_queue);
        
        free(ca);
        ca = NULL;
    }
}
//////////////////////////////////////////////////////////////////////
//
    cgroup_t *
cgroup_create (int group, int immediate)
{
    cgroup_t *cg = NULL;

    cg = (cgroup_t *) calloc(sizeof(cgroup_t), sizeof(char));
    cg->group = group;
    cg->immediate = immediate;
    cg->childs = gdsl_list_alloc(0, 0, 0);
    cg->count  = 0;
    return cg;
}

    void 
cgroup_destroy (cgroup_t *cg)
{
    // free childs, empty list.
    gdsl_list_free(cg->childs);
    free(cg);
}
///////////////////////////////////////////////////////////////////////
//
    inode_t *
cnode_create(const char *nid, uint32_t uip, int type)
{
   inode_t *cc = (inode_t *)calloc(sizeof(inode_t), sizeof(char)); 

   memcpy(cc->nid, nid, NIDSIZE);
   cc->ip = ntohl(uip);
   cc->type = type;

   return cc;
}
    void
cnode_destroy(inode_t *nd)
{
    if (nd)
        free(nd);
}
