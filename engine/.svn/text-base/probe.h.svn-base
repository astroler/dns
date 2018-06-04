/*************************************************************************
*  File Name   :    probe.h
*  Author      :    sunzg
*  Mail        :    suclinux@gmail.com
*  Created Time:    Mon Jun 20 16:11:17 2016
**************************************************************************/

#ifndef __PROBE_H__
#define __PROBE_H__

#include "obj.h"
#include <pthread.h>
#include <fcntl.h>
/////////////////////////////////////////
// store callback func.
//
typedef void * (*probecb)(void *udata, int h);
#if 0
typedef struct {

    int                 fd;
    int                 flag;

    worker_t           *worker;
    struct bufferevent *bev;
    struct event       *timer;
    int                 status;

    probecb             probe_report;

    pthread_mutex_t     lock;
    void               *node;
    //probe_t            *probe;
} probe_unit_t;

#endif
/////////////////////////////////////////////////////////////////////////////////////////
//
    void *
new_probe(void *udata);
    void
destroy_probe(void *pb);
 
/////////////////////////////////////////////////////////////////////////////////////////
// @udata, 
// @type, 探针类型，1是tcp ，2 是web；
// @host，节点IP；
// @port，如果type为1，port生效；
// @url，如果type为2，url生效；
// @cycle，探测周期，单位s；
// @cb，callback；
//
     void
probe_add(void *udata, int type, const char *host, short port, const char *url, int cycle, probecb cb);
 

#endif
