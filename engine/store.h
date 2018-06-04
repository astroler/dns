/*************************************************************************
    File Name   :    store.h
    Author      :    sunzg
    Mail        :    suclinux@gmail.com
    Created Time:    Fri Jun 17 10:55:10 2016
*************************************************************************/

#ifndef __STORE_H__
#define __STORE_H__

#include <gdsl.h>
#include <stdint.h>
#include "obj.h"

#define NODE_STATUS_INUSE 0
#define NODE_STATUS_UNUSE 1

#define NODE_STATUS_INSER 1
#define NODE_STATUS_UNSER 0

#define TIMEOUT           60
#define AREACODELEN       9
// Node info, all node use this structure.
// Some members maybe not use.


//typedef struct store_s store_t;

store_t    *new_store(void *pdata);
void     free_store(void *udata);
void     node_t_free(void *e);
char    *match_name(void *udata, const char *name);
uint32_t banlance(void *udata, uint32_t *ttl, uint32_t *ip);

#endif

