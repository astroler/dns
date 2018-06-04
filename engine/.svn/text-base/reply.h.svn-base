/*************************************************************************
    File Name   :    reply.h
    Author      :    sunzg
    Mail        :    suclinux@gmail.com
    Des         :    DNS结果返回信息处理。
    Created Time:    2016年11月10日 星期四 14时15分25秒
*************************************************************************/

#ifndef __RPPLY_H__
#define __RPPLY_H__

#include "obj.h"

typedef struct {
    /* Domain type. */
    int            type;             
    /* Return the counts of address. */
    int            count;
    /* Address list, uint32_t is base type. */
    //gdsl_list_t    addrs;
    uint32_t       addrs[8];

} apply_t;

    apply_t *
apply_create(content_t *cn, const char *name, uint32_t reqip);

    void
apply_free(apply_t *ap);

#endif
