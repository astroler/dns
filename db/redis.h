/*************************************************************************
    File Name   :    redis.h
    Author      :    sunzg
    Mail        :    suclinux@gmail.com
    Created Time:    Mon Jun 20 14:32:04 2016
*************************************************************************/

#ifndef __REDIS_H__
#define __REDIS_H__

int new_redis(const char *host, const int port, const char *pswd, int db);

void  redis_free();

int   redis_set_info(void *udata, uint8_t *key);

int   redis_get_info(void *udata, uint8_t *key, void *phint, int(blockfunc)(int, const char *, void *));

#endif
