/********************************************************************
    File Name   :   redis.c
    Author      :   sunzg
    Mail        :   suclinx@gmail.com
    Created Time:   Mon Jun 20 14:20:30 2016
********************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <hiredis.h>

#include "redis.h"
#include "arch.h"
//#define LOG(level, FMT...) fprintf(stderr, ## FMT)
typedef struct {

    char               *host;
    int                 port;
    int                 db;
    char               *pswd;

    redisContext       *rdbs[4];
    pthread_mutex_t     rlock[4];
} redispool_t;

static redispool_t *rpl = NULL;

/////////////////////////////////////////////////////////////////////////
//
    int
new_redis(const char* host, const int port, const char * pswd, int db) 
{
    if (!(rpl = (redispool_t *)calloc(sizeof(redispool_t), sizeof(char)))) {
        LOG(LOG_LEVEL_ERROR, "Create redis alloc memory error.\n");
        return 0;
    }
    int i = 0;
    rpl->host = (char *)calloc(strlen(host) +1, sizeof(char));
    rpl->pswd = (char *)calloc(strlen(pswd) +1, sizeof(char));
    memcpy(rpl->host, host, strlen(host));
    memcpy(rpl->pswd, pswd, strlen(pswd));
    rpl->port = port;
    rpl->db   = db;

    do {
        //LOG(LOG_LEVEL_FATAL, "\tredis start %d.\n", i);
        struct timeval timeout = {0, 500000};
        redisContext * c = redisConnectWithTimeout((char*)host, port, timeout);
        if (c->err == 0 && c->flags & REDIS_CONNECTED)
            ;//printf("Connected Redis-server \n");
        else {
            LOG(LOG_LEVEL_ERROR, "Connect redis %s.%d faild.\n", host, port);
            goto error;
        }

        redisReply * r = NULL;
        char  command[128] = {'\0'};

        sprintf(command, "AUTH %s", pswd);
        r = (redisReply *)redisCommand(c, command);
        if (r){
            freeReplyObject(r);
        }
        memset(command, 0, sizeof(command));
        sprintf(command, "select %d", db);
        r = (redisReply *)redisCommand(c, command);
        if (r){
            freeReplyObject(r);
        }
        pthread_mutex_init(&rpl->rlock[i], NULL);
        rpl->rdbs[i] = c;
        //LOG(LOG_LEVEL_FATAL, "\tredis count %d\n", i);
    } while (i++ < 3);

    LOG(LOG_LEVEL_DEBUG, "Redis connect success.(%s.%d)\n", host, port);

    return 1;
error:
    if(rpl) {
        free(rpl);
        rpl = NULL;
    }
    LOG(LOG_LEVEL_ERROR, "Redis connect error.(%s.%d)\n", host, port);
    return 0;
}
    void
redis_free()
{
    if (rpl) {
        if (rpl->host)
            free(rpl->host);
        if (rpl->pswd)
            free(rpl->pswd);
        int i;
        for (i = 0; i < 4; i ++)
            pthread_mutex_destroy(rpl->rlock[i]); 
    }
}
    redisContext *
chose_conn()
{
    redisContext *c;
    srand((unsigned)time(NULL));
    int i = rand() % 4;
    c = rpl->rdbs[i];
    LOG(LOG_LEVEL_FATAL, "c %d %p\n", i, c);

    return c;
}
    int
chose_index()
{
    srand((unsigned)time(NULL));
    int i = rand() % 4;

    return i;
}
    int
redis_set_info(void *pobj, uint8_t *key)
{
    int ret = 0;
    int i = chose_index();
    //redisContext * c = chose_conn();
    pthread_mutex_lock(&rpl->rlock[i]);
    redisContext * c = rpl->rdbs[i];

    redisReply * reply = (redisReply *)redisCommand(c, key);
    if (reply->type == REDIS_REPLY_ERROR) {
        LOG(LOG_LEVEL_ERROR, "Redis set key [%s] error.\n", key);
        ret = 1;
    }
    else
        ; /* command normal*/

    pthread_mutex_unlock(&rpl->rlock[i]);

    freeReplyObject(reply);

    LOG(LOG_LEVEL_DEBUG, "Redis set key [%s] suc.\n", key);

    return ret;
}

    int
redis_get_info(void *pobj, uint8_t *key, void *phint, int(blockfunc)(int, const char*, void *))
{
    int ret = 0;
    int i = chose_index();
    //redisContext * c = chose_conn();
    pthread_mutex_lock(&rpl->rlock[i]);
    redisContext * c = rpl->rdbs[i];

    redisReply * reply = (redisReply *)redisCommand(c, key);
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        ret = 1;
        LOG(LOG_LEVEL_ERROR, "Redis command %s faild.\n", key);
        goto end;
    }
    else if (reply->type == REDIS_REPLY_STRING) {
        LOG(LOG_LEVEL_DEBUG, "Redis key [%s] string reply <%s>.\n", key, reply->str);
        blockfunc(0, reply->str, phint);
    }
    else if (reply->type == REDIS_REPLY_ARRAY) {
        int j;
        if (reply->elements <= 0)
        {
            ret = 1;
            LOG(LOG_LEVEL_DEBUG, "Redis command find a nil reply. key[%s].\n", key);
            goto end;
        }
        for (j = 0; j < reply->elements; j++) {
            if (reply->element[j]->type == REDIS_REPLY_NIL) {
               // LOG(LOG_LEVEL_INFO, "Redis command find a nil reply. key[%s].\n", key);
                ret = 1;
                continue;
            }
            LOG(LOG_LEVEL_DEBUG, "Redis key %s array reply <%s>.\n", key, reply->element[j]->str);
            blockfunc(j+1, reply->element[j]->str, phint);
            ret = 0;
        }
    }
    else {
        ret = 1;
        LOG(LOG_LEVEL_DEBUG, "Redis key [%s] reply type %d, no result.\n", key, reply->type);
    }

end:
    pthread_mutex_unlock(&rpl->rlock[i]);

    if (reply)
        freeReplyObject(reply);

    return ret;
}


