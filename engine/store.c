/*************************************************************************
  File Name   :    store.c
Author      :    sunzg
Mail        :    suclinux@gmail.com
Created Time:    Mon Jun 20 10:12:56 2016
 *************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "store.h"
#include "obj.h"
#include "probe.h"
// Node info, all node use this structure.
// Some members maybe not use

extern gdsl_list_t dns_route(char *areacode, uint32_t ip,char *isp, gdsl_list_t node_list, uint16_t gtype, uint16_t count, const char *domain);
static void     initialize_store(store_t *udata);
static void    *inuse_entity(store_t *udata);
static void    *match_domain(store_t *udata, const char *name);
static uint32_t banlance_adjust(store_t *udata, uint32_t *ip, uint32_t *ttl);

static int redis_get_areaid(int i, const char *str, void *phint);

static int redis_get_dns_type(int i, const char * str, void *phint);
static int redis_get_node(int i, const char *str, void *phint);
static int redis_get_name(int i, const char * str, void *phint);
static int redis_get_dns_business_key(int i, const char * str, void *phint);
static int redis_get_node_keys(int i, const char * str, void *phint);
static int redis_get_type(int i, const char *str, void *phint);


static void     controller(void *udata);
/////////////////////////////////////////////////////////////////////////////
//
static char * keyHash2 (ngroup_t *ng)
{ return ng->name_key; }
static int hashHash2(int k)
{ return k; }
static int compHash2 (char *pk, char *k)
{
    // PRINT("pk = %s , %s\n", pk, k);
    return memcmp(pk, k, strlen(pk)); 
}

static void group_t_free(void *e)
{
    ngroup_t *group = (ngroup_t *)e;
    free(group->name_key);
    group->name_key = NULL;
    free(group->domain_tmp);
    group->domain_tmp = NULL;
}
static void name_t_free(void *e)
{
    name_t *name = (name_t *)e;
    free(name->name);
    name->name = NULL;
}

void node_t_free(void *e)
{
    node_t *node = (node_t *)e;

    if (node->ip) 
        free(node->ip);
    node->ip = NULL;

    if (node->url) 
        free(node->url);
    node->url = NULL;

    if (node->ip_code) 
        free(node->ip_code);
    node->ip_code = NULL;

    if (node->isp) 
        free(node->isp);
    node->isp = NULL;

    if (node) 
        free(node);
    node = NULL;
}

static int search_node(node_t *ng, void *key)
{
    //return memcmp(ng->id, (char *)key, strlen((char *)key));
    return strcmp(ng->id, (char *)key);
}

static int search_domain(ngroup_t *ng, void *key)
{
    //return memcmp(ng->domain_tmp, (char *)key, strlen((char *)key));
    return strcmp(ng->domain_tmp, (char *)key);
}

static int search_group(ngroup_t *ng, void *key)
{
    return (ng->type == *(int *)key);
}

static int group_list_search(void * E, void * str)
{
    ngroup_t *Ev  = (ngroup_t *)E;
    int ret = 1;
    ret = strcmp(Ev->name_key, (char *)str);
    //ret = memcmp(Ev->name_key, str, strlen(Ev->name_key));
    return ret;
}

static int search_node_key(void *E, void *str)
{
    return strcmp(E, (char *)str);
    //return memcmp(E, (char *)str, strlen((char *)str));
}


store_t *new_store(void *pdata)
{
    store_t *pstore = (store_t *)calloc(sizeof(store_t), sizeof(char));
    if (!pstore) 
    {
        LOG(LOG_LEVEL_ERROR, "create store error.\n");
        goto error;
    }

    if (!(pstore->fentity = gdsl_list_alloc("Frist entity", NULL, group_t_free))) 
    {
        LOG(LOG_LEVEL_ERROR, "create frist entity error.\n");
        goto error;
    }
    if (!(pstore->sentity = gdsl_list_alloc("Second entity", NULL, group_t_free))) 
    {
        LOG(LOG_LEVEL_ERROR, "create second entity error.\n");
        goto error;
    }

    if (!(pstore->pools = threads_create(10, 10000, 0))) 
    {
        LOG(LOG_LEVEL_ERROR, "create store pool error.\n");
        goto error;
    }

    pstore->pvind   = pdata;
    pstore->status  = 0;
    pstore->keypad  = 0;
    pstore->fen_status  = 0;
    pstore->sen_status  = 0;
    initialize_store(pstore);
    pstore->status = 1;
    threads_dispatch(pstore->pools, (void *)controller, (void *)pstore, 0);

    LOG(LOG_LEVEL_DEBUG, "Cache store init success %p.\n", pstore);
    return pstore;

error:
    if (pstore)
        free_store(pstore);
    printf("***************************************************\n");
    printf("******************init error***********************\n");
    printf("***************************************************\n");

    return NULL;
}

void free_store(void *udata)
{
    if (NULL == udata)
        return ;
    if (((store_t *)udata)->fentity) 
    {
        gdsl_list_free(((store_t *)udata)->fentity);
    }
    if (((store_t *)udata)->sentity) 
    {
        gdsl_list_free(((store_t *)udata)->sentity);
    }
    if (((store_t *)udata)->pools) 
    {
        threads_destroy(((store_t *)udata)->pools, 0);
    }

    free(udata);

    return ;
}

char *match_name(void *udata, const char *name)
{

}

uint32_t banlance(void *udata, uint32_t *ttl, uint32_t *ip)
{

}
///////////////////////////////////////////////////////////////////////////////

#if 0
static ngroup_t *new_group(const char *key)
{
    ngroup_t *group = (ngroup_t *)calloc(sizeof(ngroup_t), sizeof(char));
    if (NULL == group) {
        return NULL;
    }
    group->names = gdsl_list_alloc("name list", NULL, name_t_free);
    group->nodes = gdsl_list_alloc("node list", NULL, node_t_free);

    group->name_key = (char *)calloc(strlen(key)+1, sizeof(char));
    memcpy(group->name_key, key, strlen(key));

    return group;
}
#endif 
static int oneStep (void *e, gdsl_location_t l, void *arg)
{
//    ngroup_t *g;
    if ((arg != NULL) && (e != NULL))
    {
        //把tmp_list 设为store结构成员, 在插入之前与tmp_list中值比较，不相等才插入。    
        gdsl_list_insert_tail(arg, e);
    }

    return GDSL_MAP_CONT;
}

#if 0
static void cb_business(void *udata, const char *keyword, const char *value, int type)
{
    store_t *pstore = (store_t *)udata;
    // cdn:dns:business:keyworld
    char *skey[64] = {"\0"};
    sscanf(value, "%*17c%s", skey);
    ngroup_t *ngroup = gdsl_list_search(pstore->fentity, skey);
    if (NULL == ngroup) {
        ngroup = new_group((const char *)skey);
        gdsl_hash_insert(pstore->fentity, (void *)ngroup);

    }
}
#endif 
ngroup_t *create_ngroup(store_t *pstore)
{
    ngroup_t *ngroup    = (ngroup_t*)calloc(sizeof(ngroup_t), sizeof(char)); 
    if (ngroup == NULL)
        return NULL;
    ngroup->name_key    = NULL;
    ngroup->domain_tmp  = NULL;
    ngroup->names       = gdsl_list_alloc(NULL, NULL, (gdsl_free_func_t)name_t_free);
    ngroup->nodes       = gdsl_list_alloc(NULL, NULL, (gdsl_free_func_t)node_t_free);
    ngroup->name_keys   = gdsl_list_alloc(NULL, NULL, NULL);
    ngroup->node_keys   = gdsl_list_alloc(NULL, NULL, NULL);
    return ngroup;
}

//callback func of  func redis_get_info  to get dns_type
static int redis_get_dns_type(int i, const char * str, void *phint)
{
    store_t * pstore = (store_t *)phint;
    ngroup_t * ngroup = NULL;
    //ngroup_t * ngroup_2 = NULL;
    if (!str)
        return -1;
    if (i % 2)
    {
        if (pstore->status == 0)
        {
            ngroup = gdsl_list_search(pstore->sentity, (gdsl_compare_func_t)group_list_search, str);
        }
        else
        {
            ngroup = (pstore->keypad == 0 ?
                    gdsl_list_search(pstore->sentity, (gdsl_compare_func_t)group_list_search, str)
                    : gdsl_list_search(pstore->fentity, (gdsl_compare_func_t)group_list_search, str));
        }

        if (!ngroup)
        {
            ngroup =create_ngroup(pstore);

            if (!ngroup)
                return -1;
            if (pstore->status == 0)
            {
                if (pstore->fen_status ==0)
                {
                    gdsl_list_insert_tail(pstore->fentity, (void *)ngroup);
                }
                else if (pstore->sen_status == 0)
                {
                    gdsl_list_insert_tail(pstore->sentity, (void *)ngroup);
                }
            }
            else
            {
                if (pstore->keypad == 0)
                    gdsl_list_insert_tail(pstore->sentity, (void *)ngroup);
                else gdsl_list_insert_tail(pstore->fentity, (void *)ngroup);
            }
        }

        ngroup->inuse = 0;
        if (ngroup->name_key)
            free(ngroup->name_key);
        ngroup->name_key = NULL;
        ngroup->name_key = (char *)calloc(strlen(str) + 1, 1);
        memcpy(ngroup->name_key, str, strlen(str));
        ngroup->uptime   = time(0);
        pstore->group_tmp = ngroup;
    }
    else
    {
        if (pstore->group_tmp)
            pstore->group_tmp->type = atoi(str);
    }
    return 0;
}

static int redis_get_ipaddr(int i, const char * str, void * phint)
{
    if (!str) 
    {
        LOG(LOG_LEVEL_ERROR, "get area code false!\n");
        return -1;
    }
    //char str_area[9] = {'\0'}, str_isp[6] = {'\0'};
    code_isp_t *code_isp = (code_isp_t *)phint;
    memcpy(code_isp->code, str, 9);       
    memcpy(code_isp->isp, (str+12), 3);
    //int ad = atoi(str_area);
    //code_isp->isp  = (uint32_t)atoi(str_isp);
    return 0;
}

int route_owner(unsigned long ip, char * ip_code, char * isp)
{
    char cmd[128] = {0};
    code_isp_t *code_isp = (code_isp_t *)calloc(sizeof(code_isp_t), sizeof(char));
    code_isp->code = ip_code;
    code_isp->isp = isp;
    snprintf(cmd, sizeof(cmd), "ZRANGEBYSCORE ipaddr:new %lu +inf  LIMIT 0 1", ip);
    int ret = redis_get_info(NULL, cmd, (void *)code_isp, redis_get_ipaddr);
    if (ret == 0)
        return -1;
    free(code_isp);
    code_isp = NULL;
    return 0;
}

int get_areacode(char *areacode)
{
    if (!areacode) 
        return -1;
    char cmd[128] = {0};
    int  areacode_9 = atoi(areacode);
    snprintf(cmd, 128, "HGET ccn:areacastnew %d", areacode_9);
    redis_get_info(NULL, cmd, (void *)areacode, redis_get_areaid);
    return 0;
}

static int redis_get_node(int i, const char *str, void *phint)
{
    if (!str)
        return -1;
    ngroup_t *group = (ngroup_t *)phint;
    node_t   *node = NULL;

    switch (i)
    {
        case 1:
            if (!(node = gdsl_list_search(group->nodes, (gdsl_compare_func_t)search_node, str)))
            {
                node = (node_t *)calloc(sizeof(node_t), sizeof(char));
                if (!node)
                    return -1;
                gdsl_list_insert_tail(group->nodes, node);
            }

            group->node_tmp = node;
            memset(group->node_tmp->id, 0, NIDSIZE);            
            memcpy(group->node_tmp->id, str, strlen(str));
            node->time = time(0);

            break;
        case 2:
            if (group->node_tmp)
            {
                if (group->node_tmp->isp) free(group->node_tmp->isp);
                group->node_tmp->isp = NULL;
                group->node_tmp->isp = (char *)calloc(3, sizeof(char));
                memcpy(group->node_tmp->isp, str, strlen(str));
            }
            break;
        case 3:
            group->node_tmp->btype = atoi(str);
            if (group->node_tmp->btype != group->btype)
            {
                gdsl_list_delete_tail(group->nodes);
                group->node_tmp = NULL;
            }
            break;
        case 4:
            if (group->node_tmp)
            {
                if (group->node_tmp->ip) free(group->node_tmp->ip);
                group->node_tmp->ip = NULL;
                group->node_tmp->ip = (char *)calloc(strlen(str) + 1, 1);
                memcpy(group->node_tmp->ip, str, strlen(str));
            }
            break;
        case 5:
            if (group->node_tmp)
            {
                group->node_tmp->port = atoi(str);
            }
            break;
        case 6:
            if (group->node_tmp)
            {
                if (group->node_tmp->url) 
                    free(group->node_tmp->url);
                group->node_tmp->url = NULL;
                group->node_tmp->url = (char *)calloc(strlen(str) + 1, 1);
                memcpy(group->node_tmp->url, str, strlen(str));
            }
            break;
        case 7:
            if (group->node_tmp)
                group->node_tmp->links = atoi(str);
            break;
        case 8:
            if (group->node_tmp)
                group->node_tmp->width = atoi(str);
            break;
        case 9:
            if (group->node_tmp)
                group->node_tmp->cpus = atoi(str);
            break;
        case 10:
            if (group->node_tmp)
                group->node_tmp->memorys = atoi(str);
            break;
        case 11:
            if (group->node_tmp)
                group->node_tmp->weights = atoi(str);
            break;
        case 12:
            if (group->node_tmp)
                group->node_tmp->inuse = atoi(str);
            break;
        case 13:
            if (group->node_tmp)
                group->node_tmp->ptype  = atoi(str);
            break;
        case 14:
            if (group->node_tmp)
                group->node_tmp->cycle = atoi(str);
            break;
        case 15:
            if (group->node_tmp)
            {
                if (group->node_tmp->ip_code) 
                    free(group->node_tmp->ip_code);
                group->node_tmp->ip_code = NULL;
                group->node_tmp->ip_code = (char *)calloc(AREACODELEN, sizeof(char));
                memcpy(group->node_tmp->ip_code, str, 9);
            }
            break;
        default:
            break;
    }
}

static int redis_get_name(int i, const char * str, void *phint)
{
    if (!str)
        return -1;
    ngroup_t *group = (ngroup_t *)phint;
    name_t * sname  = NULL;

    switch (i)
    {
        case 1:
            { 
                if ( !(sname = gdsl_list_search(group->names, (gdsl_compare_func_t)search_domain, str)))
                {
                    sname = (name_t *)calloc(sizeof(name_t), sizeof(char));
                    if (!sname)
                        return -1;

                    sname->btype = group->btype;
                    gdsl_list_insert_tail(group->names, sname);
                }
                group->name_tmp = sname;

                if (group->name_tmp->name) free(group->name_tmp->name);
                group->name_tmp->name = NULL;
                group->name_tmp->name = (char *)calloc(strlen(str) + 1, 1);
                strcpy(group->name_tmp->name, str);

                if (group->domain_tmp) free(group->domain_tmp);
                group->domain_tmp = NULL;
                group->domain_tmp = (char *)calloc(strlen(str) + 1, 1);
                strcpy(group->domain_tmp, str);
                group->name_tmp->time = time(0);
            }
            break;
        case 2:
            group->name_tmp->inuse = atoi(str);
            break;
        default:
            break;
    }

    return 0;
}


static int redis_get_dns_business_key(int i, const char * str, void *phint)
{
    ngroup_t *group = (ngroup_t *)phint;
    if (str && !gdsl_list_search(group->node_keys, (gdsl_compare_func_t)search_node_key, str))
    {
        char *redis_key = (char *)calloc(strlen(str)+1, 1);
        memcpy(redis_key, str, strlen(str));
        gdsl_list_insert_tail(group->name_keys, (void *)redis_key);
    }
    return 0;
}

static int redis_get_node_keys(int i, const char * str, void *phint)
{
    ngroup_t *group = (ngroup_t *)phint;
    if (str && !gdsl_list_search(group->node_keys, (gdsl_compare_func_t)search_node_key, str))
    {
        char * redis_key = (char *)calloc(1, strlen(str) + 1);
        memcpy(redis_key, str, strlen(str));
        gdsl_list_insert_tail(group->node_keys, (void *)redis_key);
    }
    return 0;
}

static int redis_get_areaid(int i, const char *str, void *phint)
{
    if (!str) 
        return -1;
    char *areacode = (char *)phint;
    memset(areacode, 0, AREACODELEN);
    memcpy(areacode, str, strlen(str));
    strncat(areacode+4, "00", 2);
    return 0;
}

static int redis_get_type(int i, const char *str, void *phint)
{
    ngroup_t *group = (ngroup_t *)phint;
    if (!str) 
        return -1;
    switch (i)
    {
        case 1:
            group->t_attribute.num = atoi(str);
            break;
        case 2:
            group->t_attribute.gtype = atoi(str);
            break;
        case 3:
            group->t_attribute.ttl = atoi(str);
            break;
        default:
            break;
    }
    return 0;
}

static int update_node_name(gdsl_list_t list, size_t size)
{
    gdsl_list_t tmplist  = list;
    ngroup_t *group = NULL;
    int index = 1;
    int ret = 0;
    char *cmd = (char *)calloc(CMDLEN, sizeof(char));

    while ((group = gdsl_list_search_by_position(tmplist, index)) && (index <= size))
    {
        snprintf(cmd, CMDLEN, "KEYS cdn:dns:business:%d:*", group->btype);
        ret = redis_get_info(NULL, cmd, (void *)group, redis_get_dns_business_key);

        // get name from redis. 
        char *key = NULL;
        int i = 0, l_len = gdsl_list_get_size(group->name_keys);
        for (i = 0; i < l_len; ++i)
        {
            key = gdsl_list_search_by_position(group->name_keys, i+1);
            memset(cmd, 0, CMDLEN);
            snprintf(cmd, CMDLEN, "HMGET %s name inuse", key);
            ret = redis_get_info(NULL, cmd, (void *)group, redis_get_name);
        }
        // get node from redis.
        memset(cmd, 0, CMDLEN);
        snprintf(cmd, CMDLEN, "KEYS cdn:dns:node:*");
        ret = redis_get_info(NULL, cmd, (void *)group, redis_get_node_keys);
        key = NULL;
        int n_len = gdsl_list_get_size(group->node_keys);
        for (i = 0; i < n_len; ++i)
        {
            key = gdsl_list_search_by_position(group->node_keys, i+1);
            memset(cmd, 0, CMDLEN);
            snprintf(cmd, CMDLEN, "HMGET %s id isp btype ipaddr port url links width cpus memorys weight inuse ptype cycle areacode", key);
            ret = redis_get_info(NULL, cmd, (void *)group, redis_get_node);
#if 1
            if  (group->node_tmp != NULL)
            {
                if (group->node_tmp->ip_code != NULL || atoi(group->node_tmp->ip_code) == 0)
                {
                    uint32_t ip = ntohl(inet_addr(group->node_tmp->ip));
                    route_owner(ip, (char *)group->node_tmp->ip_code, group->node_tmp->isp); 
                    get_areacode(group->node_tmp->ip_code);
                }
            }
#endif
        }

        // get type`s attribute from redis.
        memset(cmd, 0, CMDLEN);
        snprintf(cmd, CMDLEN, "HMGET cdn:dns:businessconf:%d num gtype ttl ", group->btype);
        ret = redis_get_info(NULL, cmd, (void *)group, redis_get_type);

        index++;
    }

    return 0;
}

// Read data from redis db, create store.
static void initialize_store(store_t *udata)
{
    //order by ngroup, node list.
    store_t *pstore = (store_t *)udata;
    ngroup_t *group = NULL;
    //PRINT("============init store_t ==========\n"); 

    int index = 0;
    unsigned long size = 0;

    gdsl_list_t tmplist = NULL;
    gdsl_list_t tmplist2 = NULL;

    char *cmd = (char *)calloc(CMDLEN, sizeof(char));
    //first: get business type from cdn:dns:btype:register
    if ((pstore->status == 0)||(pstore->status == 1 && pstore->keypad == 1)) 
    {
        snprintf(cmd, CMDLEN, "ZRANGE cdn:dns:btype:register 0 -1 WITHSCORES"); 
        int ret = redis_get_info(NULL, cmd, (void *)pstore, redis_get_dns_type);

        pstore->fen_status = 1; 
        //        PRINT("fentity=====\n");
        tmplist = pstore->fentity;
        size = gdsl_list_get_size(tmplist);
        update_node_name(tmplist, size);

    }
    if ((pstore->status == 0)||(pstore->status == 1 && pstore->keypad == 0))
    {
        memset(cmd, 0, CMDLEN);
        snprintf(cmd, CMDLEN, "ZRANGE cdn:dns:btype:register 0 -1 WITHSCORES"); 
        int ret = redis_get_info(NULL, cmd, (void *)pstore, redis_get_dns_type);
        if (ret)
            return ;

        pstore->sen_status = 1;
        //      PRINT("sentity=====\n");
        tmplist2 = pstore->sentity;
        size = gdsl_list_get_size(tmplist2);
        update_node_name(tmplist2, size); 
    }

    free(cmd);
    cmd = NULL;
}

void * probe_cb(void *a,  int status)
{
    node_t   *node  = (node_t *) a;
    if (!node)
        return ;
    store_t *store = NULL;
    store = (store_t *)node->store;
    node->status = status;
    store->count --;
}

static void controller(void *udata) 
{
    store_t *pstore = (store_t *)udata;
    if (!pstore)
    {
        return ;
    }
    int size = 0, index = 0;
    ngroup_t *group = NULL;
    node_t  *node = NULL;

    while (pstore)
    {
#if 1
        initialize_store(pstore);

        gdsl_list_t tmplist = NULL ; 
        index = 1;
        if (pstore->status == 1)
        {
            if (pstore->keypad == 0)
            {
                // 取list fentity group 查询状态。
                //PRINT("controller_sentity\n");
                tmplist = pstore->sentity;
                size = gdsl_list_get_size(tmplist);
            }
            else 
            {
                // 取list senfity group 查询状态.
                //PRINT("controller_fentity\n");
                tmplist = pstore->fentity;
                size = gdsl_list_get_size(tmplist);
            }
            while ( (group = gdsl_list_search_by_position(tmplist, index)) && index <= size)
            {
                PRINT("=====gorup addr = %p\n", group);
                int len = gdsl_list_get_size(group->nodes);
                int i = 0;
                for (i = 1; i <= len; ++i)
                {
                    node = gdsl_list_search_by_position(group->nodes, i);
                    if (node == NULL)
                        break;
                    if ( time(0) - node->time > TIMEOUT)
                    {
                        gdsl_list_delete(group->nodes, (gdsl_compare_func_t)search_node, node->id); 
                        len--;
                        continue;
                    }
                    //node->inuse = 0;
                    if (node->ptype == 0 || node->ip == NULL || node->port == 0 || node->url == NULL || node->ip_code == 0)
                        continue;
                    if (node->ptype == 3) //A Record no need probe.
                    {
                        node->status = NODE_STATUS_INSER;
                        continue;
                    }
                    node->store = (store_t *)pstore ;
                    node->status = 0;

                    //PRINT("ber node adreess = %p, count %d\n", node, pstore->count);
                    probe_add((void *)node, node->ptype, node->ip, node->port, node->url, node->cycle, probe_cb );                
                    usleep(100);
                    pstore->count ++;
                }
                index ++;
            }
            // if (pstore->count != 0){
            //    pstore->count = 0;
            // }

        }

        sleep(15);
        //pstore->keypad = !pstore->keypad;
        if (pstore->keypad)
            __sync_fetch_and_add(&pstore->keypad, -1);
        else
            __sync_fetch_and_add(&pstore->keypad, 1);
        sleep(5);
        //PRINT("*********pstrore->coount = %d f?s %d\n", pstore->count, pstore->keypad);
    }
#endif
}

static uint32_t banlance_adjust(store_t *udata, uint32_t *ip, uint32_t *ttl)
{

}


int search_store(void *store, const char *name,  uint32_t c_ip, uint32_t res[RES_NUM], uint32_t *ttl)
{   
    if (store == NULL)
    {
        return -1;
    }
    int size = 0, ret = 0;
    char log[512] = {0};
    char res_ip[256] = {0};
    store_t     *pstore = (store_t *)store;

    if ((pstore->status == 0) && (pstore->sen_status == 0) && (pstore->fen_status==0))
    {
        return -1;
    }
    ngroup_t    *group = NULL;
    name_t      *pname = NULL;
    node_t      *node  = NULL;
    char        *areacode  = (char *)calloc(AREACODELEN, sizeof(char));
    char        *isp = (char *)calloc(3, sizeof(char));
    gdsl_list_t tmp_list = NULL;
    gdsl_list_t node_list = gdsl_list_alloc("node_list", NULL, NULL);
    gdsl_list_t res_list = NULL;   
    uint32_t c_type = 0;
    uint32_t ip_addr = c_ip;
    route_owner(ip_addr, areacode, isp);
    get_areacode(areacode);
    char ip[56] = {0};
    uint32_t tmp = ntohl(ip_addr);
    sprintf(ip, "%s", inet_ntoa(*(struct in_addr *)&tmp));
    sprintf(log+strlen(log), "Req:%s domain:%s areacode:%s==>", ip, name, areacode);    
    if (pstore->keypad == 0)
    {
        //PRINT("Search node in list fentity. %d\n", pstore->keypad);
        tmp_list = pstore->fentity;
        size = gdsl_list_get_size(tmp_list);
    }
    else 
    {
        //PRINT("Search node in list sentity. %d \n", pstore->keypad);
        tmp_list = pstore->sentity;
        size = gdsl_list_get_size(tmp_list);
    }

    int index = 1;
    while ( group = gdsl_list_search_by_position(tmp_list, index))
    {
        if (group->uptime - time(0) > TIMEOUT)
        {
            gdsl_list_remove(tmp_list, (gdsl_compare_func_t)search_group, (void *)&group->type);
            //index ++;
            continue;
        }
        int i = 0, j = 1;
        int len = gdsl_list_get_size(group->names);
        for (i = 1; i <= len; ++i)
        {
            pname = gdsl_list_search_by_position(group->names, i);
            //ret = strncmp(pname->name, name, strlen(name));
            if (time(0) - pname->time > TIMEOUT)
            {
                gdsl_list_delete(group->names, (gdsl_compare_func_t)search_domain, pname->name);
                len--;
                continue;
            }

            ret = strcmp(name, pname->name);

            if (ret == 0 && pname->inuse != 0)
            {
                c_type = pname->btype;
                sprintf(log + strlen(log), "type:%s ttl:%d", group->name_key, group->t_attribute.ttl);
                LOG(LOG_LEVEL_DEBUG, "domain :%s -->type %d\n", name, c_type);
                break;
            }

        }
        if (!c_type)
        {
            index++; 
            continue;
        }

        while (node = gdsl_list_search_by_position(group->nodes, j))
        {
            if ( node->btype == c_type && node->status == 1 && node->inuse == 1)
            {
                node_t   *tmp = (node_t *)calloc(sizeof(node_t), sizeof(char));
                memcpy(tmp, node, sizeof(node_t));
                tmp->ip = (char *)calloc(strlen(node->ip) + 1, sizeof(char));
                memcpy(tmp->ip, node->ip, strlen(node->ip));
                tmp->url = (char *)calloc(strlen(node->url) + 1, sizeof(char));
                memcpy(tmp->url, node->url, strlen(node->url));

                tmp->ip_code = (char *)calloc(strlen(node->ip_code) + 1,sizeof(char));
                memcpy(tmp->ip_code, node->ip_code, strlen(node->ip_code));
                tmp->isp = (char *)calloc(strlen(node->isp) + 1, sizeof(char));
                memcpy(tmp->isp, node->isp, strlen(node->isp));
                //printf("tmp->ip %s\n", tmp->ip);

                if (time(0)%2 == 1)
                    gdsl_list_insert_tail(node_list, tmp);
                else 
                    gdsl_list_insert_head(node_list, tmp);
            }
            j ++;
        }
#if 1
        if (gdsl_list_get_size(node_list) > 0)        
        {
            *ttl = group->t_attribute.ttl; 
            //printf("node-list size = %d\n", gdsl_list_get_size(node_list));

            if (res_list = dns_route(areacode, ip_addr, isp, node_list, group->t_attribute.gtype, group->t_attribute.num, name))
                break;
            //dns_route(char *areacode, char *isp, gdsl_list_t node_list, uint16_t gtype, uint16_t count);
        }
#endif
        index ++;

    }
    if (c_type == 0)
    {
        LOG(LOG_LEVEL_DEBUG, "Req:%s domain:%s areacode:%s==> Notfound %s in group.\n", ip, name, areacode, name);
        return 0;
    }
    if (gdsl_list_get_size(node_list) < 1)
    {
        LOG(LOG_LEVEL_DEBUG, "Req:%s domain:%s areacode:%s==> Notfound n_type %x in nodes.\n", ip, name, areacode, c_type);
        return 0;
    }
    int i = 0;

    if (res_list)
    {
        size = gdsl_list_get_size(res_list);

        for (i = 0; i <= RES_NUM && size > 0; ++i)
        {
            node = gdsl_list_search_by_position(res_list, size);
            if (node->ip) 
            {
                res[i] =  inet_addr(node->ip);
                sprintf(res_ip + strlen(res_ip), "[%s]", node->ip); 
            }
            size --;
        }
    }

    LOG(LOG_LEVEL_DEBUG,"%s res:%s\n",log, strlen((char *) res_ip) == 0 ? "NOTFOUND" : (char*)res_ip);
    if (areacode)
    {
        free(areacode); 
        areacode = NULL;
    }
    if (isp)
    {
        free(isp); 
        isp = NULL;
    }

    if (res_list)
    {
        if (!gdsl_list_is_empty(res_list))
        {
            gdsl_list_free(res_list);
        }
    }

    if (gdsl_list_get_size(node_list) > 0)
    {
        if(NULL != node)
        {
            if (NULL != node->ip) 
                free(node->ip);
            node->ip = NULL;
            if (NULL != node->url) 
                free(node->url);
            node->url = NULL;
            if (NULL != node->ip_code) 
                free(node->ip_code);
            node->ip_code = NULL;
            if (NULL != node->isp) 
                free(node->isp);
            node->isp = NULL;
        }
        gdsl_list_free(node_list);
        node_list = NULL;
    }
    return i;
}
