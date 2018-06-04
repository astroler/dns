/*************************************************************************
File Name   :    engine/route.c
Author      :    Guanzhong
Mail        :    
Created Time:    2017年01月03日 星期二 11时08分47秒
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
#include "obj.h"

#include <gdsl.h>
#include <event.h>
#include <evhttp.h>
#include <evdns.h>
//pthread_mutex_t nodelist_lock;
//pthread_mutex_init(&nodelist_lock);
extern void node_t_free(void *e); 

static int neighbor_node_list(node_t *node,const char *isp,const char *code_provice,gdsl_list_t list,uint32_t *count)
{
    int index = 0, i = 0, num = 0, ret = 0;
    char nodetmp[3] = {0};
    memcpy(nodetmp, node->ip_code, 2);
    if (atoi(code_provice) < 10)
    {
        num = 3;
    }
    else
    {
        num = 7;
    }

    if ((ret = abs(atoi(code_provice) - atoi(nodetmp))) <= num)
    {
        gdsl_list_insert_tail(list,node);
        (*count)++;
    }
    return *count;
}

gdsl_list_t area_route(const char *areacode,gdsl_list_t node_list,const char *isp,uint32_t count,gdsl_list_t return_list)
{
    char code[7] = {0};
    char code_provice[3] = {0};
    char code_city[5] = {0};
    //char isp[4] = {0};
    int index = 0, no = 0;
    uint32_t fliter_count = 0;
    uint32_t backlevel1_fliter_count = 0;
    uint32_t backlevel2_fliter_count = 0;
    uint32_t backlevel3_fliter_count = 0;
    uint32_t t = 0;
    gdsl_list_t backlevel1_list = gdsl_list_alloc(NULL, NULL, NULL);
    gdsl_list_t backlevel2_list = gdsl_list_alloc(NULL, NULL, NULL);
    gdsl_list_t backlevel3_list = gdsl_list_alloc(NULL, NULL, NULL);
    node_t *node = (node_t *)calloc(sizeof(node_t), sizeof(char));
    uint32_t size = gdsl_list_get_size(node_list);
    strncpy(code, areacode, strlen(areacode));
    strncpy(code_provice, areacode, 2);
    strncpy(code_city, areacode, 4);
    for (index = 1; index <= size; index ++)
    {
        node = gdsl_list_search_by_position(node_list, index);
        if(0 == memcmp(code_city, node->ip_code, 4))
        { // 1. 同地 同isp
            if( 0 == memcmp(isp, node->isp, sizeof(node->isp)))
            {
                fliter_count++;
                gdsl_list_insert_tail(return_list, node);
            } 
        }
        else if(0 == memcmp(code_provice, node->ip_code, 2))
        {//2.同省同isp 作为备选
            if(0 == memcmp(isp, node->isp, sizeof(node->isp)))
            {
                backlevel1_fliter_count++;   
                gdsl_list_insert_tail(backlevel1_list, node);
            }
            else 
            { //4.同省不同isp  作为备选3
                backlevel3_fliter_count++;
                gdsl_list_insert_tail(backlevel3_list, node);
            }
        }				  
        else if(neighbor_node_list(node, isp, code_provice, backlevel2_list, &backlevel2_fliter_count) > 0)     
        { //3.全网同isp作为备选2

        }
        else
        {
            if(0 == memcpy(node->isp, isp, sizeof(isp)))
            {
                backlevel2_fliter_count++;
                gdsl_list_insert_tail(backlevel2_list, node);
            }
        } 
    }
    //将筛选的节点 按照级别 逐一插入返回队列 
    if( fliter_count + backlevel1_fliter_count >= count )
    {
        while(gdsl_list_get_size(return_list) < count)
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel1_list));
        }
    }
    else if(fliter_count + backlevel1_fliter_count + backlevel2_fliter_count >= count)
    {
        while(!gdsl_list_is_empty(backlevel1_list))
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel1_list));
        }
        while(gdsl_list_get_size(return_list) < count)
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel2_list));
        }
    }
    else if(fliter_count + backlevel1_fliter_count + backlevel2_fliter_count +backlevel3_fliter_count >= count)
    {
        while(!gdsl_list_is_empty(backlevel1_list))
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel1_list));
        }
        while(!gdsl_list_is_empty(backlevel2_list))
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel2_list));
        }
        while(gdsl_list_get_size(return_list) < count)
        {		
            gdsl_list_insert_tail(return_list, gdsl_list_remove_head(backlevel3_list));
        }
    }
    else
    {
        //数量为0 随机补
        uint32_t size = 0;
        srand((unsigned)time(NULL));
        if (size = gdsl_list_get_size(node_list) > 0)
        {
            no = (rand() % size) + 1;
        } 
        node = gdsl_list_search_by_position(node_list, no);
        if(gdsl_list_get_size(return_list) == 0)
        {
            gdsl_list_insert_tail(return_list, node);
        } 
    }

    gdsl_list_free(backlevel1_list);
    gdsl_list_free(backlevel2_list);
    gdsl_list_free(backlevel3_list);

    return return_list;
}

gdsl_list_t mod_route(gdsl_list_t node_list, uint32_t ip ,uint16_t gtype,gdsl_list_t return_list)
{   char iptmp[32] = {0};
    sprintf(iptmp, "%d%d", ip, gtype);
    uint32_t size = 0;
    int no = 0;
    if (size = gdsl_list_get_size(node_list) > 0)
    {
        no = (atoi(iptmp) % size) +1;
    } 
    node_t *node = gdsl_list_search_by_position(node_list, no);
    gdsl_list_insert_tail(return_list, node );

    return return_list ;
}

gdsl_list_t random_route(gdsl_list_t node_list,gdsl_list_t return_list)
{						 //数量为0 随机补
    uint32_t size = 0;
    int no = 0;
    srand((unsigned)time(NULL));
    size = gdsl_list_get_size(node_list);
    if (size > 0)
    {
        no = (rand() % size) + 1;
        node_t *node = gdsl_list_search_by_position(node_list, no);
        gdsl_list_insert_tail(return_list, node);
    } 
    return return_list;
}


////////----------------YUCLEE
int get_domain(char *domain, char *url, int len)
{
    char *st = strstr(url, "&dom=");
    if(NULL != st)
    {
        char *ed = strstr(st+5, "&");
        if(NULL != ed)
        {
            if(len >= ed-st-4)
            {
                memcpy(domain, st+5, ed-st-5);
                return 0;
            }
        }
    }
    return -1;
}


gdsl_list_t redis_route(gdsl_list_t node_list, gdsl_list_t return_list, const char *domain)
{ 
    uint32_t size = 0;
    char g_domain[100] = {0};
    node_t *n_node[100] = {0};
    int n_num = 0;
    size = gdsl_list_get_size(node_list);
    if (size > 0)
    {
        for(size; size > 0; size--)
        {
            memset(g_domain, 0, sizeof(g_domain));
            node_t *node = gdsl_list_search_by_position(node_list, size);

            if(0 == get_domain(g_domain, node->url, sizeof(g_domain)))
            {
                if(0 == strcmp(g_domain, domain))
                {
                    n_node[n_num] = node;
                    n_num ++;
                    if(n_num >= 100)
                        break;
//                    gdsl_list_insert_tail(return_list, node);
                }
            }
        }
    }
    if(n_num > 0)
    {
        srand((unsigned)time(NULL));
        int no = (rand() % n_num);
        gdsl_list_insert_tail(return_list, n_node[no]);
    }

    return return_list;
}


gdsl_list_t dns_route(char *areacode, uint32_t ip, char *isp, gdsl_list_t node_list, uint16_t gtype, uint32_t count, const char *domain)
{
//        LOG(LOG_LEVEL_DEBUG, "areacode:[%s] ip[%d] isp[%s] gtype[%hu] conut[%d] domain[%s].\n", areacode, ip, isp, gtype, count, domain);
    gdsl_list_t return_list = gdsl_list_alloc(NULL, NULL, node_t_free);
    switch (gtype)
    {
        case 1:
            return_list	= area_route(areacode, node_list, isp, count, return_list);
            break;
        case 2:
            return_list = mod_route(node_list, ip, gtype, return_list);
            break;
        case 3:
            return_list = random_route(node_list,return_list);
            //return_list = redis_route(node_list, return_list, domain);
            break;
        default:
            //若非3种 默认随机
            return_list = random_route(node_list, return_list);
    }
    if((gdsl_list_is_empty(return_list)) == 0)
        return return_list;
    else 
        return NULL;

}
