/*************************************************************************
  File Name   :    register/core.c
Author      :    Gzz 
Mail        :    
Created Time:    2016年12月27日 星期二 14时58分47秒
 *************************************************************************/

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
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
#include <sys/queue.h>

#include "obj.h"
#include "msg.h"
#include "arch.h"
#include "redis.h"
#include "threads.h"

#define ERR      -1
#define SUC       0

#define REGBUSINESS "/register/business?"
#define REGDOMAIN    "/register/domain?"
#define ADDNODE      "/add/node?"
#define SCHDOMAIN    "/get/domain?"
#define SCHBUSINESS "/get/business?"
#define SCHNODE      "/get/node?"
#define DELDOMAIN    "/del/domain?"
#define DELNODE      "/del/node?"
#define DELBUSINESS "/del/business?"
#define FLUSHDB      "/master/ctl?"   

struct event_base *regbase = NULL;
pthread_mutex_t type_lock;
pthread_mutex_t send_lock;
//void httpd_handler(struct evhttp_request*req, void *reqtmp); 
char	BUSINESS_name[64] = {0};
char    max_score[10] = {0};
char    score[10] = {0};
char    tmpscore[10] = {0};

typedef enum {
    REG_BUSINESS = 1,
    REG_DOMAIN,
    ADD_NODE,
    SCH_DOMAIN,
    SCH_BUSINESS,
    SCH_NODE,
    DEL_DOMAIN,
    DEL_NODE,
    DEL_BUSINESS,
    FLUSH_DB
}UCMD;
typedef struct register_param{
    char	ip[16];
    char    name[128];
    char 	dom[256];
    char 	type[51];   
    char 	btype[51];   //- use for business type
    char 	area[8];   //- use for business type
    char    isp[4];
    char    ttl[8];
    char    cycle[8];
    char    uri[1024];
    char    port[10];
    char 	ptype[51]; //- use for register type
    char 	gtype[51]; //- use for register type
    char 	dtype[51]; //- use for register type
    char    desc[128];
    char    cname[128];
    char    inuse[4];
    char    db[4];
    char    opper[128];
    char    businessnum[8];
    //1 register BUSINESS, 2 register domain, 3 add node, 4 search domain,
    //5 search BUSINESS, 6 search node, 7 del domain, 8 del node, 9 del business.
    UCMD    cmd;
}register_param_t;
///////////////////////////////////////////////////////////////////////////////////////
//
void httpd_handler(void *);

register_param_t *register_filter(char *uri, char *out);
static int register_opper(register_param_t *reg_param, char *out);


///////////////////////////////////////////////////////////////////////////////////////
    void 
myfree(void  *d)
{
    register_param_t *data=(register_param_t *)d;

    if (data != NULL)
    {
        free(data);
        data = NULL;
    }
}
    int 
mystrlen(const char* str)
{
    if (str != NULL)
        return strlen(str);
    else
        return 0;
}
    static int
get_dns_type_score(int i,const char *str,void *phint)
{
    memset(tmpscore, 0, sizeof(tmpscore));
    strcpy(tmpscore, str);
    return 0 ;
}

    static int
get_dns_type_max_score(int i,const char *str,void *phint)
{
    strcpy(max_score, str);
    strcpy(score, max_score);
    return 0 ;
}
    static int
get_dns_type_max_key(int i,const char *str,void *phint)
{
    strcpy(BUSINESS_name, str);
    return 0 ;

}
    static int
get_dns_type(int i, const char * str, void *phint)
{
    register_param_t *reg_para = (register_param_t *)phint;
    // check_type();
    if (str != NULL)
    {
        strcpy(score,str);
    }

    return 0;
}
int bucode = 0;
    static int
get_max_bcode(int i,const char *str,void *phint)
{
    int bcode = 0;
    if (!(i % 2))
    {
        bcode = atoi(str);
        bucode = bcode > bucode ? bcode : bucode;
    }
    return 0 ;
}

    static int
get_business(int i,const char *str,void *phint)
{
    char *ptr = (char *)phint;
    char buf[128] = {0};
    if (i % 2)
    {
        snprintf(buf, sizeof(buf), "Business name : %s, ", str); 
    }
    else
    {
        snprintf(buf, sizeof(buf), "bcode : %s\n", str);
    }
    strcat(ptr, buf); 
    //LOGN("business", "%d, %s\n", i, str);
    //strcpy(BUSINESS_name, str);
    return 0 ;
}

    static int
get_dns_null(int i, const char *str, void *phint)
{
    return 0;
}
    static int 
register_check(register_param_t *reg_para)
{
    //查询业务编号，有：返回 无：新建返回
    // char *cmd = (char *)calloc(CMDLEN,1);
    char cmd[CMDLEN] = {0};
    int current_score = 0;
    memset(cmd, 0, CMDLEN);
    // pthread_mutex_lock(&type_lock);
    snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:btype:register %s",reg_para->btype);
    int ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type);
    if (ret)
    {
        snprintf(cmd,CMDLEN,"ZRANGEBYSCORE cdn:dns:btype:register -inf +inf ");
        ret =redis_get_info(NULL, cmd, (void *)reg_para,get_dns_type_max_key);
        if(!ret) 
        {
            memset(cmd,0, CMDLEN);
            snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:btype:register %s ",BUSINESS_name);
            ret =redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type_max_score);
            PRINT("%d\n",atoi(max_score));
        }
        else
        {
            strcpy(max_score , "0");
        }
        memset(cmd,0, CMDLEN);
        snprintf(cmd,CMDLEN,"ZADD cdn:dns:btype:register %d %s ",atoi(max_score)+1, reg_para->btype);
        ret =redis_get_info(NULL, cmd, (void *)reg_para,get_dns_null);
        current_score = atoi(max_score)+1; 
        //	pthread_mutex_unlock(&type_lock);

    }
    else
    {
        PRINT("%d\n",atoi(score));
        current_score = atoi(score); 
        //    pthread_mutex_unlock(&type_lock);
    }
    //查询域名是否插入可用表 ，已插入 inuse = 1 若否新建inuse=1
    snprintf(cmd,CMDLEN,"HGET cdn:dns:business:%d:%s  name",current_score,reg_para->dom);
    ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);
    if(!ret)
    {
        //非空
        snprintf(cmd,CMDLEN,"HSET cdn:dns:business:%d:%s  inuse 1",current_score,reg_para->dom);
        ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);

    }
    else
    {
        snprintf(cmd,CMDLEN,"HSET cdn:dns:business:%d:%s  name %s",current_score,reg_para->dom,reg_para->dom);
        ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);
        snprintf(cmd,CMDLEN,"HSET cdn:dns:business:%d:%s  inuse 1",current_score,reg_para->dom);
        ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);
    }
    uint64_t id =  inet_addr(reg_para->ip);
    PRINT("%ld = id\n",id);
    //生成node表 
    snprintf(cmd,CMDLEN,
            "HMSET cdn:dns:node:%ld-%s "
            "id %ld "
            "isp %s "
            "type %d "
            "btype %d "
            "ipaddr %s "
            "port %s "    
            "uri %s "
            "links 100 "
            "width 100 "
            "cpus 50 "
            "memorys 50 "
            "weight 0 "
            "inuse 1 "
            "ptype %d "
            "cycle 10 "
            "areacode 0 "
            , id, reg_para->port, id, reg_para->isp, current_score, current_score, reg_para->ip, reg_para->port, reg_para->uri, 
            memcmp(reg_para->ptype, "tcp", strlen(reg_para->ptype)) ? 1 : memcmp(reg_para->ptype, "http", strlen(reg_para->ptype)) ? 2 : 3);
    ret = redis_set_info(NULL, cmd);//, (void *)reg_para, get_dns_null);
    //生成gtype表 如果没有便插入 有则不作操作
    snprintf(cmd,CMDLEN,"HGET cdn:dns:businessconf:%d  num",current_score);
    if (ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null) )
    {
        snprintf(cmd,CMDLEN,
                "HMSET cdn:dns:businessconf:%d "
                "num    1 "
                "gtype  3 "
                "ttl    30 "
                ,current_score);
        ret = redis_set_info(NULL, cmd);
    } 
    return 0;

}
#if 1
    void 
httpd_handler_dispatch(struct evhttp_request* req ,void* pdata)
{
    httpd_handler( (void *)req);
    //pthread_mutex_lock(&send_lock);
    //threads_dispatch(((content_t *)pdata)->pools, httpd_handler, (void *)req, 0);
    //pthread_mutex_unlock(&send_lock);
}

#endif
    void 
httpd_handler( void *reqtmp) 
{
    struct evhttp_request *req = (struct evhttp_request*)reqtmp;
    char output[2048] = {0};
    //输出缓存区 
    struct evbuffer *buf = NULL;

    //获取客户端请求的URI(使用evhttp_request_uri或直接req->uri)
    const char *uri = NULL;

    uri = evhttp_request_uri(req);
    //decoded uri
    char *decoded_uri = evhttp_decode_uri(uri);
    register_param_t *reg_param = register_filter(decoded_uri, output);
    if (!reg_param)
        goto illegal;

    int errcode = register_opper(reg_param, output);
    LOG(LOG_LEVEL_NOTICE, "opper %d %s\n", errcode, output);
    switch (errcode)
    {
        case 0:
            //HTTP header
            evhttp_add_header(req->output_headers, "Server", "vind7");
            evhttp_add_header(req->output_headers, "Content-Type", "text/plain; charset=UTF-8");
            evhttp_add_header(req->output_headers, "Connection", "close");
            //输出的内容
            buf = evbuffer_new();
            evbuffer_add_printf(buf, "\t\tREQUEST SUCCESS\n%s\n", output);
            evhttp_send_reply(req, HTTP_OK, "OK", buf);
            evbuffer_free(buf);
            myfree(reg_param);
            break;
        default:
            goto illegal;
    }
    return ;

illegal:
    evhttp_add_header(req->output_headers, "Server", "vind7");
    evhttp_add_header(req->output_headers, "Content-Type", "text/plain; charset=UTF-8");
    evhttp_add_header(req->output_headers, "Connection", "close");
    buf = evbuffer_new();
    evbuffer_add_printf(buf, "dns  register url is illegal !!(\reg) !\n%s\n", output);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
    return;
}
    void 
register_dispatch(void *udata)
{
    event_base_dispatch(regbase);
}
    int
register_init(content_t *pdata )
{    
    uint16_t httpport = pdata->pconf->httpport;
    if(httpport == 0)
    {
        return ERR;
    }
    char *httpd_option_listen = "0.0.0.0";
    int httpd_option_timeout = 120; //in seconds

    pthread_mutex_init(&type_lock, 0);
    pthread_mutex_init(&send_lock, 0);
    regbase = event_base_new();
    if (!regbase) {
        fprintf(stderr, "creating event_base failed. Exiting.\n");
        return ERR;
    }

    struct evhttp *httpd = NULL;
    httpd = evhttp_new(regbase);	

    evhttp_bind_socket(httpd, httpd_option_listen, httpport);

    //指定generic callback
    evhttp_set_gencb(httpd, httpd_handler_dispatch, (void *)pdata);
    //	evhttp_set_gencb(httpd, httpd_handler, (void *)pdata);
    //也可以为特定的URI指定callback
    //evhttp_set_cb(httpd, "/", specific_handler, NULL);

    threads_dispatch(((content_t *)pdata)->pools, register_dispatch, (void *)pdata, 0);

    //	evhttp_free(httpd);

    return SUC;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
    UCMD
register_matchcmd(const char *uri)
{
    UCMD cmd = 0;
    if (!strncmp(uri, REGBUSINESS, strlen(REGBUSINESS)))
    {
        cmd = REG_BUSINESS;
    }
    else if (!strncmp(uri, ADDNODE, strlen(ADDNODE)))
    {
        cmd = ADD_NODE;
    }
    else if (!strncmp(uri, REGDOMAIN, strlen(REGDOMAIN)))
    {
        cmd = REG_DOMAIN;
    }
    else if (!strncmp(uri, SCHDOMAIN, strlen(SCHDOMAIN)))
    {
        cmd = SCH_DOMAIN;
    }
    else if (!strncmp(uri, SCHBUSINESS, strlen(SCHBUSINESS)))
    {
        cmd = SCH_BUSINESS;
    }
    else if (!strncmp(uri, SCHNODE, strlen(SCHNODE)))
    {
        cmd = SCH_NODE;
    }
    else if (!strncmp(uri, DELDOMAIN, strlen(DELDOMAIN)))
    {
        cmd = DEL_DOMAIN;
    }
    else if (!strncmp(uri, DELNODE, strlen(DELNODE)))
    {
        cmd = DEL_NODE;
    }
    else if (!strncmp(uri, DELBUSINESS, strlen(DELBUSINESS)))
    {
        cmd = DEL_BUSINESS;
    }
    else if (!strncmp(uri, FLUSHDB, strlen(FLUSHDB)))
    {
        cmd = FLUSH_DB;
    }
    LOG(LOG_LEVEL_NOTICE, "cmd %d\n", cmd);
    return cmd;
}

    bool
parse_register_business(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "name=%s\n", evhttp_find_header(&params, "name"));
    if (mystrlen(evhttp_find_header(&params, "name")) != 0 &&
            mystrlen(evhttp_find_header(&params, "name")) <= 128)
    {
        strncpy(reg_param->name, evhttp_find_header(&params, "name"),strlen(evhttp_find_header(&params, "name")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "gtype=%s\n", evhttp_find_header(&params, "gtype"));
    if (mystrlen(evhttp_find_header(&params, "gtype")) != 0 &&
            mystrlen(evhttp_find_header(&params, "gtype")) <= 8)
    {
        strncpy(reg_param->gtype,evhttp_find_header(&params, "gtype"),strlen(evhttp_find_header(&params, "gtype")));
    }
    else
    {
        return false;
        //goto err;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "ttl=%s\n", evhttp_find_header(&params, "ttl"));
    if (mystrlen(evhttp_find_header(&params, "ttl")) != 0 &&
            mystrlen(evhttp_find_header(&params, "ttl")) <= 8)
    {
        strncpy(reg_param->ttl,evhttp_find_header(&params, "ttl"),strlen(evhttp_find_header(&params, "ttl")));
    }
    else
    {
        snprintf(reg_param->ttl, 8, "%d", 300);
        //return false;
        //goto err;
    }
    strcat(output, tmp);

    return true;
}
    bool
parse_register_domain(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "dom=%s\n", evhttp_find_header(&params, "dom"));
    if (mystrlen(evhttp_find_header(&params, "dom")) != 0 &&
            mystrlen(evhttp_find_header(&params, "dom")) <= 128)
    {
        strncpy(reg_param->dom,evhttp_find_header(&params, "dom"),strlen(evhttp_find_header(&params, "dom")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "name=%s\n", evhttp_find_header(&params, "name"));
    if (mystrlen(evhttp_find_header(&params, "name")) != 0 &&
            mystrlen(evhttp_find_header(&params, "name")) <= 128)
    {
        strncpy(reg_param->name,evhttp_find_header(&params, "name"),strlen(evhttp_find_header(&params, "name")));
    }
    else
    {
        return false;
        //goto err;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "dtype=%s\n", evhttp_find_header(&params, "dtype"));
    if (mystrlen(evhttp_find_header(&params, "dtype")) != 0 &&
            mystrlen(evhttp_find_header(&params, "dtype")) <= 8)
    {
        strncpy(reg_param->dtype, evhttp_find_header(&params, "dtype"),strlen(evhttp_find_header(&params, "dtype")));
    }
    else
    {
        snprintf(reg_param->dtype, 8, "%s", "A");
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "cname=%s\n", evhttp_find_header(&params, "cname"));
    if (mystrlen(evhttp_find_header(&params, "cname")) != 0 &&
            mystrlen(evhttp_find_header(&params, "cname")) <= 8)
    {
        strncpy(reg_param->cname, evhttp_find_header(&params, "cname"),strlen(evhttp_find_header(&params, "cname")));
    }
    else
    {
        snprintf(reg_param->cname, 128, "%s", "null");
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "inuse=%s\n", evhttp_find_header(&params, "inuse"));
    if (mystrlen(evhttp_find_header(&params, "inuse")) != 0 &&
            mystrlen(evhttp_find_header(&params, "inuse")) <= 8)
    {
        strncpy(reg_param->inuse, evhttp_find_header(&params, "inuse"),strlen(evhttp_find_header(&params, "inuse")));
    }
    else
    {
        snprintf(reg_param->inuse, 8, "%d", 1);
    }
    strcat(output, tmp);

    return true;
}
    bool
parse_add_node(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "ip=%s\n", evhttp_find_header(&params, "ip"));
    if (mystrlen(evhttp_find_header(&params, "ip")) != 0 &&
            mystrlen(evhttp_find_header(&params, "ip")) <= 16)
    {
        strncpy(reg_param->ip,evhttp_find_header(&params, "ip"),strlen(evhttp_find_header(&params, "ip")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "port=%s\n", evhttp_find_header(&params, "port"));
    if (mystrlen(evhttp_find_header(&params, "port")) != 0 &&
            mystrlen(evhttp_find_header(&params, "port")) <= 8)
    {
        strncpy(reg_param->port,evhttp_find_header(&params, "port"),strlen(evhttp_find_header(&params, "port")));
    }
    else
    {
        snprintf(reg_param->port, 8, "%s", "0");
        //return false;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "isp=%s\n", evhttp_find_header(&params, "isp"));
    if (mystrlen(evhttp_find_header(&params, "isp")) != 0 &&
            mystrlen(evhttp_find_header(&params, "isp")) <= 6)
    {
        strncpy(reg_param->isp,evhttp_find_header(&params, "isp"),strlen(evhttp_find_header(&params, "isp")));
    }
    else
    {
        ;//goto err;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "uri=%s\n", evhttp_find_header(&params, "uri"));
    if (mystrlen(evhttp_find_header(&params, "uri")) != 0 &&
            mystrlen(evhttp_find_header(&params, "uri")) <= 1023)
    {
        strncpy(reg_param->uri,evhttp_find_header(&params, "uri"),strlen(evhttp_find_header(&params, "uri")));
    }
    else
    {
        ;//goto err;
    }
    strcat(output, tmp);



    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "name=%s\n", evhttp_find_header(&params, "name"));
    if (mystrlen(evhttp_find_header(&params, "name")) != 0 &&
            mystrlen(evhttp_find_header(&params, "name")) <= 128)
    {
        strncpy(reg_param->name, evhttp_find_header(&params, "name"),strlen(evhttp_find_header(&params, "name")));
    }
    else
    {
        snprintf(reg_param->name, 8, "%s", "null");
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "ptype=%s\n", evhttp_find_header(&params, "ptype"));
    if (mystrlen(evhttp_find_header(&params, "ptype")) != 0 &&
            mystrlen(evhttp_find_header(&params, "ptype")) <= 8)
    {
        strncpy(reg_param->ptype, evhttp_find_header(&params, "ptype"),strlen(evhttp_find_header(&params, "ptype")));
    }
    else
    {
        snprintf(reg_param->ptype, 8, "%s", 4); //defaule a-recored.
    }
    strcat(output, tmp);
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "area=%s\n", evhttp_find_header(&params, "area"));
    if (mystrlen(evhttp_find_header(&params, "area")) != 0 &&
            mystrlen(evhttp_find_header(&params, "area")) <= 8)
    {
        strncpy(reg_param->area, evhttp_find_header(&params, "area"),strlen(evhttp_find_header(&params, "area")));
    }
    else
    {
        snprintf(reg_param->area, 128, "%s", "null");
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "cycle=%s\n", evhttp_find_header(&params, "cycle"));
    if (mystrlen(evhttp_find_header(&params, "cycle")) != 0 &&
            mystrlen(evhttp_find_header(&params, "cycle")) <= 8)
    {
        strncpy(reg_param->cycle, evhttp_find_header(&params, "cycle"),strlen(evhttp_find_header(&params, "cycle")));
    }
    else
    {
        snprintf(reg_param->cycle, 8, "%d", 300);
    }
    strcat(output, tmp);


    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "inuse=%s\n", evhttp_find_header(&params, "inuse"));
    if (mystrlen(evhttp_find_header(&params, "inuse")) != 0 &&
            mystrlen(evhttp_find_header(&params, "inuse")) <= 8)
    {
        strncpy(reg_param->inuse, evhttp_find_header(&params, "inuse"),strlen(evhttp_find_header(&params, "inuse")));
    }
    else
    {
        snprintf(reg_param->inuse, 8, "%d", 1);
    }
    strcat(output, tmp);

    return true;
}
    bool
parse_get_domain(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "dom=%s\n", evhttp_find_header(&params, "dom"));
    if (mystrlen(evhttp_find_header(&params, "dom")) != 0 &&
            mystrlen(evhttp_find_header(&params, "dom")) <= 128)
    {
        strncpy(reg_param->dom,evhttp_find_header(&params, "dom"),strlen(evhttp_find_header(&params, "dom")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);
    return true;
}
    bool
parse_get_business(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    bool no = true;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "name=%s\n", evhttp_find_header(&params, "name"));
    if (mystrlen(evhttp_find_header(&params, "name")) != 0 &&
            mystrlen(evhttp_find_header(&params, "name")) <= 128)
    {
        strncpy(reg_param->name,evhttp_find_header(&params, "name"),strlen(evhttp_find_header(&params, "name")));
    }
    else
    {
        memset(reg_param->name, 0, sizeof(reg_param->name));
        no = false;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "opper=%s\n", evhttp_find_header(&params, "opper"));
    if (mystrlen(evhttp_find_header(&params, "opper")) != 0 &&
            mystrlen(evhttp_find_header(&params, "opper")) <= 128)
    {
        strncpy(reg_param->opper, evhttp_find_header(&params, "opper"),strlen(evhttp_find_header(&params, "opper")));
        no = true;
    }
    else
    {
        memset(reg_param->opper, 0, sizeof(reg_param->opper));
    }
    strcat(output, tmp);

    return no;
}
    bool
parse_get_node(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "ip=%s\n", evhttp_find_header(&params, "ip"));
    if (mystrlen(evhttp_find_header(&params, "ip")) != 0 &&
            mystrlen(evhttp_find_header(&params, "ip")) <= 16)
    {
        strncpy(reg_param->ip,evhttp_find_header(&params, "ip"),strlen(evhttp_find_header(&params, "ip")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "port=%s\n", evhttp_find_header(&params, "port"));
    if (mystrlen(evhttp_find_header(&params, "port")) != 0 &&
            mystrlen(evhttp_find_header(&params, "port")) <= 8)
    {
        strncpy(reg_param->port,evhttp_find_header(&params, "port"),strlen(evhttp_find_header(&params, "port")));
    }
    else
    {
        snprintf(reg_param->port, 8, "%d", 0);
    }
    strcat(output, tmp);

    return true;
}
    bool
parse_del_domain(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "dom=%s\n", evhttp_find_header(&params, "dom"));
    if (mystrlen(evhttp_find_header(&params, "dom")) != 0 &&
            mystrlen(evhttp_find_header(&params, "dom")) <= 128)
    {
        strncpy(reg_param->dom,evhttp_find_header(&params, "dom"),strlen(evhttp_find_header(&params, "dom")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);
    return true;
}

    bool
parse_del_node(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "ip=%s\n", evhttp_find_header(&params, "ip"));
    if (mystrlen(evhttp_find_header(&params, "ip")) != 0 &&
            mystrlen(evhttp_find_header(&params, "ip")) <= 16)
    {
        strncpy(reg_param->ip,evhttp_find_header(&params, "ip"),strlen(evhttp_find_header(&params, "ip")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "port=%s\n", evhttp_find_header(&params, "port"));
    if (mystrlen(evhttp_find_header(&params, "port")) != 0 &&
            mystrlen(evhttp_find_header(&params, "port")) <= 8)
    {
        strncpy(reg_param->port,evhttp_find_header(&params, "port"),strlen(evhttp_find_header(&params, "port")));
    }
    else
    {
        ;
    }
    strcat(output, tmp);
    return true;
}
    bool
parse_del_business(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "btype=%s\n", evhttp_find_header(&params, "btype"));
    if (mystrlen(evhttp_find_header(&params, "db")) != 0 &&
            mystrlen(evhttp_find_header(&params, "db")) <= 8)
    {
        strncpy(reg_param->btype,evhttp_find_header(&params, "btype"),strlen(evhttp_find_header(&params, "btype")));
    }
    else
    {
        ;
    }
    strcat(output, tmp);

    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "name=%s\n", evhttp_find_header(&params, "name"));
    if (mystrlen(evhttp_find_header(&params, "name")) != 0 &&
            mystrlen(evhttp_find_header(&params, "name")) <= 128)
    {
        strncpy(reg_param->name,evhttp_find_header(&params, "name"),strlen(evhttp_find_header(&params, "name")));
    }
    else
    {
        ;
    }
    strcat(output, tmp);
    return true;
}

    bool
parse_flushdb(const char *uri, char *out, register_param_t *reg_param)
{
    struct evkeyvalq params;
    evhttp_parse_query(uri, &params);
    char tmp[1024] = {0};
    char *output = out;
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp), "db=%s\n", evhttp_find_header(&params, "db"));
    if (mystrlen(evhttp_find_header(&params, "db")) != 0 &&
            mystrlen(evhttp_find_header(&params, "db")) <= 16)
    {
        strncpy(reg_param->db,evhttp_find_header(&params, "db"),strlen(evhttp_find_header(&params, "db")));
    }
    else
    {
        return false;
    }
    strcat(output, tmp);
    return true;
}
    register_param_t * 
register_filter(char *uri, char *out)
{
    register_param_t *reg_param = (register_param_t *)calloc(1 , sizeof(register_param_t));
    char tmp[1024] = {0};

    reg_param->cmd = register_matchcmd(uri);
    if (!reg_param->cmd)
    {
        goto err;
    }

    switch(reg_param->cmd)
    {
        case REG_BUSINESS:
            if (!parse_register_business(uri, out, reg_param))
                goto err;
            break;
        case REG_DOMAIN:
            if (!parse_register_domain(uri, out, reg_param))
                goto err;
            break;
        case ADD_NODE:
            if (!parse_add_node(uri, out, reg_param))
                goto err;
            break;
        case SCH_DOMAIN:
            if (!parse_get_domain(uri, out, reg_param))
                goto err;
            break;
        case SCH_BUSINESS:
            if (!parse_get_business(uri, out, reg_param))
                goto err;
            break;
        case SCH_NODE:
            if (!parse_get_node(uri, out, reg_param))
                goto err;
            break;
        case DEL_DOMAIN:
            if (!parse_del_domain(uri, out, reg_param))
                goto err;
            break;
        case DEL_NODE:
            if (!parse_del_node(uri, out, reg_param))
                goto err;
            break;
        case DEL_BUSINESS:
            if (!parse_del_business(uri, out, reg_param))
                goto err;
            break;
        case FLUSH_DB:
            if (!parse_flushdb(uri, out, reg_param))
                goto err;
            break;
defaule:
            goto err;;
    }
    LOGN("parse", "parse %s\n", out);
    return reg_param;
err:
    if (reg_param)
        free(reg_param);
    return NULL;
}
///////////////////////////////////////////////////////////////////////
// execl cmd
//
    static int 
opper_business(char *out, register_param_t *reg_para)
{
    //查询业务编号，有：返回 无：新建返回
    char cmd[CMDLEN] = {0};
    int current_score = 0;
    memset(cmd, 0, CMDLEN);
    switch(reg_para->cmd)
    {
        case REG_BUSINESS:
            {
                snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:business:register %s",reg_para->name);
                int ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type);
                if (ret)
                {
                    snprintf(cmd,CMDLEN,"ZRANGEBYSCORE cdn:dns:business:register -inf +inf withscores");
                    ret =redis_get_info(NULL, cmd, (void *)reg_para, get_max_bcode);

                    PRINT("%d\n",atoi(score));
                    current_score = bucode; 
                    memset(cmd,0, CMDLEN);
                    snprintf(cmd,CMDLEN,"ZADD cdn:dns:business:register %d %s ", current_score + 1, reg_para->name);
                    ret =redis_get_info(NULL, cmd, (void *)reg_para,get_dns_null);
                    current_score ++; 
                    LOGN("business", "zadd business %s bcode %d\n", reg_para->name, current_score);
                }
                else
                {
#if 0
                    snprintf(cmd,CMDLEN,"ZRANGEBYSCORE cdn:dns:business:register -inf +inf ");
                    ret =redis_get_info(NULL, cmd, (void *)reg_para,get_dns_type_max_key);
                    if(!ret) 
                    {
                        memset(cmd,0, CMDLEN);
                        snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:business:register %s ", reg_para->name);
                        ret =redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type_max_score);
                        PRINT("%d\n",atoi(max_score));
                    }
                    else
                    {
                        strcpy(max_score , "0");
                    }
                    memset(cmd,0, CMDLEN);
                    snprintf(cmd,CMDLEN,"ZADD cdn:dns:business:register %d %s ",atoi(max_score)+1, reg_para->name);
                    ret =redis_get_info(NULL, cmd, (void *)reg_para,get_dns_null);
#endif
                    current_score = atoi(score); 
                }

                //生成gtype表 如果没有便插入 有则不作操作
                snprintf(cmd,CMDLEN,"HGET cdn:dns:business:conf:%d  num",current_score);
                if (ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null) )
                {
                    snprintf(cmd,CMDLEN,
                            "HMSET cdn:dns:business:conf:%d "
                            "name  %s "
                            "num    1 "
                            "gtype  %s "
                            "ttl    %s "
                            "business_code  %d "
                            ,current_score, reg_para->name, reg_para->gtype, reg_para->ttl, current_score);
                    ret = redis_set_info(NULL, cmd);
                } 
            }
            break;
        case SCH_BUSINESS:
            {
                int code = 0;
                if (strlen(reg_para->name)) // Search one business info.
                {
                    snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:business:register %s",reg_para->name);
                    int ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type_score/*get_dns_type*/);
                    code = atoi(tmpscore);
                    char tmp[128] = {0};
                    snprintf(tmp, sizeof(tmp), "\n %s code is %d, if code == 0, the business is not registered. ", reg_para->name, code);
                    strcat(out, tmp);
                    LOGN("BUSINESS", "%s %s\n", reg_para->name, tmpscore);
                }
                else
                {
                    char buf[1024] = {0};
                    snprintf(cmd,CMDLEN,"ZRANGE cdn:dns:business:register 0 -1 WITHSCORES");
                    int ret =redis_get_info(NULL, cmd, (void *)buf, get_business);
                    strcat(out, buf); 
                }
            }
            break;
        default:
            break;
    }
    return 0;
}
    static int 
opper_domain(char *out, register_param_t *reg_para)
{
    //查询业务编号，有：返回 无：新建返回
    // char *cmd = (char *)calloc(CMDLEN,1);
    char cmd[CMDLEN] = {0};
    char tmp[512] = {0};
    int current_score = 0;
    memset(cmd, 0, CMDLEN);
    switch(reg_para->cmd)
    {
        case REG_DOMAIN:
            {
                snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:business:register %s",reg_para->name);
                int ret =redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type_score);
                if (ret)//Not find business.
                {
                    snprintf(tmp, sizeof(tmp), "not find business %s registered ", reg_para->name);
                    strcat(out, tmp);
                    return -1;
                }
                memset(tmp, 0, sizeof(tmp));

                int tmpcode = atoi(tmpscore);
                //查询域名是否插入可用表 ，已插入 inuse = 1 若否新建inuse=1
                snprintf(cmd,CMDLEN,"HGET cdn:dns:business:%d:%s  domain", tmpcode, reg_para->dom);
                ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);
                if(!ret)//Find domain, update inuse.
                {
                    snprintf(tmp, sizeof(tmp), "update domain %s with ", reg_para->name);
                }
                else
                {
                    snprintf(tmp, sizeof(tmp), "add new domain %s with ", reg_para->name);
                }
                strcat(out, tmp);
                snprintf(cmd,CMDLEN,"HMSET cdn:dns:business:%d:%s domain %s cname %s dtype %s inuse %s",
                        tmpcode, reg_para->dom, reg_para->dom, reg_para->cname, reg_para->dtype, reg_para->inuse);
                ret = redis_get_info(NULL, cmd, (void *)reg_para, get_dns_null);
                strcat(out, cmd);
            }
            break;
        default:
            return -1;
    }
    return 0;

}
    static int 
opper_node(char *out, register_param_t *reg_para)
{
    char cmd[CMDLEN] = {0};
    char tmp[512] = {0};
    int current_score = 0;
    memset(cmd, 0, CMDLEN);
    switch(reg_para->cmd)
    {
        case ADD_NODE:
            {
                snprintf(cmd,CMDLEN,"ZSCORE cdn:dns:business:register %s",reg_para->name);
                int ret =redis_get_info(NULL, cmd, (void *)reg_para, get_dns_type_score);
                if (ret)//Not find business.
                {
                    snprintf(tmp, sizeof(tmp), "not find business %s registered ", reg_para->name);
                    strcat(out, tmp);
                    //don't need return.
                }
                memset(tmp, 0, sizeof(tmp));

                int code = atoi(tmpscore);

                snprintf(cmd,CMDLEN,
                        "HMSET cdn:dns:node:%s-%s "
                        "id 1 "
                        "isp %s "
                        "type 1 "
                        "business %s "
                        "bcode %d "
                        "ipaddr %s "
                        "port %s "    
                        "uri %s "
                        "links 100 "
                        "width 100 "
                        "cpus 50 "
                        "memorys 50 "
                        "weight 0 "
                        "inuse %s "
                        "ptype %s "
                        "cycle %s "
                        "areacode %s "
                        , reg_para->ip, reg_para->port, reg_para->isp, reg_para->name, code, reg_para->ip, reg_para->port, reg_para->uri, 
                        reg_para->inuse, /*memcmp(reg_para->ptype, "tcp", strlen(reg_para->ptype)) ? 1 : memcmp(reg_para->ptype, "http", strlen(reg_para->ptype)) ? 2 : 3*/ reg_para->ptype, reg_para->cycle, reg_para->area);
                ret = redis_set_info(NULL, cmd);//, (void *)reg_para, get_dns_null);
                //生成gtype表 如果没有便插入 有则不作操作
            }
            break;
        default:
            break;
    }
    return 0;

}
    static int 
opper_db(char *out, register_param_t *reg_para)
{
    char cmd[CMDLEN] = {0};
    int current_score = 0;
    memset(cmd, 0, CMDLEN);

    snprintf(cmd,CMDLEN,"flushdb");
    redis_set_info(NULL, cmd);
    strcat(out, cmd);
    return 0;
}

    static int 
register_opper(register_param_t *reg_param, char *out)
{
    int err = -1;
    if (!reg_param || !out)
        return err;

    switch(reg_param->cmd)
    {
        case REG_BUSINESS:
            if (opper_business(out, reg_param))
                goto err;
            break;
        case REG_DOMAIN:
            if (opper_domain(out, reg_param))
                goto err;
            break;
        case ADD_NODE:
            if (opper_node(out, reg_param))
                goto err;
            break;
        case SCH_DOMAIN:
            if (opper_domain(out, reg_param))
                goto err;
            break;
        case SCH_BUSINESS:
            if (opper_business(out, reg_param))
                goto err;
            break;
        case SCH_NODE:
            if (opper_node(out, reg_param))
                goto err;
            break;
        case DEL_DOMAIN:
            if (opper_domain(out, reg_param))
                goto err;
            break;
        case DEL_NODE:
            if (opper_node(out, reg_param))
                goto err;
            break;
        case DEL_BUSINESS:
            if (opper_business(out, reg_param))
                goto err;
            break;
        case FLUSH_DB:
            if (opper_db(out, reg_param))
                goto err;
            break;
defaule:
            goto err;;
    }
    err = 0;
    return err; 
err:

    return err;
}
