/*************************************************************************
*  File Name   :    probe.c
*  Author      :    sunzg
*  Mail        :    suclinux@gmail.com
*  Created Time:    Mon Jun 20 16:28:43 2016
**************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <event.h>

#include "threads.h"
#include "probe.h"
#include "obj.h"
#include "store.h"
#include "arch.h"

#define  PNODE_INIT     0
#define  PNODE_PROBING  1
#define  PNODE_PROBED   2
#define  PNODE_PROBEER  3

#define  PROBE_TCP      1
#define  PROBE_WEB      2

#define  BUFFER_SIZE    1024
#define   HTTP_GET       "GET /test HTTP/1.1\r\n" \
                         "Host: somehost\r\n"     \
                         "Connection: close\r\n"  \
                         "\r\n"


static void super_probe(void *udata);
static void readcb(struct bufferevent *bev, void *arg);
static void probe_cbtimeout(evutil_socket_t fd, short what, void *arg);
static void launch_probe(void *pdata);
static void action_eventcb(struct bufferevent *bev, short events, void *user_data);
#if 0
static probe_node_t *copy_node(node_t *des, node_t *src);
probe_add(void *udata, int type, const char *host, short port, const char *url, int cycle, probecb cb);
#endif
typedef struct {
    struct event       *nev;
    struct event_base  *evbase; 

    struct timeval      tv;

    // probe type, 1 use tcp probe, 2 use web probe.
    int                 probe_type;
    struct bufferevent *bev;
    // tcp probe ip and port.
    char               *host;
    short               port;
    // http probe source info.
    char               *url;
    // timer
    int                 cycle;

    // node status, 0 init, 1 normal.
    int                 pstatus;
    // node callback func, probe_add init.
    probecb             probe_report;

    //probe_unit_t       *unit;

    time_t              update;
    void               *udata;

} probe_node_t;

static int cbconnect (struct bufferevent *bev, probe_node_t *pnode, int fd , int probe_type);
static void update_node(probe_node_t *,int); 
static void create_probeaction(probe_node_t *pnode);//, short port, const char *ip)
#if 1
typedef struct {

    struct bufferevent *bev;
    struct event       *timer;
    int                 status;

    probecb             probe_report;

    probe_node_t             *node;
    //probe_t            *probe;
} probe_unit_t;
#endif
typedef struct {
#if 1
    void            *evbase;
    void            *evsend;
    void            *evrecv;
#endif
    //    int              evsend;
    //   int              evrecv;
    struct event*    evtimer;
    gdsl_list_t      add_queue;
    gdsl_list_t      node_list;
    threadpool_t    *pools;
    pthread_mutex_t  mutex;

    void            *pvind;
} probe_t;


/////////////////////////////////////////////////////////////////////////
//

static struct event_base 
*probe_base = NULL;

static probe_t
*probe = NULL;

/////////////////////////////////////////////////////////////////////////
//
#if 0
static int http_tcpclient_send(int socket,char *buff,int size){  
    int sent=0,tmpres=0;  

    while(sent < size){  
        tmpres = send(socket,buff+sent,size-sent,0);  
        if(tmpres == -1){  
            return -1;  
        }  
        sent += tmpres;  
    }  
    return sent;  
}  
#endif

static void http_errcb(struct bufferevent *bev , short what, void *pnodetmp)
{
    probe_node_t *pnode = (probe_node_t *)pnodetmp;
    update_node(pnode, NODE_STATUS_UNSER);
}

static void http_readcb(struct bufferevent *bev, void *pnodetmp)  
{  
    probe_node_t *pnode = (probe_node_t *)pnodetmp;
    struct evbuffer *input, *output;
    char *request_line = NULL;
    size_t len = 0;
    input = bufferevent_get_input(bev);
    //其实就是取出bufferevent中的input
    output = bufferevent_get_output(bev);
    //其实就是取出bufferevent中的output

    size_t input_len = evbuffer_get_length(input);
    //printf("input_len: %d\n", input_len);
    size_t output_len = evbuffer_get_length(output);
    //printf("output_len: %d\n", output_len);
    while(1)  
    {  
        request_line = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF);//从evbuffer前面取出一行，用一个新分配的空字符结束的字符串返回这一行,EVBUFFER_EOL_CRLF表示行尾是一个可选的回车，后随一个换行符
        if(NULL == request_line)
        {
            //printf("The first line has not arrived yet.\n");
            update_node(pnode, NODE_STATUS_UNSER);
            free(request_line);//之所以要进行free是因为 line = mm_malloc(n_to_copy+1))，在这里进行了malloc
            break;
        }
        else
        {  
            printf("Get one line date: %s\n", request_line);  
            if(strstr(request_line, "OK") != NULL || strstr(request_line,"302") != NULL)  
            {  
                update_node(pnode, NODE_STATUS_INSER);
                free(request_line);  
                break;  
            }  
        }  
        update_node(pnode, NODE_STATUS_UNSER);
        free(request_line);  
    }  
    // mod by gzz
    bufferevent_free(pnode->bev);
}  

static int cbconnect (struct bufferevent *bev, probe_node_t* pnode, int fd , int probe_type)
{
    //    BEGIN
    int opt = 0, r = 0;
    socklen_t socklen;
    char buf[10] = "test";

    socklen = sizeof(int);
    //	r = getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&opt), &socklen);
    if (probe_type == 1)
    {
        r = send(fd, buf, 2, MSG_NOSIGNAL);
        //PRINT("探测发送 r = %d\n",r); 
        if (r > 0) 
        {
            //	PRINT("tcp probe success\n"); 
            //LOG(LOG_LEVEL_ERROR, "Sock_ER-(%d)%s.\n", errno, strerror(errno));
            return 0;
        } 
        else 
        {
            if(time(0) - pnode->update < 9)
            {
                bufferevent_settimeout(pnode->bev,0, 5);
                //		PRINT("tcp probe failed\n"); 
                return 1;	
            }
            return -1;
        }
    }
#if 0
    else if (probe_type == 2){
        char buf[1024]={0}; 
        sprintf(buf,HTTP_GET,"VOOLEDNS","53");  

        if(fcntl(fd,F_SETFL,0) < 0){ 
            //阻塞，即使前面设置的是非阻塞的，这里设为阻塞  
            PRINT("fcntl failed\n");     
        }     
        else{     
            PRINT("fcntl=%d\n",fcntl(fd,F_SETFL,0));     
        }  
        if(http_tcpclient_send(fd,buf,strlen(buf)) < 0){  
            PRINT("http_tcpclient_send failed..\n");  
            return -1;  
        }  
        //  PRINT("发送请求:\n%s\n",lpbuf);  

        if(http_tcpclient_recv(fd,buf) <= 0){  
            PRINT("http_tcpclient_recv failed\n");  
            return -1;  
        }  
        PRINT("http buf = %s\n",buf);
        if(strstr(buf,"200")){
            PRINT("http probe return 200"); 
            return 0;

        }else{
            PRINT("http probe failed\n"); 
            return -1;
        }
    }
#endif
}

void * new_probe(void *pdata)
{
    //struct bufferevent *evpair[2];
    probe = (probe_t *)calloc(sizeof(probe_t), sizeof(char));

    if (!probe) 
    {
        LOG(LOG_LEVEL_ERROR, "create probe error.\n");
        return NULL;
    }

    probe->add_queue = gdsl_list_alloc("probe add queue", NULL, NULL);
    probe->node_list = gdsl_list_alloc("probe node list", NULL, NULL);

    pthread_mutex_init(&probe->mutex, NULL);

    probe->pvind = pdata;

    probe->pools = threads_create(10, 10000, 0);

    probe_base   = event_base_new();
    //PRINT("heeheheheeheheheeheh\n");
    threads_dispatch(probe->pools, (void *)super_probe, (void *)probe, 0);

    return (void *)probe;
}

void free_probe(void *udata)
{

}

void probe_add(void *udata, int type, const char *host, short port, const char *url, int cycle, probecb cb)
    //probe_add(void *udata, void *node)
{
    PRINT("start probe_add\n");
    if (NULL == udata) 
    {
        LOG(LOG_LEVEL_INFO, "Find a null udata.");
        return ;
    }

    //probe_t *probe = (probe_t *)udata;
    probe_node_t  *node  = (probe_node_t *)calloc(sizeof(probe_node_t), sizeof(char));
    if (NULL == node) 
    {
        LOG(LOG_LEVEL_ERROR, "calloc pnode error.\n");
        return ;
    }
    node->host = (char *)calloc(strlen(host) +1, sizeof(char));
    memcpy(node->host, host, strlen(host));
    node->port = port;

    switch (type) {
        case 1:
            //        node->host = (char *)calloc(strlen(host) +1, sizeof(char));
            //        memcpy(node->host, host, strlen(host));
            //        node->port = port;
            break;
        case 2:
            node->url  = (char *)calloc(sizeof(char), strlen(url) +1);
            memcpy(node->url, url, strlen(url));
            break;
        default:
            break;
    }
    //PRINT("Find type %d\n", type);
    node->probe_type   = type;// == 1 ? PROBE_TCP : PROBE_WEB;
    node->cycle        = cycle;
    node->probe_report = cb;
    node->pstatus       = 0;
    node->udata        = udata;

    //PRINT("开始发管道\n");
    pthread_mutex_lock(&probe->mutex);
    gdsl_list_insert_tail(probe->add_queue, node);
    bufferevent_write((struct bufferevent *)probe->evsend, " ", 1);
    pthread_mutex_unlock(&probe->mutex);
    /*
     *bufferevent_write((struct event *)probe->evsend, " ", 1);
     */
}

void probe_refresh(void *udata, void *node)
{

}
///////////////////////////////////////////////////////////////////////////
//
static void super_probe(void *udata)
{
    //probe_t *probe     = (probe_t *)udata;
    struct timeval sec = {10, 0};

    probe->evbase = event_base_new();

    struct bufferevent *evpair[2] ;
    bufferevent_pair_new((struct event_base *)probe->evbase, 0, evpair);

    probe->evsend = evpair[0];
    probe->evrecv = evpair[1];
    bufferevent_setcb(evpair[1], readcb, NULL, NULL, NULL);
    //mod  by guanzhong 
    bufferevent_enable(evpair[1], EV_READ|EV_PERSIST);

    probe->evtimer = event_new((struct event_base *)probe->evbase, -1, EV_PERSIST|EV_TIMEOUT, probe_cbtimeout, udata);

    event_add((struct event *)probe->evtimer, &sec);

    event_base_dispatch((struct event_base *)probe->evbase);
}

/*    static void 
      addev(struct bufferevent *bev, void *node)
      {
      bufferevent_write(bev, " ", 1);
      }*/

static void http_writecb(struct bufferevent *bev, void *arg)    
{

    //PRINT("TEST2 \n");
    if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) 
    {
        /* enable reading of the reply */
        bufferevent_enable(bev, EV_READ);
    }
}

#if 1
static void readcb(struct bufferevent *bev, void *arg)
{
    //PRINT("读事件触发\n");
    if (bev == (struct bufferevent *)probe->evrecv) 
    {
        struct evbuffer *evbuf = evbuffer_new();
        char buffer[64] = {0};
        time_t t = time(0);
        struct tm *lt = localtime(&t);
        strftime(buffer, sizeof(buffer), "%H:%M:%S ", localtime(&t));
        PRINT("\t\t\t%s Find a pair notice\n", buffer);
        /* gratuitous test of bufferevent_read_buffer */
        bufferevent_read_buffer(bev, evbuf);

        //        bufferevent_disable(bev, EV_READ);
        int len = evbuffer_get_length(evbuf);

        //printf("\t get pair notice len %d.\n", len);
        //count -= len;
        PRINT("\t remain notice count %d.\n", len);
        if (evbuffer_get_length(evbuf) == 1) 
        {
            //test_ok+
        }
        probe_node_t *pnode = NULL;
        do{
            pthread_mutex_lock(&probe->mutex);
            pnode = gdsl_list_remove_head(probe->add_queue);
            pthread_mutex_unlock(&probe->mutex);
            if (pnode)
            {
                launch_probe((void *)pnode);
                //PRINT("pnode->ptype = %dhost=%s %d\n", pnode->probe_type,pnode->host, pnode->port);
            }
        }while(pnode);
        ///////////////////////////

#if 0
        bufferevent_setcb(evpair[0], readcb, NULL, NULL, NULL);
        bufferevent_enable(evpair[1], EV_READ);
#endif
        //threads_dispatch(probe->pools, (void *)launch_probe, (void *)pnode, 0);
        ///////////////////////////
#if 0
        if (node is new )
        {
            pthread_mutex_lock(&probe->mutex);
            gdsl_list_insert(probe->node_list, pnode->node);
            pthread_mutex_unlock(&probe->mutex);
        }
#endif
        evbuffer_free(evbuf);
    }
}
static void probe_cbtimeout(evutil_socket_t fd, short what, void *arg)
{
    char buffer[64] = {0};
    time_t t = time(0);
    struct tm *lt = localtime(&t);
    strftime(buffer, sizeof(buffer), "%H:%M:%S ", localtime(&t));

    //PRINT("PROBE %s Event ocurrence every 2 seconds.\n", buffer);
}

static void update_node(probe_node_t *node, int status)
{
    node->pstatus = status;
    node->probe_report(node->udata,status);
    //PRINT(" 哈哈哈node->host=%s,node->port=%u,%d\n",node->host,node->port,status);
}
#if 0
    static void 
pnode_cbtimeout(evutil_socket_t fd, short what, void *arg)
{
    probe_node_t *pnode = (probe_node_t *)arg;

    if (PNODE_PROBED != pnode->pstatus) {
        update_node(pnode->node, NODE_STATUS_UNSER);
        if (NODE_STATUS_UNUSE == pnode->node->inuse) {
            //event_del(pnode->timer);
            //event_free(pnode->timer);
        }
    }
    struct timeval tv_r;
    tv_r.tv_sec  = pnode->cycle;
    tv_r.tv_usec = 0;

    evtimer_add(pnode->timer, &tv_r);
    launch_probe(pnode);
}
#endif
#if 0
    static probe_node_t *
copy_node(probe_node_t *des, probe_node_t *src)
{
    memcpy(des->id, src->id, strlen(src->id));
    memcpy(des->ip, src->ip, strlen(src->ip));
    memcpy(des->url, src->url, strlen(src->url));
    des->port    = src->port;
    des->inuse   = src->inuse;
    des->status  = src->status;
    des->timekey = src->timekey;
    des->probekey= src->probekey;
    des->weights = src->weights;
    des->cycle   = src->cycle;

    return des;
}
#endif
static long int pnode_search_cb(const gdsl_element_t E, void *VALUE)
{
    probe_node_t *pnode = (probe_node_t *)E;
    probe_node_t *node = (probe_node_t*)VALUE;
    //if (pnode->ptype == PROBE_TCP) {
    if( (strcmp(pnode->host, node->host)) == 0 && (pnode->probe_type == node->probe_type) && pnode->port == node->port)
        return 0;
    else
        return 1;
    //}
#if 0
    if (pnode->ptype == PROBE_WEB) {
        if( (strcmp(pnode->url, node->url)) == 0)
            return 0;
        else 
            return 1;
    }
#endif
}

static probe_node_t *pnode_search(void *udata, probe_node_t *node)
{
    probe_node_t *pnode = NULL;
    probe_t *probe = (probe_t *) udata;
    pnode = (probe_node_t*)gdsl_list_search(probe->node_list,(gdsl_compare_func_t)pnode_search_cb, node);
    if (pnode)
        return pnode;
    else 
        return NULL;
}

static void launch_probe(void *pdata)
{
    pthread_mutex_lock(&probe->mutex);
    probe_node_t *pnode = (probe_node_t *)pdata;
    //printf("heheh ooooopnode->host = %s\n",pnode->host);
    //map node
    probe_node_t *hpnode = pnode_search(probe, pnode);
    if (hpnode) 
    {
        if (pnode != hpnode) 
        {
            //此处node未名，暂且只释放pnode
            //  if (pnode->node) {
            //      free(pnode->node);
            //      pnode->node = NULL;
            //  }
            hpnode->udata = pnode->udata;
            free(pnode);
        }
        pnode = hpnode;

    } 
    else 
    {
        gdsl_list_insert_tail(probe->node_list, pnode);
    }

    pthread_mutex_unlock(&probe->mutex);
    //printf("eheheh pnode->host = %s\n",pnode->host);
    //PRINT("Probe type %d\n", pnode->probe_type);
    switch (pnode->probe_type) 
    {
        case 1: //tcp 
            create_probeaction(pnode);
            break;
        case 2: // web
            create_probeaction(pnode);
            break;
        case 3:
            break;
        default:
            break;
    }
}

static void create_probeaction(probe_node_t *pnode)//, short port, const char *ip)
{
    struct sockaddr_in localhost;
    struct sockaddr *sa = NULL;
    memset(&localhost, 0, sizeof(localhost));

    localhost.sin_port = htons(pnode->port); /* pick-a-port */
    localhost.sin_addr.s_addr = inet_addr(pnode->host);
    localhost.sin_family = AF_INET;
    sa = (struct sockaddr *)&localhost;
    int i = 1;
    pnode->bev = bufferevent_socket_new((struct event_base *)probe->evbase, -1, 
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (pnode->probe_type == 1)
    {//tcp probe
        bufferevent_setcb(pnode->bev, NULL, NULL, action_eventcb, (void *)pnode);
        pnode->pstatus = PNODE_PROBING; 
        pnode->update = time(0);
        bufferevent_settimeout(pnode->bev,0, 5);
        bufferevent_enable(pnode->bev, EV_WRITE|EV_READ|EV_TIMEOUT);
        if ((i = bufferevent_socket_connect(pnode->bev, sa, sizeof(localhost))) < 0) 
        {
            PRINT("socket connect < 0.\n");
        }

    }
    else if (pnode->probe_type == 2)
    { //tcp
        bufferevent_setcb(pnode->bev, http_readcb,http_writecb, http_errcb, (void *)pnode);
        //  bufferevent_base_set(probe->evbase, pnode->bev);
        pnode->pstatus = PNODE_PROBING; 
        bufferevent_enable(pnode->bev, EV_WRITE|EV_READ|EV_TIMEOUT);
        if ((i = bufferevent_socket_connect(pnode->bev, sa, sizeof(localhost))) < 0) {
            PRINT("socket connect < 0.\n");
        }
        PRINT("TEST \n");
        bufferevent_write(pnode->bev , HTTP_GET, strlen(HTTP_GET));
        // event_base_dispatch(probe->evbase);
        //bufferevent_free(pnode->bev);


    }
    else
    {
        return;
    }


}

#if 0
    static void 
action_writecb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *output = bufferevent_get_output(bev);
    if (evbuffer_get_length(output) == 0) {
        PRINT("flushed answer\n");
        int fd = bufferevent_getfd(bev);
        char buf[2] = {"\0"};
        int i = read(fd, buf, 1);
        PRINT("i %d\n", i);
        if (!checkconnect (bufferevent_getfd(bev))) {
            PRINT("socket ok.!\n");
        } else {
            PRINT("socket er.!\n");
        }
        //bufferevent_free(bev);
    }
    /*if (msg) {
      PRINT("WRITE a MESSAGE.\n");
      bufferevent_write(bev, msg, ntohl(msg->len));
      PRINT("WRITE a MESSAGE END.\n");
      }*/

}
#endif


static void action_eventcb(struct bufferevent *bev, short events, void *user_data)
{
    PRINT("Find event\n");
    probe_node_t *pnode = (probe_node_t *)user_data;
    int fd = bufferevent_getfd(bev);
    int ret = 0;

    if (events & BEV_EVENT_CONNECTED)
    {
        if (!(ret = cbconnect(bev, pnode, fd, pnode->probe_type))) 
        {
            PRINT("CONNTECTED 探测类型 = %s SUCCESS\n", pnode->probe_type == 1 ? "TCP " : "HTTP");
            update_node(pnode, NODE_STATUS_INSER);
            bufferevent_free(bev);
        }
        else if (ret == 1) 
        {
            PRINT("CONNTECT  探测类型 = %s ERROR \n", pnode->probe_type == 1 ? "TCP " : "HTTP");
            //update_node(pnode, NODE_STATUS_UNSER);
        }

    }
    else
    {
        update_node(pnode, NODE_STATUS_UNSER);
        bufferevent_free(bev);
    }

    //    bufferevent_enable(bev, EV_READ);
    //    return;

}
#endif
