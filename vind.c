/*************************************************************************
  File Name   :    vind.c
Author      :    sunzg
Mail        :    suclinux@gmail.com 
Created Time:    Thu Jun 16 15:19:12 2016
 *************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <err.h>
#include <pthread.h>
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
#include <stdbool.h>

#include <gdsl.h>
#include <event.h>
#include <evhttp.h>
#include <evdns.h>

#include "redis.h"
#include "obj.h"
#include "store.h"
#include "msg.h"
#include "arch.h"
#include "version.h"
#define  MYNAME "vind7"

char *config_file = "vind.cfg";
content_t *cn = NULL;
int worker = 0;
extern int LOG_LEVEL;
extern void logo();
void on_timer(int fd, short event , void *arg);
///////////////////////////////////////////////////////////////////////////
//
wobj_t *new_obj(worker_t *wk, void *ca)
{
    wobj_t *pdev = (wobj_t*)calloc(sizeof(wobj_t), sizeof(char));
    pdev->ev = calloc(sizeof(struct event), sizeof(char));
    pdev->wk = wk;
    pdev->ca = ca;
    return pdev;
}

void wobj_free(wobj_t *pdev)
{
    free(pdev->ev);
    free(pdev);
}

void worker_destroy(worker_t *wk)
{
    event_base_free(wk->evbase);
    pthread_mutex_destroy(&wk->reglock);
    if (wk->registration)
    {
        gdsl_queue_free(wk->registration);
    }
    free(wk);
}

void worker_thread(worker_t *wk)
{
    __sync_fetch_and_add(&worker, 1);
#if 0
    event_set(wk->notify_event->ev, wk->notify_recv, EV_READ | EV_PERSIST, on_timer, wk->notify_event);
    event_base_set(wk->evbase, wk->notify_event->ev);
    event_add(wk->notify_event->ev, 0);
    fprintf(stdout, "\tWORKER %d SUCCESS.\n", worker);
#endif
    event_base_dispatch(wk->evbase);

    while (cn)
    {
        sleep(1);
    }
    worker_destroy(wk);
    __sync_fetch_and_add(&worker, -1);
}

worker_t *new_worker()
{
    static int iworker = 0;

    worker_t *wk = (worker_t *)calloc(sizeof(worker_t), sizeof(char));

    wk->registration = gdsl_queue_alloc(NULL, NULL, NULL);

    pthread_mutex_init(&wk->reglock, 0);

    int fds[2];
    if (pipe(fds))
    {
        free(wk);
        perror("Can't create notify pipe");
        return NULL;
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK | fcntl(fds[0], F_GETFL, 0));
    fcntl(fds[1], F_SETFL, O_NONBLOCK | fcntl(fds[1], F_GETFL, 0));
    wk->notify_recv = fds[0];
    wk->notify_send = fds[1];

    wk->notify_event = new_obj(wk, NULL);

    if (!iworker)
    {
        wk->evbase = event_init();
        event_set(wk->notify_event->ev, wk->notify_recv, EV_READ | EV_PERSIST, on_timer, wk->notify_event);
        event_add(wk->notify_event->ev, 0);
        iworker ++;
    }
    else
    {
        wk->evbase = event_base_new();
        event_set(wk->notify_event->ev, wk->notify_recv, EV_READ | EV_PERSIST, on_timer, wk->notify_event);
        event_base_set(wk->evbase, wk->notify_event->ev);
        event_add(wk->notify_event->ev, 0);
    }
    if (pthread_create(&(wk->thread), 0, (void *)worker_thread, wk) < 0)
    {
        free(wk);
        perror("Can't create event worker thread");
        return NULL;
    }

    return wk;
}
//////////////////////////////////////////////////////////////////////////
//
void dispatch(void *ca)
{
    core_dispatch(cn, ca);
}

//////////////////////////////////////////////////////////////////////////
//
void root_handler(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;
    const char *uri = evhttp_request_get_uri(req);
    buf = evbuffer_new();
    if (buf == NULL)
        err(1, "failed to create response buffer");
    PRINT("In root get \"%s\"\n", uri);
    evbuffer_add_printf(buf, "Hello World!\n");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void generic_handler(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;
    const char *uri = evhttp_request_get_uri(req);

    buf = evbuffer_new();
    if (buf == NULL)
        err(1, "failed to create response buffer");
    PRINT("In generic get \"%s\"\n", uri);
    evbuffer_add_printf(buf, "Requested: %s\n", evhttp_request_uri(req));
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

static void evdns_server_callback(struct evdns_server_request *req, void *data)
{
    LOG(LOG_LEVEL_DEBUG, "[dns] callback\n");
    int i = 0, r = 0;
    for (i = 0; i < req->nquestions; ++i) 
    {
        if (req->questions[i]->type == EVDNS_TYPE_A &&
                req->questions[i]->dns_question_class == EVDNS_CLASS_INET) 
        {
            struct sockaddr_in net;
            evdns_server_request_get_requesting_addr(req, (struct sockaddr *)&net, sizeof(struct sockaddr_in));
            struct in_addr in;
            uint32_t nip = ntohl(net.sin_addr.s_addr);
            uint32_t kk = htonl(nip);
            uint32_t res[RES_NUM] = {0};
            int res_num = 0, ttl = 0;

            res_num = search_store(cn->store, req->questions[i]->name, nip, res, &ttl);

            LOG(LOG_LEVEL_NOTICE, "[dns] Find a name request[%s][%d]\n", req->questions[i]->name, res_num);
            int j = 0;
            for (j = 0; j < res_num; j++)
                r = evdns_server_request_add_a_reply(req, req->questions[i]->name, 1, &res[j], ttl);
            // r = evdns_server_request_add_a_reply(req, req->questions[i]->name, 1, &kk, 30);
            LOG(LOG_LEVEL_DEBUG, "Find a name request.\n");
        }
        else if (req->questions[i]->type == EVDNS_TYPE_PTR &&
                req->questions[i]->dns_question_class == EVDNS_CLASS_INET) 
        {
            LOG(LOG_LEVEL_NOTICE, " -- replying for %s (PTR)\n", req->questions[i]->name);
            r = evdns_server_request_add_ptr_reply(req, NULL, req->questions[i]->name, "foo.bar.example.com", 3600);
            if (r < 0)
                LOG(LOG_LEVEL_NOTICE, "ugh, no luck");
        }
        else 
        {
            LOG(LOG_LEVEL_NOTICE, " -- skipping %s [%d %d]\n", req->questions[i]->name, req->questions[i]->type, req->questions[i]->dns_question_class);
        }
    }
    r = evdns_server_request_respond(req, 0);
}
//////////////////////////////////////////////////////////////////////
//
// main entry.
//
void handler(int signo) 
{ 
    int pad = 0 ;
    switch(signo)
    { 
        case SIGUSR1: 
            //pad = archive_debug();
            LOG_LEVEL  = LOG_LEVEL % 6 + 1; 
            if(pad)
            { 
                PRINT("switch on   debug_level\n"); 
            }
            else
            {
                PRINT("switch off  debug_level\n"); 
            }
            break; 
        default:  
            PRINT("hehe\n"); 
            break; 
    } 

    return ; 
} 

void check_program(const char *prom)
{
    char *ptr = strrchr(prom, '/');
    if (memcmp(MYNAME, ++ptr, 5))
    {
        kit();
        exit(0);
    }
}

int main(int argc, char **argv)
{
    int i = 0, daemon = 0;
    char *options = "f:dhvs", *cfgfile = NULL;
    char c;
    bool logout = false;

    struct sigaction act;  
    act.sa_handler=handler;  
    sigemptyset(&act.sa_mask);  
    act.sa_flags = 0;  


    signal(SIGPIPE,SIG_IGN); 
    if(sigaction(SIGUSR1,&act, NULL) == -1)  
    {  
        printf("sigaction error exit now\n");  
        exit(0);  
    }
    check_program(argv[0]);
    while ((c=getopt(argc, argv, options)) != -1) 
    {
        switch(c) 
        {
            case 'f': 
                cfgfile = optarg;
                break;
            case 'd':
                daemon = 1;
                break;
            case 'h':
                logo();
                fprintf(stdout, "\n    Usage: %s -f cfgfile [-h]\n\n\n", argv[0]);
                exit(0);
            case 'v':
                logo();
                fprintf(stdout, "\n    VIND (Name Entry)\n");
                fprintf(stdout, "    Ver 4.0.0  Compiled:%s %s\n\n\n", __DATE__, __TIME__);
                exit(0);
            case 's':
                fprintf(stdout, "\n\n    SVN=>%s\n\n\n", RESOURCE);
                exit(0);
            default: 
                exit(EINVAL);
        }
    }

    if (daemon) 
    {
        if (fork() > 0) 
            exit(0);
        setsid();
        if (fork() > 0) 
            exit(0);
    }
    if (cfgfile == NULL) 
    {
        cfgfile = config_file;
    }

    cn = (content_t *)calloc(sizeof(content_t), sizeof(char));
    memset(cn, 0, sizeof(content_t));

    //fprintf(stdout, "cfgfile %s\n", cfgfile);


    for ( i = 0; i < 4; i ++) 
    {
        cn->workers[i] = new_worker();
        if (!cn->workers[i]) {
            int j = 0;
            for (j =0; j < i; j ++)
                event_base_loopbreak(cn->workers[j]->evbase);
            logout = true;
            goto exit;
        }
    }
    if (!content_init(cn, argv[0], cfgfile)) 
    {
        fprintf(stderr, "Content init fail, see the error message in log.\n");
        logout = true;
        goto exit;
    }

    LOG(LOG_LEVEL_NOTICE, "vind init finish.\n");
    fprintf(stdout, "\tVIND START SUCCESS.\n");
    fprintf(stdout, "\n");
    /* Not reached in this code as it is now. */
    while (!logout)
        sleep(1);
exit:

    for (i = 0; i < worker; i++)
    {
        event_base_loopbreak(cn->workers[i]->evbase);
    }

    LOG(LOG_LEVEL_DEBUG, "Shutdown.\n"); 
    //evhttp_free(httpd);

    if (cn) 
    {
        free_content(cn);
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////
//
//
#if 1
int get_sessionid()
{
    static int sessionID = 1;
    // 对于成千上万的连接请求,如果有并发存在,需要枷锁保护sessionID 的数据更新  
    //     // 但libevent 是单线程模型，所以不用加锁。
    return sessionID++;
}

int on_error(caccess_t *ca)
{
    if (NULL == ca)
        return -1;
    if (ca->pdev)
        event_del((struct event *)ca->pdev->ev);
#if 0
    pthread_mutex_lock(&ca->access_lock);

    pthread_mutex_unlock(&ca->access_lock);
#endif 
    LOG(LOG_LEVEL_DEBUG, "On_error %s, %p.\n", ca->nid, ca);
    ca->status = NS_INVALID;
    pthread_mutex_lock(&cn->objlock);
    ca = gdsl_hash_remove(cn->accesses, INT2PTR(ca->fd));
    pthread_mutex_unlock(&cn->objlock);
    // need other.
    threads_dispatch(cn->pools, dispatch, (void *)ca, 0);

    return 0;
}

void on_signal(int fd, short event, void *arg)
{
    if (SIGINT == fd) 
    {
        event_loopbreak();
        return ;
    }
    wobj_t   *pev = (wobj_t *)arg;
    worker_t *wk = (worker_t *)pev->wk;
    //    caccess_t *ca = (caccess_t *)arg;

    LOG(LOG_LEVEL_DEBUG, "On signal %d.\n", gdsl_queue_get_size(wk->registration));
    while (!gdsl_queue_is_empty(wk->registration)) {
        int s = 0;
        LOG(LOG_LEVEL_DEBUG, "wk %p, wk->registration %p, on_signal fd %d, size %lu\n", wk, wk->registration, fd, gdsl_queue_get_size(wk->registration));
        pthread_mutex_lock(&wk->reglock);
        s = PTR2INT(gdsl_queue_remove(wk->registration));
        pthread_mutex_unlock(&wk->reglock);
        pthread_mutex_lock(&cn->objlock);
        caccess_t *ca = (caccess_t *) gdsl_hash_search(cn->accesses, INT2PTR(s));
        pthread_mutex_unlock(&cn->objlock);

        //printf("Find s %d, ca %p\n", s, ca);
        if (!ca) 
        {
            LOG(LOG_LEVEL_INFO, "Signal ca null.\n"); 
            continue;
        }
        if (ca->pdev) 
        {
            LOG(LOG_LEVEL_DEBUG, "Event active, %s nid.\n", ca->nid);
            event_active(ca->pdev->ev, EV_WRITE| EV_READ, 1);
            continue;
        } 
        else 
        {
            LOG(LOG_LEVEL_DEBUG, "Create new obj nid %s.\n", ca->nid);
            ca->pdev = pev = new_obj(wk, ca);
        }

        if (!pev) 
        {
            LOG(LOG_LEVEL_ERROR, "event calloc error\n");
            return;
        }

        if (ca->nodetype == NT_DNSSERVER) 
        {
            LOG(LOG_LEVEL_DEBUG, "in add dns server ca %p\n", ca);
            evdns_add_server_port_with_base(wk->evbase, ca->fd, 0, evdns_server_callback, (void *)cn);
        } 
        else 
        {
            LOG(LOG_LEVEL_DEBUG, "[event set] in add server ca %p, fd %d\n", ca, ca->fd);
            event_set(pev->ev, ca->fd, EV_READ | EV_PERSIST, on_timer, pev);
            event_base_set(wk->evbase, pev->ev);
            event_add(pev->ev, &ca->tv);
        }
    }
    wk->flag &= ~FLAG_ACTIVE;
}

int on_accept(int sock, short event, void* arg)
{
    int sid = get_sessionid();
    LOG(LOG_LEVEL_DEBUG, "Session id:%d\n",sid);
    //socket的描述字可以封装一个结构体sock_ev 来保护读、写的事件以及数据缓冲区  
    //多个客户端因而对应多个newfd, 并对应多个sock_ev 变量  
    caccess_t *ca;
    int c = 0, r = 0;
    struct event *ev;
    struct sockaddr_in client;
    bzero(&client, r=sizeof(client));
    if ( -1 == (c = accept(sock, (struct sockaddr *)&client, (socklen_t *)&r))) 
    {
        LOG(LOG_LEVEL_ERROR, "accept error %d.(%s)\n", errno, strerror(errno));
        return -1;
    }
    ca = new_caccess(cn, c, (const char *)inet_ntoa(client.sin_addr), ntohs(client.sin_port), NT_CLIENT);

    pthread_mutex_lock(&cn->objlock);
    gdsl_hash_insert(cn->accesses, ca);
    pthread_mutex_unlock(&cn->objlock);

    LOG(LOG_LEVEL_DEBUG, "[accept] client ca %p,fd %d\n", ca, c);

    fcntl(c, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL, 0));
    //evutil_make_socket_nonblocking(c);

    wevent_active(cn, ca);
#if 0
    ev = ca->pdev = calloc(sizeof(struct event), sizeof(char));

    event_set(ev, c, EV_READ | EV_PERSIST, on_timer, (void *)ca);
    event_add(ev, NULL);
#endif
    ca->status = NS_CONNECTING;

    return 0;
}

int on_write(int sock, short event, void* arg)
{
    LOG(LOG_LEVEL_DEBUG, "on write\n");
    wobj_t *pev = (wobj_t *)arg;
    caccess_t *ca = (caccess_t *)pev->ca;
    int r;
    if (!ca || ca->status == NS_DISUSE)
        return on_error(ca);
    //dnsmsg_t *msg = (dnsmsg_t *)calloc(sizeof(dnsmsg_t), sizeof(char));
    dnsmsg_t *msg = (dnsmsg_t *)ca->send_incomplete;
    struct event *ev = (struct event *)pev->ev;
    if (ca->besent == 0) {
        pthread_mutex_lock(&ca->access_lock);
        msg = (dnsmsg_t *)gdsl_list_remove_head(ca->send_queue);
        pthread_mutex_unlock(&ca->access_lock);
        if (!msg) {
            LOG(LOG_LEVEL_NOTICE, "[event set] on write event add\n");
            event_del(ev), ev->ev_events &= ~EV_WRITE, event_add(ev, &ca->tv);
            return -1;
        }
        ca->send_incomplete = (uint8_t *)msg;
        ca->besent = ntohl(msg->pdu.len);
    }

    r = send(sock, ((uint8_t *)&msg->pdu) + ntohl(msg->pdu.len) - ca->besent, ca->besent, MSG_NOSIGNAL);
    if (0 == r || (r < 0 && errno != EAGAIN && errno != EINTR)) {
        return !on_error(ca);
    }

    if (r > 0) 
        ca->sentsum += r;

    if (r == ca->besent)
    {
        ca->send_incomplete = NULL;
        ca->besent = 0;
    }
    else// if (r > 0) {
    {
        ca->besent = ca->besent - r;
    }

    if (!(ev->ev_events & EV_WRITE) || (event & EV_TIMEOUT))
    {
        LOG(LOG_LEVEL_DEBUG, "[event set] on write end event add\n");
        event_del(ev), ev->ev_events |= EV_WRITE, event_add(ev, &ca->tv);}

        return 0;
}

    int 
on_read(int sock, short event, void* arg)
{
    int r = 0;
    wobj_t *pdev = (wobj_t *)arg;
    struct event *ev = pdev->ev;
    caccess_t *ca = pdev->ca;
    worker_t  *wk = pdev->wk;

    LOG(LOG_LEVEL_DEBUG, "On_read %d\n", sock);

    if (sock == wk->notify_recv) {

        LOG(LOG_LEVEL_DEBUG, "On_read wk %d\n", sock);

        char buf[PIPE_BUF] = {0};
        wk->flag &= ~FLAG_ACTIVE;
        read(sock, &buf, sizeof(buf));
        return 1;
    }

    if (!ca) 
    {
        LOG(LOG_LEVEL_ERROR, "on_read error\n"); 
        return on_error(ca);
    }

    if (ca->nodetype == NT_TCPSERVER) 
    {
        LOG(LOG_LEVEL_DEBUG, "read to accept\n");
        int ret = on_accept(sock, event, arg);
        return ret;
    }

    ca->interaction = time(0);

    dnsmsg_t *msg = (dnsmsg_t *)ca->recv_incomplete;
    LOG(LOG_LEVEL_DEBUG, "read info\n");
    if (NULL == ca->recv_incomplete) 
    {
        r = recv(ca->fd, ((uint8_t *)&ca->magic) + ca->received, 4 - ca->received, 0);
        if (0 == r || (r < 0&& errno != EAGAIN && errno != EINTR)) 
        {
            LOG(LOG_LEVEL_ERROR, "read error 1\n");
            int ret = on_error(ca);

            return ret;
        }

        if (r > 0) ca->recvnum += r;
        if (r < 0 || (ca->received += r) < 4) 
            return 1;

        if (ntohl(ca->magic) > 102400 || ntohl(ca->magic) <= 12) 
        {
            LOG(LOG_LEVEL_ERROR, "read error 2\n");
            return on_error(ca);
        }
        uint32_t msgsize = ntohl(ca->magic) > sizeof(struct _dns_pdu) ? sizeof(dnsmsg_t) + ntohl(ca->magic) : sizeof(dnsmsg_t);
        msg = new_msg(msgsize);
        ca->recv_incomplete = (uint8_t *)msg;
        msg->pdu.len = ca->magic;
        ca->status = NS_NORMAL;
        return 1;
    }
    r = recv(ca->fd, ((uint8_t *)&msg->pdu) + ca->received, ntohl(msg->pdu.len) - ca->received, 0);
    if (0 == r || (r < 0 && errno != EAGAIN && errno != EINTR)) 
    {
        LOG(LOG_LEVEL_ERROR, "read fail %d.\n", r);
        int ret = on_error(ca);
        return ret;
    }
    if (r > 0) 
        ca->recvnum += r;
    if (r > 0 && (ca->received += r) == ntohl(msg->pdu.len)) 
    {
        ca->recv_incomplete = NULL;
        ca->received = 0;

        pthread_mutex_lock(&ca->access_lock);
        gdsl_list_insert_tail(ca->recv_queue, msg);
        pthread_mutex_unlock(&ca->access_lock);

        LOG(LOG_LEVEL_DEBUG, "read end %d.\n", r);
        threads_dispatch(cn->pools, dispatch, (void *)ca, 0);
    }
    return 1;
}

void on_timer(int fd, short event , void *arg)
{
    if (NULL == arg)
        return ;
    wobj_t *pev = (wobj_t *)arg;
    caccess_t *ca = (caccess_t *)pev->ca;
    struct event *ev = pev->ev;
    worker_t *wk = (worker_t *)pev->wk;
    wk->flag |= FLAG_ACTIVE;
    //printf("on timer, fd %d\n", fd);
    if ((event & EV_WRITE) && on_write(fd, event, arg))
        goto end;
    if ((event & EV_READ) && !on_read(fd, event, arg))
        goto end;
    if (!(event & EV_TIMEOUT))
        goto end;

    if (ca->status != NS_NORMAL) {
        on_error(ca); goto end;
    }
    LOG(LOG_LEVEL_DEBUG, "ca %p otimer %d, size %d\n", ca, ev->ev_events & EV_WRITE, gdsl_list_get_size(ca->send_queue));
    if (!(ev->ev_events & EV_WRITE) && gdsl_list_get_size(ca->send_queue) > 0) {
        LOG(LOG_LEVEL_DEBUG, "otimer send queue\n");
        wevent_active(cn, ca);
    }
end:
    on_signal(fd, event, arg);
}

#endif
