#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <sys/timeb.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <gdsl.h>
#include "arch.h"

typedef struct 
{
    //Archive folder
    char path[URLMAXLEN];

    //File name's prefix.
    char prefix[PREFIXMAXLEN]; 

    FILE *logfd;   /* system fd */
    FILE *asrfd;
    uint32_t timebase;
    cbsink_t cb;
    void *arg;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int mask;

    gdsl_queue_t    write_queue;
    pthread_mutex_t queue_lock;
    pthread_t       pth;

    int debug;
} archivemod_t;
//////////////////////////////////////////////////////
//
static archivemod_t *am = NULL;

struct level_s {
    int     level;
    char   *info;
};

struct level_s levels[7] = 
{   
    {1, "[INFO]\t"},
    {2, "[WARNING]\t"},
    {3, "[TRACE]\t"},
    {4, "[ERROR]\t"},
    {5, "[DEBUG]\t"},
    {6, "[NOTICE]\t"},
    {7, "[EMERG]\t"}
};
struct level_s colors[7] =
{
    {1, "\033[32m%s\033[0m"},
    {2, "\033[33m%s\033[0m"},
    {3, "\033[34m%s\033[0m"},
    {4, "\033[31m%s\033[0m"},
    {5,"\033[36m%s\033[0m"},
    {6,"\033[35m%s\033[0m"},
    {7, "\033[44;37m%s\033[0m"}
};
///////////////////////////////////////////////////////
//

static void flush_file(void *arg)
{
    char *buffer = NULL;
    while(1){
        pthread_mutex_lock(&am->queue_lock);
        pthread_cond_wait(&am->cond, &am->queue_lock);
        pthread_mutex_unlock(&am->queue_lock);

        pthread_mutex_lock(&am->queue_lock);
        while (buffer = gdsl_queue_remove(am->write_queue)) {
            //printf("Find a log %s", buffer);
            if (fwrite(buffer, 1, strlen(buffer), am->logfd) <= 0){
                fprintf(stderr, "Error, Can't write to file, %s.\n", strerror(errno));
            }
            fflush(am->logfd);
            free(buffer);
            buffer = NULL;
        }
        pthread_mutex_unlock(&am->queue_lock);
    }
}

//Module Initialization Method
int archive_init(const char * path, const char *prefix, int srv, cbsink_t cb, void *arg)
{
    if (am == NULL) {
        am = calloc(sizeof(archivemod_t), sizeof(char));
        if (NULL == am)
            return 0;
    }
    am->write_queue = gdsl_queue_alloc(NULL, NULL, NULL);
    pthread_mutex_init(&am->queue_lock, NULL);

    char *str = NULL;
    if ((str = strrchr(prefix, '/'))) {
        str ++;
        strncpy(am->prefix, str, strlen(str));
    }
    else
        strncpy(am->prefix, prefix, strlen(prefix));

    snprintf(am->path, URLMAXLEN,  "%s/log", path);
    //Verify the folder exists, or create it if it doesn't.
    if (access(am->path, F_OK) && mkdir(am->path, 0751)){
        fprintf(stderr, "error creating log folder, %s.\n", strerror(errno));
        return 0;
    }
    am->mask = srv;
    am->cb = cb; /* callback function and parameter */
    am->arg = arg;
    int pth = pthread_create(&am->pth, NULL, (void *)flush_file, NULL);
    if (pth != 0){
        fprintf(stderr, "Error, can`t create thread! %s.\n", strerror(errno));
        free(am);
        return ;
    }

    am->debug = 0;
    pthread_cond_init(&am->cond, NULL);
    pthread_mutex_init(&am->lock, 0);

    return 1;
}

//Module Cleanup Method
void archive_destroy()
{
    if (am == NULL) 
        return;

    //Close the file handles and destroy the lock.
    if ((am->mask & ATASR) != 0 && NULL != am->logfd)
        fclose(am->logfd), am->logfd=0;
#if 0
    pthread_join(log_to_file, NULL);
    pthread_join(log_to_redis, NULL);
#endif
    pthread_mutex_destroy(&am->lock);
    free(am);
    am = NULL;
}
int archive_debug()
{
    pthread_mutex_lock(&am->lock);
    am->debug = am->debug ? 0 : 1;
    pthread_mutex_unlock(&am->lock);
    return am->debug;
}
//Create two files with current date for name.
static int createFile (time_t t)
{
    char buffer[512] = {0};
    struct tm *lt, llt;
    lt = localtime_r(&t,&llt);

    if (lt->tm_year*10000+(lt->tm_mon+1)*100+lt->tm_mday == am->timebase)
        return 0;

    if ((am->mask & ATLOG) != 0) { /* create current day's log */ 
        if (am->logfd != NULL) 
            fclose(am->logfd);
        sprintf(buffer, "%s/%s_%02d%02d%02d.log", am->path, am->prefix, 
                lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday);
        if ((am->logfd=fopen(buffer, "a+b")) == NULL)
            abort();
    }
    if ((am->mask & ATASR) != 0) { /* asr file */
        if (am->asrfd != NULL)
            fclose(am->asrfd);
        sprintf(buffer, "%s/%s_%02d%02d%02d.asr", am->path, am->prefix, 
                lt->tm_year+1900, lt->tm_mon+1, lt->tm_mday);
        if ((am->asrfd=fopen(buffer, "a+b")) == NULL)
            abort();
    } 
    am->timebase = lt->tm_year*10000+(lt->tm_mon+1)*100+lt->tm_mday; /* YYYYMMDD */
    return 0;
}

void archive_of_log (int level, char* format, ...)
{
    char buffer[1024] = {0};
    int log_grade = 0;
    va_list ap;
    time_t t = time(0);
    struct tm *lt, llt;
    lt = localtime_r(&t, &llt);

    if (level > 8 || level < 1)
        return ;
    if (!am->debug && level == LOG_DEBUG)
        return ;
    if( !am || (am->mask & ATLOG) == 0)
        return;

    if (lt->tm_year*10000+(lt->tm_mon+1)*100+lt->tm_mday != am->timebase) {
        pthread_mutex_lock(&am->lock);
        createFile(t);
        pthread_mutex_unlock(&am->lock);
    }

    va_start(ap, format);
    strftime(buffer, sizeof(buffer), "%H:%M:%S ", lt);
    snprintf(buffer+ strlen(buffer), sizeof(buffer), "%10s", levels[level-1].info);
    vsnprintf(buffer+strlen(buffer), sizeof(buffer)-strlen(buffer), format, ap);
    va_end(ap);

    //=====================================================
    char *str = (char *)calloc(strlen(buffer)+16, 1);
#ifdef CDN_COLOR
    snprintf(str, strlen(buffer) + 16, colors[level-1].info, buffer);
#else
    memcpy(str, buffer, strlen(buffer));
#endif
    pthread_mutex_lock(&am->queue_lock);
    gdsl_queue_insert(am->write_queue, (void *)str);
    pthread_mutex_unlock(&am->queue_lock);
    //printf("%d %s", level, str);
    pthread_mutex_lock(&am->queue_lock);
    pthread_cond_signal(&am->cond);
    pthread_mutex_unlock(&am->queue_lock);
}

