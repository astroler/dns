// jianghuiliang@mail.voole.com    2008/12/30 
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <sys/timeb.h>
#include <sys/time.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

//#include "mpool.h"
#include "arch.h"
//#include "errmsg.h"
int LOG_LEVEL = 3;
//extern int LOG_LEVEL;
//extern uint32_t CCN_REPORT;
typedef struct module_s {
    const char *name;
    int inuse;
}module_t;

typedef struct {
    int  index;
    char *name;
} level_t;

level_t level[] = {{0, "-"}, {1, "D"} ,{2, "I"},{3, "W"},{4, "E"},{5, "F"},{6, "N"}};

module_t modules[] = {
    {"",  0},
    {"net",  0},
    {"live", 0},
    {"tracker",  0},
    {"app", 0},
    {"http", 0},
    {"p2sp",0},
    {"web",0},
    {"config",  0},
    {"main",  0},
    {"vod", 0},

    {"",  0}
};

int need_module = 0;


typedef struct
{
    //Archive folder
    char path[URLMAXLEN];

    //File name's prefix.
    char prefix[PREFIXMAXLEN];

    FILE *asrfd;             /* business fd */
    FILE *logfd;             /* system fd */

    uint32_t timebase;
    cbsink_t cb;
    void *arg;

    char buffer[2][1000000]; /* 0-log, 1-asr */
    int readpos[2];
    int writepos[2];

    pthread_mutex_t lock;
    pthread_cond_t signal;

    pthread_t thread;
    int exit_flag; 

    int mask;
} archivemod_t;

static archivemod_t *am = NULL;

static int readbuffer(int i, char *buf, int bufsize)
{
    int readpos = 0, writepos = 0, datalen = 0;

    if (am->readpos[i] >= am->writepos[i])
        return 0; // buffer is empty
    readpos = am->readpos[i] % sizeof(am->buffer[i]);
    datalen = am->writepos[i] - am->readpos[i];
    if (readpos + datalen > sizeof(am->buffer[i]))
        datalen = sizeof(am->buffer[i]) - readpos;
    if (datalen > bufsize)
        datalen = bufsize;
    if (datalen > 0)
    {
        memcpy(buf, am->buffer[i] + readpos, datalen);
        am->readpos[i] += datalen;
        readpos = am->readpos[i] % sizeof(am->buffer[i]);
        writepos = am->writepos[i] % sizeof(am->buffer[i]);
        if (readpos <= writepos)
        {
            am->readpos[i] = readpos;
            am->writepos[i] = writepos;
        }
    }
    return datalen;
}

static int writebuffer(int i, char *buf, int datalen)
{
    int writepos = 0;

    if (am->writepos[i] + datalen >= am->readpos[i] + sizeof(am->buffer[i]))
        return 0; // buffer is full
    writepos = am->writepos[i] % sizeof(am->buffer[i]);
    if (writepos + datalen > sizeof(am->buffer[i]))
    {
        memcpy(am->buffer[i] + writepos, buf, sizeof(am->buffer[i]) - writepos);
        memcpy(am->buffer[i], buf + (sizeof(am->buffer[i]) - writepos), datalen - (sizeof(am->buffer[i]) - writepos));
    }
    else
        memcpy(am->buffer[i] + writepos, buf, datalen);
    am->writepos[i] += datalen;
    return datalen;
}

void archive_of_thread(void *param)
{
    while (am->exit_flag == 0)  /* exit flag */
    {
        char buffer[2][4096] = {{0}};
        int len[2] = {0};
        int i = 0;

        pthread_mutex_lock(&am->lock);
        if (am->readpos[0] >= am->writepos[0] &&
                am->readpos[1] >= am->writepos[1])
            pthread_cond_wait(&(am->signal), &(am->lock));
        for (i = 0; i < 2; i++)
            len[i] = readbuffer(i, buffer[i], sizeof(buffer[i]));
        pthread_mutex_unlock(&am->lock);
        if (len[0] > 0)
        {
            if (fwrite(buffer[0], 1, len[0], am->logfd) <= 0)
                fprintf(stderr, "can't write to log file - (%d) %s.\n", errno, strerror(errno));
            fflush(am->logfd);
#if 0
            if(CCN_REPORT && strstr(buffer[0], "CCND"))
            {
                char sendtime[16] = {0};
                char module[8] = "CEND";
                char errcode[16] = {0};
                char desc[128] = {0};
                char *save = NULL;
                strncpy(sendtime, strtok_r(buffer[0], " ", &save), sizeof(sendtime));
                strtok_r(NULL, "C", &save);
                strtok_r(NULL, "D", &save);
                strncpy(errcode, strtok_r(NULL, " ", &save), sizeof(errcode));
                strncpy(desc, strtok_r(NULL, "\n", &save), sizeof(desc));

                collect_msg_send(0, 0, NULL, NULL, module, "2.0.0", NULL, errcode, desc, NULL, time(0));
            }
#endif

        }
        if (len[1] > 0)
        {
            if (fwrite(buffer[1], 1, len[1], am->asrfd) <= 0)
                fprintf(stderr, "can't write to asr file - (%d) %s.\n", errno, strerror(errno));
            fflush(am->asrfd);
        }
    }

    am->exit_flag = 2;

    //Close the file handles and destroy the lock.
    if ((am->mask & ATLOG) != 0 && NULL != am->logfd)
        fclose(am->logfd), am->logfd = 0;
    if ((am->mask & ATASR) != 0 && NULL != am->asrfd)
        fclose(am->asrfd), am->asrfd = 0;
    pthread_mutex_destroy(&am->lock);
    pthread_cond_destroy(&am->signal);

    perror("arch thread destroyed");
    pthread_exit(NULL);
}
//Module Initialization Method
/**
 * @Synopsis  archive Initialization
 *
 * @Param     path    Log storage path
 * @Param     prefix  Log name
 * @Param     srv     Log type
 * @Param     cb      Call back funtion
 * @Param     arg     Call back funtion of param
 *
 * @Returns   success return 0;failed return 1
 */
int archive_init(const char *path, const char *prefix, int srv, cbsink_t cb, void *arg)
{
    if (am == NULL)
        am = calloc(sizeof(archivemod_t), 1);
    snprintf(am->path, URLMAXLEN, "%s/log", path);
    strncpy(am->prefix, prefix, PREFIXMAXLEN - 1);
    //Verify the folder exists, or create it if it doesn't.
    if (access(am->path, F_OK) && mkdir(am->path, 0777))
    {
        fprintf(stderr, "failed to create log folder - (%d) %s.\n", errno, strerror(errno));
        return 1;
    }
    am->exit_flag = 0;
    am->mask = srv;
    am->cb = cb;  /* callback function and parameter - edgenode_sink */
    am->arg = arg;
    pthread_mutex_init(&am->lock, 0);
    pthread_cond_init(&(am->signal), 0);
    if (pthread_create(&(am->thread), 0, (void *)archive_of_thread, (void *)am))
        exit(-1);
    pthread_detach(am->thread);
    return 0;
}

//Module Cleanup Method
void archive_destroy()
{
    if (am == NULL)
        return;
    int i = 0;
    int j = 0;
    while(1)
    {
        pthread_mutex_lock(&am->lock);
        if (am->readpos[i%2] >= am->writepos[i%2])
            j ++;
        pthread_mutex_unlock(&am->lock);
        if (j == 2)
            break;
        i++;
        usleep(300);
    }

    if (am->exit_flag == 0)
        am->exit_flag = 1;
    pthread_mutex_lock(&am->lock);
    pthread_cond_signal(&am->signal);
    pthread_mutex_unlock(&am->lock);
}

void archive_print()
{
    int i = 0;
    for (i = 0; i < 2; i++)
    {
        LOGN("ARCH", "%d readpos %d writepos %d space %d\n", i,
                am->readpos[i], am->writepos[i], sizeof(am->buffer[i]) - (am->writepos[i] - am->readpos[i]));
    }
}

//Create two files with current date for name.
static int createFile(time_t t)
{
    char buffer[512] = {0};
    struct tm *lt = localtime(&t);

    if (lt->tm_year * 10000 + (lt->tm_mon + 1) * 100 + lt->tm_mday == am->timebase)
        return 0;

    /* create current day's log file */
    if ((am->mask & ATLOG) != 0)
    {
        if (am->logfd != NULL)
            fclose(am->logfd);
        sprintf(buffer, "%s/%s.%02d%02d%02d.log", am->path, am->prefix,
                lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
        if ((am->logfd = fopen(buffer, "a+b")) == NULL)
            abort();
    }
    /* asr file */
    if ((am->mask & ATASR) != 0)
    {
        if (am->asrfd != NULL)
            fclose(am->asrfd);
        sprintf(buffer, "%s/%s.%02d%02d%02d.asr", am->path, am->prefix,
                lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
        if ((am->asrfd = fopen(buffer, "a+b")) == NULL)
            abort();
    }
    am->timebase = lt->tm_year * 10000 + (lt->tm_mon + 1) * 100 + lt->tm_mday;  /* YYYYMMDD */
    return 0;
}

int64_t getcurtime_ms()
{
    struct timeval cur = {0, 0};
    gettimeofday(&cur, NULL);
    return cur.tv_sec * 1000L + cur.tv_usec / 1000L;
}

void archive_of_log_o(char* facility, char* format, ...)
{
    char buffer[2048] = {0};
    int len = 0;
    va_list ap;
    //time_t t = time(0);
    struct tm lt;

    if ((am->mask & ATLOG) == 0)
        return;

    //ignore low level logs.

    uint64_t now = getcurtime_ms();
    time_t t = (time_t)(now / 1000);
    localtime_r(&t, &lt);
    uint64_t ms = now % 1000;

    if (lt.tm_year * 10000 + (lt.tm_mon + 1) * 100 + lt.tm_mday != am->timebase)
        pthread_mutex_lock(&am->lock), createFile(t), pthread_mutex_unlock(&am->lock);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", &lt);
    len = strlen(buffer);
    snprintf(buffer + len, sizeof(buffer) - len, ".%03lu [%s 0x%lx] ",
            ms, facility, pthread_self());
    len = strlen(buffer);
    va_start(ap, format);
    vsnprintf(buffer + len, sizeof(buffer) - len, format, ap);
    va_end(ap);
    len = strlen(buffer);

    pthread_mutex_lock(&am->lock);
    if (writebuffer(0, buffer, len) > 0)
        pthread_cond_signal(&am->signal);
    pthread_mutex_unlock(&am->lock);

    if (!(strcmp(facility, "FATAL")) && am->cb != NULL)
        am->cb(am->arg, facility, buffer);
}



/**
 * @Synopsis  Log function to be called
 *
 * @Param facility log level {1, "[DEBUG]"} ,{2, "[INFO]"},{3, "[WARN]"},{4, "[ERROR]"},{5, "[FATAL]"},{6, "[NOTICE]"}
 * @Param format   format of print
 * @Return         NULL
 */
void archive_of_log(uint32_t facility, char *format, ...)
{
    char buffer[2048] = {0};
    int len = 0;
    va_list ap;
    //time_t t = time(0);
    struct tm lt;

    if ((am->mask & ATLOG) == 0)
        return;

    //ignore low level logs.
    if (facility < LOG_LEVEL)
        return;

    uint64_t now = getcurtime_ms();
    time_t t = (time_t)(now / 1000);
    localtime_r(&t, &lt);
    uint64_t ms = now % 1000;

    if (lt.tm_year * 10000 + (lt.tm_mon + 1) * 100 + lt.tm_mday != am->timebase)
        pthread_mutex_lock(&am->lock), createFile(t), pthread_mutex_unlock(&am->lock);

    strftime(buffer, sizeof(buffer), "%H:%M:%S", &lt);
    len = strlen(buffer);
    snprintf(buffer + len, sizeof(buffer) - len, ".%03lu [%s 0x%lx] ",
            ms, level[facility].name, pthread_self());
    len = strlen(buffer);
    va_start(ap, format);
    vsnprintf(buffer + len, sizeof(buffer) - len, format, ap);
    va_end(ap);
    len = strlen(buffer);

    pthread_mutex_lock(&am->lock);
    if (writebuffer(0, buffer, len) > 0)
        pthread_cond_signal(&am->signal);
    pthread_mutex_unlock(&am->lock);

    if (facility == LOG_LEVEL_FATAL && am->cb != NULL)
        am->cb(am->arg, level[facility].name, buffer);
}

void archive_of_asr(uint32_t app, const char *format, ...)
{
    char buffer[1024] = {0};
    int len = 0;
    va_list ap;
    time_t t = time(0);
    struct tm lt;

    if ((am->mask & ATASR) == 0)
        return;

    localtime_r(&t, &lt);
    if (lt.tm_year * 10000 + (lt.tm_mon + 1) * 100 + lt.tm_mday != am->timebase)
        pthread_mutex_lock(&am->lock), createFile(t), pthread_mutex_unlock(&am->lock);
    strftime(buffer, sizeof(buffer), "%H:%M:%S ", &lt);
    len = strlen(buffer);
    snprintf(buffer + len, sizeof(buffer) - len, "%08x ", app);
    len = strlen(buffer);
    va_start(ap, format);
    vsnprintf(buffer + len, sizeof(buffer) - len, format, ap);
    va_end(ap);
    len = strlen(buffer);

    pthread_mutex_lock(&am->lock);
    if (writebuffer(1, buffer, len) > 0)
        pthread_cond_signal(&am->signal);
    pthread_mutex_unlock(&am->lock);
}
int set_module(const char *mode)
{
    int i = 0, j = 0;
    for(i = 1; modules[i].name[0]; i ++)
    {
        if (!strcmp(mode, modules[i].name))
        {
            modules[i].inuse = 1;
            j = __sync_fetch_and_add(&need_module, 1);
            return 1;
        }
    }
    return 0;
}

void archive_update()
{
    char path[128] = {0};
    char ms[1024] = {0};
    char *ptr = NULL, *str = NULL, *optr = NULL;

    snprintf(path, sizeof(path), "%s/modules", am->path);
    int ret = 0;
    FILE *fp = fopen(path, "r");
    if (fp)
    {
        ret = fread(ms, 1, sizeof(ms), fp);
        fclose(fp);
    }
    if (!ret)
    {
        __sync_lock_release(&need_module);
        return ;
    }
    ms[strlen(ms)-1] = '\0';
    str = ms;
    while ((ptr = strtok_r(str, "|", &optr)) != NULL)
    {
        if (!ptr)
            break;
        set_module(ptr);
        str = optr;
    }
}
#ifdef ARCH_TEST
int main(int argc, char *argv[])
{
    archive_init("./", "tlog", ATLOG, NULL, NULL);
    archive_update();
    LOGE("app", "log app");
    LOGE("live", "log live");
    LOGE("live1", "log live1");
    LOGE("net", "log net");
    LOGE("gzz", "log gzz");
    archive_destroy();
    return 0;
}
#endif
int check_module(const char *mode)
{
    int i = 0;
    for(i = 1; modules[i].name[0]; i ++)
    {
        if (!strcmp(mode, modules[i].name))
        {
            return modules[i].inuse;
        }
    }
    return 0;
}
void log_filter(const char *module, uint32_t ilevel, const char *func, const char *format,...)
{
    char errBuf[2048] = {0};
    va_list arg_ptr;
    int inuse = 0;
    if (ilevel < LOG_LEVEL)
    {
        if (need_module)
            inuse = check_module(module);
        if (!inuse)
            return ;
    }

    va_start(arg_ptr, format);
    vsnprintf(errBuf, sizeof(errBuf), format, arg_ptr);
    va_end(arg_ptr);
    archive_of_log(ilevel, "[%s] %s", module, errBuf);
}

const char *voole_error_string[] = {
    "OK",
    "Common system error",
    "Unknow error",
    "Null pointer",
    "No entry",
    "Out of range",
    "Container full",
    "Db error",
    "Syntax error",
    "Create system object failed",
    "System operate failed",
    "Bad parameter",
    "3rd party lib error",
    "No memory",
    "Timeout",
    "Try again",
    "Release earlier",
    "MAX_ERROR_CODE"
};

const char *verror_str(int errval) {
    if(errval > 0) return NULL;

    int err_index = errval * -1;

    assert(err_index < (sizeof(voole_error_string)/sizeof(char *)));

    return voole_error_string[err_index];
}
int xtoi(const char *p)
{
    int ret = 0, i = 0;
    /* Limit 6 length */
    if (6 != strlen(p))
        return ret;
    while (*p)
    {
        if (++i > 4)
            ret = ret * 100 + *p - '0';
        else
        {
            if(!isdigit(*p))
                return 0;
            ret = ret * 10 + *p - '0';
        }
        p++;
    }

    return ret;
}

