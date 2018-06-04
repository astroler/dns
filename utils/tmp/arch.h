/* Copyright (c) 2008, Voole All rights reserved.
 * file name :log.h
 * programme design: jianghuiliang/ jianghuiliang@mail.voole.com
 * accomplish time:  Start: 2008-12-18 Complete:
 * version:
 * modification time:
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

#define URLMAXLEN        1024
#define PREFIXMAXLEN     24

#define LOG_INFO         1        //情报信息，普通信息
#define LOG_WARNING      2        //告警信息
#define LOG_TRACE        3        //某一事件的执行路径信息，用于追踪流程
#define LOG_ERR          4        //错误信息
#define LOG_DEBUG        5        //程序调试信息，信息量大
#define LOG_NOTICE       6        //非错误信息，可能需要处理
#define LOG_EMERG        7        //紧急情况，需要立即处理
static int s = 0;
#define LOG(LEVEL, format, ...)                 \
    do                                          \
    {                                           \
        archive_of_log(LEVEL, "[%s,%d] " format,  \
        __FUNCTION__,  __LINE__, ##__VA_ARGS__);\
    } while (0)
#define _CLEAN \
        if (!(s % 10)) \
            printf("\033[1A\033[1A\033[1A\033[1A\033[1A\033[1A\033[1A\033[1A\033[1A\033[1A"), printf("\033[K\033[K\033[K\033[K\033[K\033[K\033[K\033[K\033[K\033[K")

        //_CLEAN;
#define PRINT do{ \
        char buffer[10]={"\0"};\
		time_t t = time(0);\
		struct tm *lt,llt;\
        s += 1;\
		lt = localtime_r(&t,&llt);\
		strftime(buffer, sizeof(buffer), "%H:%M:%S ", lt);\
        printf("%s ",buffer);\
                 }while(0);\
		printf("\t%s [%d]: ", __FUNCTION__, __LINE__),printf


typedef int(*cbsink_t)(void *arg, const char* level, const char* message);

//Service Type Definition
#define ATASR   0x001
#define ATLOG   0x002

//Module Initialization and Cleanup Method
int  archive_init (const char * path, const char *prefix, int srv, cbsink_t cb, void *arg);
void archive_destroy ();
int archive_debug();
void archive_of_log (int facility, char* format, ...);
void logo();
void kit();
#endif /*log.h */
