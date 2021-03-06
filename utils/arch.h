/* Copyright (c) 2008, Voole All rights reserved.
 * file name :log.h
 * programme design: jianghuiliang/ jianghuiliang@mail.voole.com
 * accomplish time:  Start: 2008-12-18 Complete:
 * version:
 * modification time:
 */

#ifndef _ARCH_H_
#define _ARCH_H_

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

//TODO ---------------------

#define URLMAXLEN        64
#define PREFIXMAXLEN     10
#define LOG_LEVEL_MAX    6
//#ifdef CDNDEBUG
#define LOG(LEVEL, FMT...) archive_of_log(LEVEL, ## FMT)
//#else
//#define LOG(LEVEL, FMT...) archive_of_log_o(LEVEL, ## FMT)
//#endif
#define ASR(APP, FMT...) archive_of_asr(APP, ## FMT)

typedef int(*cbsink_t)(void *arg, const char* level, const char* message);

void log_filter(const char *module, uint32_t ilevel, const char *func, const char *format,...);
//Service Type Definition
#define ATASR   0x001
#define ATLOG   0x002

#define LOG_LEVEL_DEBUG  1
#define LOG_LEVEL_INFO   2
#define LOG_LEVEL_WARN   3
#define LOG_LEVEL_ERROR  4
#define LOG_LEVEL_FATAL  5
#define LOG_LEVEL_NOTICE 6

#define LOG_INFO         7        //情报信息，普通信息
#define LOG_WARNING      6        //告警信息
#define LOG_TRACE        5        //某一事件的执行路径信息，用于追踪流程
#define LOG_ERR          4        //错误信息
#define LOG_DEBUG        3        //程序调试信息，信息量大
#define LOG_NOTICE       2        //非错误信息，可能需要处理
#define LOG_EMERG        1        //紧急情况，需要立即处理

void archive_print();

#define LOGD(mode,FMT...)                              \
        log_filter(mode,LOG_LEVEL_DEBUG,__FUNCTION__,## FMT)

#define LOGI(mode,FMT...)                              \
        log_filter(mode,LOG_LEVEL_INFO,__FUNCTION__,## FMT)

#define LOGW(mode,FMT...)                              \
        log_filter(mode,LOG_LEVEL_WARN,__FUNCTION__,## FMT)

#define LOGE(mode,FMT...)                              \
        log_filter(mode,LOG_LEVEL_ERROR,__FUNCTION__,## FMT)
        
#define LOGF(mode,FMT...)                              \
            log_filter(mode,LOG_LEVEL_FATAL,__FUNCTION__,## FMT)

#define LOGN(mode,FMT...)                              \
            log_filter(mode,LOG_LEVEL_NOTICE,__FUNCTION__,## FMT)
#define PRINT(FMT, ...) 
/*
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
*/
//Module Initialization and Cleanup Method
int  archive_init (const char * path, const char *prefix, int srv, cbsink_t cb, void *arg);
void archive_destroy ();
void archive_update();

void archive_of_log (uint32_t facility, char* format, ...);
void archive_of_asr (uint32_t app, const char *format, ...);
void archive_of_log_o(char* facility, char* format, ...);

extern const char *voole_error_string[];

const char *verror_str(int errval);
int xtoi(const char *p);
#endif /*arch.h */
