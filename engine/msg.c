/*************************************************************************
    File Name   :    msg.c
    Author      :    sunzg
    Mail        :    suclinux@gmail.com
    Created Time:    2016年11月03日 星期四 16时47分53秒
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "msg.h"

    dnsmsg_t *
new_msg(int size)
{
    dnsmsg_t *msg = (dnsmsg_t *)calloc(size, sizeof(char));
    msg->size = size;
    return msg;
}
    void
free_msg(dnsmsg_t *msg)
{
    free(msg);
}
