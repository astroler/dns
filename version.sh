#########################################################################
# File Name     : version.sh
# Author      : sunzg
# Mail        : suclinux@gmail.com
# Created Time: 2018年04月04日 星期三 14时50分12秒
#########################################################################
#!/bin/bash
LANG=en_US;
path=`svn info | awk '{for(i=1;i<NF;i++){if(NR==2){print $2}}}'`
ver=`svn info | awk '{for(i=1;i<NF;i++){if(NR==5){print $2}}}'`
echo -e "/* version.h  Get svn revision.  */\n\n \
#ifndef _SVN_REVISION_H_\n \
#define _SVN_REVISION_H_\n\n \
#define RESOURCE \"$path r$ver\" \n\n\
#endif \n" > version.h

