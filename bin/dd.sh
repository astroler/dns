#########################################################################
# File Name     : dd.sh
# Author      : sunzg
# Mail        : suclinux@gmail.com
# Created Time: 2018年05月10日 星期四 17时29分56秒
#########################################################################
#!/bin/bash
rm -rf log/*
for ((i=1; i<=100; i++))
do
    ./vind7
done

echo $i,"end"
