#!/bin/bash
show_debug_info=0
logshow() {
    
    if [ $show_debug_info -ne 0 ] ; then
        echo "`date '+%Y/%m/%d %H:%M:%S'`"": "$*
    fi
}

enablelog() {
     show_debug_info=1
 }
