#!/bin/bash
source ./log.sh
source ./remote.conf
source ./comm.sh

b_start() {
    remotedir=$1

    while read addr ; do
        if [ -z $addr -o ${addr:0:1} = "#" ] ; then
            continue
        fi 

        logshow ssh -f ${user}"@"${addr} "cd ${remotedir}; ./bitcoind-regtest-stop.sh;exit"
                ssh -f ${user}"@"${addr} "cd ${remotedir}; ./bitcoind-regtest-stop.sh;exit"
    done < rhosts
    exit 0
}


b_start  $workpath
