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

        logshow ssh -f ${user}"@"${addr} "cd ${remotedir}; ./bitcoind-regtest-start.sh -o -daemon"
                ssh -f ${user}"@"${addr} "cd ${remotedir}; ./bitcoind-regtest-start.sh -o -daemon"
    done < rhosts
}

b_start $workpath
