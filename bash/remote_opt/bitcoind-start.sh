#!/bin/bash
source ./log.sh
source ./userdir

enablelog

b_start() {
    while read addr ; do
        if [ -z $addr -o ${addr:0:1} = "#" ] ; then
            logshow $addr
            continue
        fi 

        logshow ssh -f ${user}"@"${addr} "cd ~/bitcoin/bash/regtest; ./bitcoind-regtest-start.sh -o -daemon"
                ssh -f ${user}"@"${addr} "cd ~/bitcoin/bash/regtest; ./bitcoind-regtest-start.sh -o -daemon"
    done < rhosts
}


b_start bash/regest 
