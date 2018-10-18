#!/bin/bash
source ./nodes
user_home="/root/"
bitcoind_path="/home/root/work/sinnga/src/"
bitcoincli_path="/home/root/work/sinnga/src/"

#regtest : 18407 main:8407
BITCOIND_PORT=18407 
BITCOIND_RPCPORT=18406

localhost=""

BITCOIND_CMDS="-deprecatedrpc=accounts " #${ADDNODE_RPC_NODE1}" "${ADDNODE_RPC_NODE2}" "${ADDNODE_RPC_NODE3} 

find_index() { 
    x="${1%%$2*}"
    [[ $x = $1 ]] && echo -1 || echo ${#x}
}
node_index=0
equ_symbol="="
while read line ; do
    eval "$line"
    x="${line%%$equ_symbol*}"
    pos=${#x}

    if [ -z ${line} ] ; then
        continue
    fi

    if [ ${pos} -le 0 ] ; then
        continue
    fi

    addr=${line:$pos + 1}
    if [ ${addr} = ${localhost} ] ; then
        continue
    fi

    node_name[$node_index]=${line:0:$pos}
    node_addr[$node_index]=$addr
    let node_index++
done < nodes

for node in  ${node_addr[@]} 
do
    addnode_cmds+=" -addnode="${node}":""${BITCOIND_PORT}"
done

BITCOIND_CMDS+=$addnode_cmds
echo $BITCOIND_CMDS
echo ${node_name[@]}
echo ${node_addr[@]}
