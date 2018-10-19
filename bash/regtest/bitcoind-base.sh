#!/bin/bash
#addnode list
source ./hosts
#my defined funcs(show log functions)
source ./log.sh

localhost="127.0.0.1"
user_home="/root/"
bitcoind_path="/home/root/work/sinnga/src/"
bitcoincli_path="/home/root/work/sinnga/src/"

#bitcoind bind and rpcbind setting
##default port setting(regtest : 18407 main:8407)
###main
BITCOIND_PORT=8407       #bitcoind port
BITCOIND_RPCPORT=18406    #bincoind rpc port
###testnet
BITCOIND_TESTPORT=8507       #bitcoind port
BITCOIND_TESTRPCPORT=18506    #bincoind rpc port
###regtest
BITCOIND_REGPORT=8607       #bitcoind port
BITCOIND_REGRPCPORT=18606    #bincoind rpc port

#default address setting
target_addr="0.0.0.0"
target_rpcaddr="127.0.0.1"

#reset user user setting(configure file)
source ./bind

datadir_path=${user_home}".bitcoin/"

BITCOIND_CMDS="-deprecatedrpc=accounts " #${ADDNODE_RPC_NODE1}" "${ADDNODE_RPC_NODE2}" "${ADDNODE_RPC_NODE3} 
BITCOIND_TESTCMDS="-deprecatedrpc=accounts " #${ADDNODE_RPC_NODE1}" "${ADDNODE_RPC_NODE2}" "${ADDNODE_RPC_NODE3} 
BITCOIND_REGCMDS="-deprecatedrpc=accounts " #${ADDNODE_RPC_NODE1}" "${ADDNODE_RPC_NODE2}" "${ADDNODE_RPC_NODE3} 

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
done < hosts

#generate cmds
#main
for node in  ${node_addr[@]} 
do
    addnode_cmds+=" -addnode="${node}":""${BITCOIND_PORT}"
done

##testnet
for node in  ${node_addr[@]} 
do
    addnode_testcmds+=" -addnode="${node}":""${BITCOIND_TESTPORT}"
done

##regtest
for node in  ${node_addr[@]} 
do
    addnode_regcmds+=" -addnode="${node}":""${BITCOIND_REGPORT}"
done

BITCOIND_CMDS+=$addnode_cmds
BITCOIND_TESTCMDS+=$addnode_testcmds
BITCOIND_REGCMDS+=$addnode_regcmds
logshow $BITCOIND_CMDS
logshow $BITCOIND_TESTCMDS
logshow $BITCOIND_REGCMDS
logshow ${node_name[@]}
logshow ${node_addr[@]}
