#!/bin/bash
user_home="/root/"
bitcoind_path="/home/root/work/sinnga/src/"
bitcoincli_path="/home/root/work/sinnga/src/"

#regtest : 18407 main:8407
BITCOIND_PORT=18407 
BITCOIND_RPCPORT=18406

node1="192.168.177.128"
node2="192.168.177.129"
node3="192.168.177.130"
#node4="192.168.177.131"
node4="127.0.0.1"

RPC_NODE1=${node1}":"${BITCOIND_PORT}
RPC_NODE2=${node2}":"${BITCOIND_PORT}
RPC_NODE3=${node3}":"${BITCOIND_PORT}
RPC_NODE4=${node4}":"${BITCOIND_PORT}
ADDNODE_RPC_NODE1="-addnode="${RPC_NODE1}
ADDNODE_RPC_NODE2="-addnode="${RPC_NODE2}
ADDNODE_RPC_NODE3="-addnode="${RPC_NODE3}
ADDNODE_RPC_NODE4="-addnode="${RPC_NODE4}


BITCOIND_CMDS="-deprecatedrpc=accounts "${ADDNODE_RPC_NODE1}" "${ADDNODE_RPC_NODE2}" "${ADDNODE_RPC_NODE3} 
#${ADDNODE_RPC_NODE4} 
BITCOINCLI_CMDS=""
