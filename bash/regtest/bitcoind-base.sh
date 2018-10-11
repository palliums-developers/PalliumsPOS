#!/bin/bash
user_home="/root/"
bitcoind_path="/home/root/work/sinnga/src/"
bitcoincli_path="/home/root/work/sinnga/src/"

BITCOIND_REGPORT=18407
BITCOIND_PORT=8407

node1="192.168.177.128"
node2="192.168.177.129"
node3="192.168.177.130"

REG_RPC_NODE1=${node1}":"${BITCOIND_REGPORT}
REG_RPC_NODE2=${node2}":"${BITCOIND_REGPORT}
REG_RPC_NODE3=${node2}":"${BITCOIND_REGPORT}
ADDNODE_REG_RPC_NODE1="-addnode="${REG_RPC_NODE1}
ADDNODE_REG_RPC_NODE2="-addnode="${REG_RPC_NODE2}
ADDNODE_REG_RPC_NODE3="-addnode="${REG_RPC_NODE3}


BITCOIND_CMDS="-deprecatedrpc=accounts "${ADDNODE_REG_RPC_NODE1}" "${ADDNODE_REG_RPC_NODE2}" "${ADDNODE_REG_RPC_NODE3} 
BITCOINCLI_CMDS=""
