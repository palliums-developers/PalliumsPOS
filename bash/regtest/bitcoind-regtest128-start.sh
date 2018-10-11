#!/bin/bash
source ./bitcoind-base.sh

target="128"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf="bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "启动bitcoind " $target
echo "bitcoind path " $bitcoind_path
cd $bitcoind_path

echo ./bitcoind -regtest -port=18407 -rpcport=18406 -bind=$node1 -rpcbind=$node1 -rpcallowip=$node1 -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS} $*
./bitcoind -regtest -port=18407 -rpcport=18406 -bind=$node1 -rpcbind=$node1 -rpcallowip=$node1 -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS} $*


cd -
