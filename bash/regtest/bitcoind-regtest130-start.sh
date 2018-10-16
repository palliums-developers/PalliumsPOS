#!/bin/bash
source ./bitcoind-base.sh

target="130"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf=${datadir_path}"bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "启动bitcoind " $target
echo "bitcoind path " $bitcoind_path
cd $bitcoind_path

echo ./bitcoind -regtest -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$node3 -rpcbind=$node3 -rpcallowip=$node3 -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} $BITCOIND_CMDS "$@"
./bitcoind -regtest -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$node3 -rpcbind=$node3 -rpcallowip=$node3 -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} $BITCOIND_CMDS "$@"


cd -
