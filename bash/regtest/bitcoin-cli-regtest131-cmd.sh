#!/bin/bash
source ./bitcoind-base.sh

target="131"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf="bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "cli bitcoin-cli " $target
echo "bitcoin-cli path " $bitcoincli_path
cd $bitcoincli_path

echo ./bitcoin-cli -regtest -rpcport=$BITCOIND_RPCPORT -rpcconnect=$node4 -datadir=${datadir_path} -conf=$bitcoin_conf ${BITCOINCLI_CMDS} $*
./bitcoin-cli -regtest -rpcport=$BITCOIND_RPCPORT -rpcconnect=$node4 -datadir=${datadir_path} -conf=$bitcoin_conf ${BITCOINCLI_CMDS} $*


cd -
