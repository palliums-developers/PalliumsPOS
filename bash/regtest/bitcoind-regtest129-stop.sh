#!/bin/bash
source ./bitcoind-base.sh

target="129"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf="bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "stop bitcoind " $target
echo "bitcoin-cli path " $bitcoincli_path
cd $bitcoincli_path

echo ./bitcoin-cli -regtest -rpcport=$BITCOIND_RPCPORT -rpcconnect=$node2 -datadir=${datadir_path} stop
./bitcoin-cli -regtest -rpcport=$BITCOIND_RPCPORT -rpcconnect=$node2 -datadir=${datadir_path} stop


cd -
