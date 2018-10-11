#!/bin/bash
source ./bitcoind-base.sh

target="129"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf="bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "cmd bitcoin-cli " $target
echo "bitcoin-cli path " $bitcoincli_path
cd $bitcoincli_path

echo ./bitcoin-cli -regtest -rpcport=18405 -rpcconnect=$node2 -datadir=${datadir_path} ${BITCOINCLI_CMDS} $*
./bitcoin-cli -regtest -rpcport=18405 -rpcconnect=$node2 -datadir=${datadir_path} ${BITCOINCLI_CMS} $*


cd -
