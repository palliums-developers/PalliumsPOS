#!/bin/bash
source ./bitcoind-base.sh

target="128"
datadir_path=${user_home}".bitcoin-"$target"/"
bitcoin_conf=${datadir_path}"bitcoin.conf" 

echo $datadir_path
echo $bitcoin_conf

echo "启动bitcoind " $target
echo "bitcoind path " $bitcoind_path
cd $bitcoind_path

echo ./bitcoind -regtest -port=18407 -rpcport=18406 -bind="192.168.177.128" -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} $*
./bitcoind -regtest -port=18407 -rpcport=18406 -bind="192.168.177.128" -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} $*


cd -
