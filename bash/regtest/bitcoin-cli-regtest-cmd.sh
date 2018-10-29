#!/bin/bash
source ./bitcoind-base.sh
source ./log.sh

target=""
bitcoin_arg=""
bitcoin_conf="bitcoin.conf" 

while getopts "db:o:?" arg
do
    case $arg in
        d)
            show_debug_info=1
            ;;
        b)
            target=$OPTARG
            ;;
        o)
            bitcoin_arg="${OPTARG}"
            ;;
        ?)
            echo "unkown argument"
            exit 1
            ;;
    esac
done
logshow "bitcoin argument:" $bitcoin_arg

datadir_path=${user_home}".bitcoin/"
node_index=-1

if [ -n "${target}" ] ; then
    for name in  ${node_name[@]} 
    do
        let node_index++
        if [ ${name} = ${target} ] ; then
            target_rpcaddr=${node_addr[node_index]}
            break
        fi
    done

    datadir_path=${user_home}".bitcoin-"${target}"/"
fi

if [ -z "${target_addr}" ] ; then
    echo "node["$target"] not found."
    exit 1
fi

logshow "target rpc addr : " $target_rpcaddr
logshow "datadir path: " $datadir_path
logshow "bitcoin conf: " $bitcoin_conf

logshow "stop bitcoind " $target
logshow "bitcoin-cli path: " $bitcoind_path
cd $bitcoind_path

logshow "command : " ./bitcoin-cli -regtest -rpcport=$BITCOIND_REGRPCPORT -rpcconnect=$target_rpcaddr -datadir=${datadir_path} ${bitcoin_arg}
                     ./bitcoin-cli -regtest -rpcport=$BITCOIND_REGRPCPORT -rpcconnect=$target_rpcaddr -datadir=${datadir_path} ${bitcoin_arg}
cd -
