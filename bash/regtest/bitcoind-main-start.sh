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
            bitcoin_arg=$OPTARG
            ;;
        ?)
            echo "unkown argument"
            exit 1
            ;;
    esac
done

logshow "++++++++++++"${bitcoin_arg}

node_index=-1

if [ -n "${target}" ] ; then
    for name in  ${node_name[@]} 
    do
        let node_index++
        if [ ${name} = ${target} ] ; then
            target_addr=${node_addr[node_index]}
            target_rpcaddr=$target_addr
            break
        fi
    done

    datadir_path=${user_home}".bitcoin-"${target}"/"
fi

if [ -z "${target_addr}" ] ; then
    echo "node["$target"] not found."
    exit 1
fi

if [ ! -e "${datadir_path}" ] ; then 
    mkdir -v $datadir_path
fi

logshow "target addr : "${target_addr}
logshow "target rpc addr : "${target_rpcaddr}
logshow $datadir_path
logshow $bitcoin_conf

logshow "启动bitcoind " $target
logshow "bitcoind path " $bitcoind_path

cd $bitcoind_path

logshow ./bitcoind -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$target_addr -rpcbind=$target_rpcaddr -rpcallowip=$target_rpcaddr -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS} ${bitcoin_arg}
./bitcoind  -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$target_addr -rpcbind=$target_rpcaddr -rpcallowip=$target_rpcaddr -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS}  ${bitcoin_arg}


cd -
