#!/bin/bash
source ./bitcoind-base.sh

target=""
bitcoin_arg=""
bitcoin_conf="bitcoin.conf" 

while getopts "n:o:?" arg
do
    case $arg in
        n)
            target=$OPTARG
            ;;
        o)
            bitcoin_arg=$OPTARG
            ;;
        ?)
            echo "unkown argument"
            ;;
    esac
done
echo "++++++++++++"$bitcoin_arg

target_addr="0.0.0.0"
target_rpcaddr="127.0.0.1"
datadir_path=${user_home}".bitcoin/"
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

echo "target addr : " $target_addr
echo "target rpc addr : " $target_rpcaddr
echo $datadir_path
echo $bitcoin_conf

echo "启动bitcoind " $target
echo "bitcoind path " $bitcoind_path
cd $bitcoind_path

echo ./bitcoind -regtest -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$target_addr -rpcbind=$target_rpcaddr -rpcallowip=$target_rpcaddr -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS} ${bitcoin_arg}
./bitcoind -regtest -port=$BITCOIND_PORT -rpcport=$BITCOIND_RPCPORT -bind=$target_addr -rpcbind=$target_rpcaddr -rpcallowip=$target_rpcaddr -txindex=1 -datadir=${datadir_path} -conf=${bitcoin_conf} ${BITCOIND_CMDS}  ${bitcoin_arg}


cd -
