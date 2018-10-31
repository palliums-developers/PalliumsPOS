# !/bin/bash
source ./remote.conf
source ./comm.sh
source ./log.sh

enablelog

mkdir_cmd="mkdir -p "${rootdir}

show_scp_help() {
    echo "argument 1 source path, "\/" end"
    echo "argument 2 target subpath"
}

scpfile() {
    SRC_PATH=$1
    TAG_PATH=$2


    while read addr ; do
        if [ -z $addr -o ${addr:0:1} = "#" ] ; then
            continue
        fi 
        
        b_mkdir_target ${user}"@"${addr}  $TAG_PATH

        if [ -f $SRC_PATH ] ; then 
            logshow scp -C $SRC_PATH  ${user}"@"${addr}":"$TAG_PATH   
                    scp -C $SRC_PATH  ${user}"@"${addr}":"$TAG_PATH
        elif [ -d $SRC_PATH ] ; then
            for file in `ls $SRC_PATH`
            do
                if [ -d $SRC_PATH$file ] ; then
                    logshow $SRC_PATH$file
                else
                        logshow scp -C $SRC_PATH$file  ${user}"@"${addr}":"$TAG_PATH   
                                scp -C $SRC_PATH$file  ${user}"@"${addr}":"$TAG_PATH
                fi
            done
        fi
    done < rhosts
}
b_mkdir_target() {
    logshow ssh -f $1 "mkdir -p $2"
            ssh -f $1 "mkdir -p $2"
}
b_mkdir() {
    while read addr ; do
        if [ -z $addr -o ${addr:0:1} = "#" ] ; then
            continue
        fi 
        b_mkdir_target ${user}"@"${addr}  $1
     done < rhosts
}

if [ $# -lt 1 ] ; then
    echo "too few parameters"
    show_scp_help
    exit 1
fi

logshow "source path: "$1
logshow "target path: "$2


if [ $# -ge 2 ] ; then
   scpfile $1 $2
else
   scpfile $1 ${rootdir}
fi
