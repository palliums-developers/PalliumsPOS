#!/bin/bash
source ./remote.conf

./scp-files.sh ../regtest/ ${rootdir}"bash/regtest"
