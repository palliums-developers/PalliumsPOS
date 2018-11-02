#!/bin/bash
source ./remote.conf
./scp-files.sh ../../src/bitcoind ${rootdir}"src" 
./scp-files.sh ../../src/bitcoin-cli ${rootdir}"src"
./scp-files.sh ../../src/bitcoin-tx  ${rootdir}"src"
