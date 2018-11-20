// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_REGISTER_H
#define BITCOIN_RPC_REGISTER_H

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

/** Register block chain RPC commands */
void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
/** Register P2P networking RPC commands */
void RegisterNetRPCCommands(CRPCTable &tableRPC);
/** Register miscellaneous RPC commands */
void RegisterMiscRPCCommands(CRPCTable &tableRPC);
/** Register mining RPC commands */
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
/** Register raw transaction RPC commands */
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);

/** Register Omni data retrieval RPC commands */
extern void RegisterOmniDataRetrievalRPCCommands(CRPCTable &tableRPC);
/** Register Omni transaction creation RPC commands */
extern void RegisterOmniTransactionCreationRPCCommands(CRPCTable &tableRPC);
/** Register Omni payload creation RPC commands */
extern void RegisterOmniPayloadCreationRPCCommands(CRPCTable &tableRPC);
/** Register Omni raw transaction RPC commands */
extern void RegisterOmniRawTransactionRPCCommands(CRPCTable &tableRPC);

extern void RegisterSinngaTransactionCreationRPCCommands(CRPCTable &tableRPC);

static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterMiscRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);

	/* Omni Core RPCs: */
	RegisterOmniDataRetrievalRPCCommands(t);
    RegisterOmniTransactionCreationRPCCommands(t);
	RegisterOmniPayloadCreationRPCCommands(t);
	RegisterOmniRawTransactionRPCCommands(t);

    RegisterSinngaTransactionCreationRPCCommands(t);
}

#endif // BITCOIN_RPC_REGISTER_H
