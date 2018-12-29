#ifndef RPCNT_H
#define RPCNT_H

#include <univalue.h>

#include "rpc/server.h"


// register managable token
UniValue sinnga_sendissuancefixed(const JSONRPCRequest& request);
UniValue omni_registernodetoken(const JSONRPCRequest& request);
UniValue omni_getregisterpubkeys(const JSONRPCRequest& request);

// register node token
UniValue omni_sendregisternodetoken(const JSONRPCRequest& request);
UniValue omni_sendnodetoken(const JSONRPCRequest& request);
UniValue omni_registernodebytx(const JSONRPCRequest& request);
UniValue omni_unregisternodebytx(const JSONRPCRequest& request);
UniValue omni_getregisterInfo(const JSONRPCRequest& request);

// test interface
UniValue omni_registernodebytxtest(const JSONRPCRequest& request);
UniValue omni_getregisterInfotest(const JSONRPCRequest& request);


#endif // RPCNT_H
