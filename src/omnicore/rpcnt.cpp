#include "omnicore/rpctx.h"
#include "omnicore/wallet_ref.h"

#include "omnicore/createpayload.h"
#include "omnicore/dex.h"
#include "omnicore/errors.h"
#include "omnicore/omnicore.h"
#include "omnicore/pending.h"
#include "omnicore/rpcrequirements.h"
#include "omnicore/rpcvalues.h"
#include "omnicore/sp.h"
#include "omnicore/tx.h"
#include "omnicore/wallettxbuilder.h"

#include "policy/fees.h"
#include "init.h"
#include "rpc/server.h"
#include "sync.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "wallet/rpcwallet.h"
#include <univalue.h>

#include <stdint.h>
#include <stdexcept>
#include <string>

#include "rpcnt.h"

using std::runtime_error;
using namespace mastercore;

extern CCriticalSection cs_main;

extern UniValue omni_sendissuancefixed(const JSONRPCRequest& request);

UniValue sinnga_sendissuancefixed(const JSONRPCRequest &request)
{
    return omni_sendissuancefixed(request);
}


static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------

  { "omni layer (transaction creation)", "sinnga_sendissuancefixed",       &sinnga_sendissuancefixed,       {"fromaddress","ecosystem","type","previousid","category","subcategory","name","url","data","amount"} },

};

void RegisterSinngaTransactionCreationRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

