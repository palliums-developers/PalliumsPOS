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
#include "nodetoken.h"



//
#include <amount.h>
#include <chain.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <httpserver.h>
#include <validation.h>
#include <key_io.h>
#include <net.h>
#include <outputtype.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <rpc/mining.h>
#include <rpc/rawtransaction.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <shutdown.h>
#include <timedata.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <stdint.h>

#include <univalue.h>

#include <functional>
//




using std::runtime_error;
using namespace mastercore;

extern CCriticalSection cs_main;

extern UniValue omni_sendissuancefixed(const JSONRPCRequest& request);

extern std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request);

UniValue sinnga_sendissuancefixed(const JSONRPCRequest &request)
{

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    CNodeToken nodeToken;

    uint32_t nId = 2147483653;

    nodeToken.GetNodeTokenerPubkey(nId, pwallet);

    //test
    std::string sOP = "Hello,OPReturn!";

    std::vector<unsigned char> payload = {'H','E','L','L','O','O','P','R','T','U','R','N','\0'};


    // obtain parameters & info
    std::string fromAddress = "2NAvgaCpj2V5vdzbtpj1TrQJUuLJFvYjzVr";
   // uint8_t ecosystem = 2;
   // uint16_t type = 1;
    //uint32_t previousId = 0;
    std::string category = "OPRETURN";
    std::string subcategory = "LL";
    std::string name = "PO";
    std::string url = "";
    std::string data = "";
    //int64_t amount = 10;


    uint256 txid;
    std::string rawHex;
    //WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);



//    //code Create a Transaction
//    CTxDestination txDes = "";

//    CMutableTransaction txNew;
//    txNew.nVersion = 1;
//    txNew.vin.resize(1);
//    txNew.vin[0].prevout.n = 0;
//    uint256 txHash;
//    txHash.SetHex("1fe4c25e895bbad6f5dc36471c1dc20d9d30ce55e9562906b440aa84bb27c63d");
//    txNew.vin[0].prevout.hash = txHash;
//    txNew.vin[0].scriptSig = GetScriptForDestination("");


//    txNew.vout.resize(1);
//    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
//    txNew.vout[0].nValue = genesisReward;
//    txNew.vout[0].scriptPubKey = genesisOutputScript;




    return omni_sendissuancefixed(request);
}


static CTransactionRef SendMoneyy(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, const CCoinControl& coin_control, mapValue_t mapValue, std::string fromAccount)
{
    CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);


    //zzl-add
    std::string sOP = "Hello,OPReturn!";
    std::vector<unsigned char> payload = {'H','E','L','L','O','O','P','R','T','U','R','N','\0'};  




    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    CTransactionRef tx;
    if (!pwallet->CreateTransaction(vecSend, tx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */, std::move(fromAccount), reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    return tx;
}

UniValue sinnga_sendtoaddress(const JSONRPCRequest &request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendtoaddress \"address\" amount ( \"comment\" \"comment_to\" subtractfeefromamount replaceable conf_target \"estimate_mode\")\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"address\"            (string, required) The bitcoin address to send to.\n"
            "2. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"            (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "6. replaceable            (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
            "7. conf_target            (numeric, optional) Confirmation target (in blocks)\n"
            "8. \"estimate_mode\"      (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    mapValue_t mapValue;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        mapValue["to"] = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.m_signal_bip125_rbf = request.params[5].get_bool();
    }

    if (!request.params[6].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[6]);
    }

    if (!request.params[7].isNull()) {
        if (!FeeModeFromString(request.params[7].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }


    EnsureWalletIsUnlocked(pwallet);

    CTransactionRef tx = SendMoneyy(pwallet, dest, nAmount, fSubtractFeeFromAmount, coin_control, std::move(mapValue), {} /* fromAccount */);
    return tx->GetHash().GetHex();
}

static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------

  { "omni layer (transaction creation)", "sinnga_sendissuancefixed",       &sinnga_sendissuancefixed,       {"fromaddress","ecosystem","type","previousid","category","subcategory","name","url","data","amount"} },
  { "wallet",                                "sinnga_sendtoaddress",           &sinnga_sendtoaddress,       {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode"} },

};

void RegisterSinngaTransactionCreationRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

