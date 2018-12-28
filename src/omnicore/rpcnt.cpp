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
#include "omnicore/createpayload.h"

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
#include <iostream>
#include <sstream>

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
#include <keystore.h>

#include <stdint.h>

#include <univalue.h>

#include <functional>
//



using std::runtime_error;
using namespace mastercore;

extern CCriticalSection cs_main;

extern UniValue omni_sendissuancefixed(const JSONRPCRequest& request);

extern std::shared_ptr<CWallet> GetWalletForJSONRPCRequest(const JSONRPCRequest& request);

extern void omni_GetWalletForJSONRPCRequest(const JSONRPCRequest& request);

UniValue sinnga_sendissuancefixed(const JSONRPCRequest &request)
{

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    CNodeToken nodeToken;

    uint32_t nId = 2147483653;

    nodeToken.GetNodeTokenerPubkey(nId, pwallet);

    nodeToken.GetRegisterNodeTokenerVrfPubkey(nId);
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

UniValue omni_registernodetoken(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() < 4 || params.size() > 5)
        throw runtime_error(
            "omni_registernodetokent \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"memo\" )\n"

            "\nIssue or grant new units of managed tokens.\n"

            "\1:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the receiver of the tokens (sender by default, can be \"\")\n"
            "3. propertyid           (number, required) the identifier of the tokens to grant\n"
            "4. amount               (string, required) the amount of tokens to create\n"
            "5. memo                 (string, optional) a text note attached to this transaction (none by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("omni_registernodetoken", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\" \"\" 51 \"7000\"")
            + HelpExampleRpc("omni_registernodetoken", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\", \"\", 51, \"7000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    std::string toAddress = !ParseText(params[1]).empty() ? ParseAddress(params[1]): "";
    uint32_t propertyId = ParsePropertyId(params[2]);
    int64_t amount = ParseAmount(params[3], isPropertyDivisible(propertyId));
    std::string memo = (params.size() > 4) ? ParseText(params[4]): "";

    // input vrfpubkey
    if(toAddress.empty())
    {
       memo = fromAddress;
    }
    else
    {
       memo = toAddress;
    }

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_Grant(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue omni_getregisterpubkeys(const JSONRPCRequest &request)
{
    CNodeToken nodeToken;

    uint32_t nId = 2147483653;

   std::vector<std::string> vecVrfPubKeys = nodeToken.GetRegisterNodeTokenerVrfPubkey(nId);

   UniValue responseVrfPubkeys(UniValue::VOBJ);
   uint32_t nOrder = 1;
   for(std::vector<std::string>::iterator itr = vecVrfPubKeys.begin();
       itr != vecVrfPubKeys.end(); itr++)
   {
       std::string sVrfPubkey = *itr;
       std::string skey("vrfpubkey");
       char chOrder[4];
       memset(chOrder, 0, 4);
       memcpy(chOrder, &nOrder, 4);
       skey += chOrder;
       responseVrfPubkeys.push_back(Pair(skey, sVrfPubkey));
       nOrder++;
   }

   return  responseVrfPubkeys;
}

UniValue omni_sendregisternodetoken(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() != 10)
        throw runtime_error(
            "omni_sendregisternodetoken \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" \"amount\"\n"

            "\nCreate new token to register node.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (use 0 for new tokens)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. amount              (string, required) the number of tokens to create\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("omni_sendregisternodetoken", "\"3Ck2kEGLJtZw9ENj2tameMCtS3HB7uRar3\" 2 1 0 \"Companies\" \"Bitcoin Mining\" \"Quantum Miner\" \"\" \"\" \"1000000\"")
            + HelpExampleRpc("omni_sendregisternodetoken", "\"3Ck2kEGLJtZw9ENj2tameMCtS3HB7uRar3\", 2, 1, 0, \"Companies\", \"Bitcoin Mining\", \"Quantum Miner\", \"\", \"\", \"1000000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    uint8_t ecosystem = ParseEcosystem(params[1]);
    uint16_t type = ParsePropertyType(params[2]);
    uint32_t previousId = ParsePreviousPropertyId(params[3]);
    std::string category = ParseText(params[4]);
    std::string subcategory = ParseText(params[5]);
    std::string name = ParseText(params[6]);
    std::string url = ParseText(params[7]);
    std::string data = ParseText(params[8]);
    int64_t amount = ParseAmount(params[9], type);

    // perform checks
    RequirePropertyName(name);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_RegisterNodeToken(ecosystem, type, previousId, category, subcategory, name, url, data, amount);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue omni_sendnodetoken(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() < 4 || params.size() > 6)
        throw runtime_error(
            "omni_send \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nCreate and broadcast a simple send transaction.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. propertyid           (number, required) the identifier of the tokens to send\n"
            "4. amount               (string, required) the amount to send\n"
            "5. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "6. referenceamount      (string, optional) a bitcoin amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("omni_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"100.0\"")
            + HelpExampleRpc("omni_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"100.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    std::string toAddress = ParseAddress(params[1]);
    uint32_t propertyId = ParsePropertyId(params[2]);
    int64_t amount = ParseAmount(params[3], isPropertyDivisible(propertyId));
    std::string redeemAddress = (params.size() > 4 && !ParseText(params[4]).empty()) ? ParseAddress(params[4]): "";
    int64_t referenceAmount = (params.size() > 5) ? ParseAmount(params[5], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireBalance(fromAddress, propertyId, amount);
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SendNodeToken(propertyId, amount);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, MSC_TYPE_SIMPLE_SEND, propertyId, amount);
            return txid.GetHex();
        }
    }
}

UniValue omni_registernodebytx(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "omni_registernodebytx \"address\" \n"
            "\nCreate and broadcast a simple send transaction to register node.\n"
            "\nArguments:\n"
            "1. address          (string, required) the address to register\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("omni_registernodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\"")
            + HelpExampleRpc("omni_registernodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    std::string redeemAddress = "";
    int64_t referenceAmount = 0;

    // create a payload for the transaction
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    auto keyid = GetKeyForDestination(*pwallet, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CPubKey vchPubkey;
    if (!pwallet->GetPubKey(keyid, vchPubkey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }

    std::string vrfPubkeyH = HexStr(vchPubkey);
    std::string vrfPubkeyNew = vrfPubkeyH.substr(0,32);
    std::vector<char> vech32Test(32,0);
    std::string sKeyId = std::string((const char*)keyid.begin(), (const char*)keyid.begin()+20);
    std::vector<unsigned char> payload;
    if(!CNodeToken::IsKeyidRegisterDisk(sKeyId)) {
        payload = CreatePayload_RegisaterNodeByTx(1, 0, vech32Test, sKeyId);
    } else {
        throw JSONRPCError(RPC_TYPE_ERROR, "this address is already register!");
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, fromAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, MSC_TYPE_SIMPLE_SEND, 1, (int64_t)0);
            return txid.GetHex();
        }
    }
}

UniValue omni_unregisternodebytx(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "omni_unregisternodebytx \"address\" \n"
            "\nCreate and broadcast a simple send transaction to register node.\n"
            "\nArguments:\n"
            "1. address          (string, required) the address to register\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("omni_unregisternodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\"")
            + HelpExampleRpc("omni_unregisternodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    std::string redeemAddress = "";
    int64_t referenceAmount = 0;

    // create a payload for the transaction
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    auto keyid = GetKeyForDestination(*pwallet, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CPubKey vchPubkey;
    if (!pwallet->GetPubKey(keyid, vchPubkey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }

    std::string vrfPubkey =std::string((const char*)vchPubkey.data());
    std::string vrfPubkeyH = HexStr(vchPubkey);
    std::string vrfPubkeyNew = vrfPubkeyH.substr(0,32);
    std::vector<char> vech32Test(32,0);
    std::string sKeyId = std::string((const char*)keyid.begin(), (const char*)keyid.begin()+20);
    std::vector<unsigned char> payload;
    if(CNodeToken::IsKeyidRegisterDisk(sKeyId)) {
        payload = CreatePayload_UnregisaterNodeByTx(1, 0, vech32Test, sKeyId);
    } else {
        throw JSONRPCError(RPC_TYPE_ERROR, "this address is already unregister!");
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, fromAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, MSC_TYPE_SIMPLE_SEND, 1, (int64_t)0);
            return txid.GetHex();
        }
    }
}

UniValue omni_getregisterInfo(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "omni_getregisterInfo \n"
            "\nGet registed node info include VrfPubkey and keyid\n"
            "\nWithout Arguments\n"
            "\nResult:\n"
            "[                                 (array of JSON objects)\n"
            " \"vrfpubkey\" : \"keyid\",                  (string) the hex-encoded hash of the transaction\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("omni_getregisterInfo","")
        );


   CNodeToken nodeToken;
   std::map<std::vector<char>, std::string> mapVrfDid = nodeToken.GetRegisterNodeTokenerVrfPubkeyDisk();
   UniValue responseVrfPubkeys(UniValue::VOBJ);
   for(std::map<std::vector<char>, std::string>::iterator itr = mapVrfDid.begin();
       itr != mapVrfDid.end(); itr++)
   {
       std::vector<char> sVrfPubkey = itr->first;
       std::string sKeyid = itr->second;
       std::vector<unsigned char> hexvec(&sKeyid[0], &sKeyid[0] + sKeyid.length());
       std::string sVrfPubkeys = HexStr(sVrfPubkey);
       std::string sHexKeyID = HexStr(hexvec);
       responseVrfPubkeys.push_back(Pair(sVrfPubkeys, sHexKeyID));
   }
   return  responseVrfPubkeys;
}

UniValue omni_registernodebytxtest(const JSONRPCRequest &request)
{

    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() < 4 || params.size() > 6)
        throw runtime_error(
            "omni_registernodebytx \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nCreate and broadcast a simple send transaction.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. propertyid           (number, required) the identifier of the tokens to send\n"
            "4. amount               (string, required) the amount to send\n"
            "5. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "6. referenceamount      (string, optional) a bitcoin amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("omni_registernodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"100.0\"")
            + HelpExampleRpc("omni_registernodebytx", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"100.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(params[0]);
    std::string toAddress = ParseAddress(params[1]);
    uint32_t propertyId = ParsePropertyId(params[2]);
    uint64_t amount = ParseAmount(params[3], isPropertyDivisible(propertyId));
    std::string redeemAddress = (params.size() > 4 && !ParseText(params[4]).empty()) ? ParseAddress(params[4]): "";
    int64_t referenceAmount = (params.size() > 5) ? ParseAmount(params[5], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireBalance(fromAddress, propertyId, amount);
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }


    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    auto keyid = GetKeyForDestination(*pwallet, dest);
    if (keyid.IsNull()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CPubKey vchPubkey;
    if (!pwallet->GetPubKey(keyid, vchPubkey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }

    std::string vrfPubkey ="123456789012345678999"; //std::string((const char*)vchPubkey.data())
    std::string vrfPubkeyH = HexStr(vchPubkey);
    std::string vrfPubkeyNew = vrfPubkeyH.substr(0,32);
    std::string did = "1230";
    std::vector<unsigned char> payload = CreatePayload_RegisaterNodeByTxTest(vrfPubkeyNew, did);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, MSC_TYPE_SIMPLE_SEND, propertyId, (int64_t)amount);
            return txid.GetHex();
        }
    }

}

UniValue omni_getregisterInfotest(const JSONRPCRequest &request)
{
    omni_GetWalletForJSONRPCRequest(request);
    const UniValue &params = request.params;
    const bool& fHelp = request.fHelp;
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "omni_getregisterInfo \n"
            "\nGet registed node info include VrfPubkey and Did\n"
            "\nWithout Arguments\n"
            "\nResult:\n"
            "[                                 (array of JSON objects)\n"
            " \"vrfpubkey\" : \"did\",                  (string) the hex-encoded hash of the transaction\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("omni_getregisterInfo","")
        );

   CNodeToken nodeToken;
   std::map<std::string, std::string> mapVrfDid = nodeToken.GetRegisterNodeTokenerVrfPubkeyTest();
   UniValue responseVrfPubkeys(UniValue::VOBJ);
   for(std::map<std::string, std::string>::iterator itr = mapVrfDid.begin();
       itr != mapVrfDid.end(); itr++)
   {
       std::string sVrfPubkey = itr->first;
       std::string sDid = itr->second;
       responseVrfPubkeys.push_back(Pair(sVrfPubkey, sDid));
   }
   return  responseVrfPubkeys;
}



static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------

  { "omni layer (transaction creation)", "sinnga_sendissuancefixed",       &sinnga_sendissuancefixed,   {"fromaddress","ecosystem","type","previousid","category","subcategory","name","url","data","amount"} },
  { "wallet",                            "sinnga_sendtoaddress",           &sinnga_sendtoaddress,       {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode"} },
  { "omni layer (transaction creation)", "omni_registernodetoken",         &omni_registernodetoken,     {"fromaddress","toaddress","propertyid","amount","memo"} },
  { "omni layer (transaction creation)", "omni_getregisterpubkeys",        &omni_getregisterpubkeys,     {} },
  { "omni layer (transaction creation)", "omni_sendnodetoken",             &omni_sendnodetoken,                    {"fromaddress","toaddress","propertyid","amount","redeemaddress","referenceamount"} },
  { "omni layer (transaction creation)", "omni_sendregisternodetoken",     &omni_sendregisternodetoken,       {"fromaddress","ecosystem","type","previousid","category","subcategory","name","url","data","amount"} },
  { "omni layer (transaction creation)", "omni_registernodebytx",          &omni_registernodebytx,                    {"address","propertyid"} },
  { "omni layer (transaction creation)", "omni_unregisternodebytx",        &omni_unregisternodebytx,                  {"address","propertyid"} },
  { "omni layer (transaction creation)", "omni_getregisterInfo",           &omni_getregisterInfo,        {} },

  { "omni layer (transaction creation)", "omni_registernodebytxtest",          &omni_registernodebytxtest,                    {"fromaddress","toaddress","propertyid","amount","redeemaddress","referenceamount"} },
  { "omni layer (transaction creation)", "omni_getregisterInfotest",           &omni_getregisterInfotest,        {} },


};

void RegisterSinngaTransactionCreationRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}

