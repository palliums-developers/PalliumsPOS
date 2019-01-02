#include <key_io.h>
#include <univalue.h>
#include <utilstrencodings.h>
#include <rpc/util.h>
#include <wallet/wallet.h>
#include <script/standard.h>
#include <rpc/server.h>


#include "validation.h"
#include "chainparams.h"

#include "omnicore/omnicore.h"
#include "omnicore/tally.h"
#include "omnicore/walletfetchtxs.h"
#include "omnicore/rpc.h"
#include "omnicore/errors.h"
#include "omnicore/utilsbitcoin.h"
#include "omnicore/tx.h"
#include "omnicore/dbtxlist.h"

#include "nodetoken.h"

using namespace mastercore;

extern std::set<std::pair<std::string,uint32_t> > setFrozenAddresses;

extern CMPTxList* mastercore::p_txlistdb;

class DescribeWalletAddressVisitorNt : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    void ProcessSubScript(const CScript& subscript, UniValue& obj, bool include_addresses = false) const
    {
        // Always present: script type and redeemscript
        txnouttype which_type;
        std::vector<std::vector<unsigned char>> solutions_data;
        Solver(subscript, which_type, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));

        CTxDestination embedded;
        UniValue a(UniValue::VARR);
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(detail);
            UniValue wallet_detail = boost::apply_visitor(*this, embedded);
            subobj.pushKVs(wallet_detail);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript.begin(), subscript.end()));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
            if (include_addresses) a.push_back(EncodeDestination(embedded));
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) a.push_back(EncodeDestination(key.GetID()));
                pubkeys.push_back(HexStr(key.begin(), key.end()));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys using their P2PKH address.
        // For that reason, only add the 'addresses' field when needed for backward compatibility. New applications
        // can use the 'embedded'->'address' field for P2SH or P2WSH wrapped addresses, and 'pubkeys' for
        // inspecting multisig participants.
        if (include_addresses) obj.pushKV("addresses", std::move(a));
    }

    explicit DescribeWalletAddressVisitorNt(CWallet* _pwallet) : pwallet(_pwallet) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj, IsDeprecatedRPCEnabled("validateaddress"));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const { return UniValue(UniValue::VOBJ); }
};



CNodeToken::CNodeToken()
{

}

CNodeToken::~CNodeToken()
{

}

std::vector<std::string> CNodeToken::GetNodeTokenerPubkey(uint32_t propertyId, CWallet* pwallet)
{

    // Get Address of Token

    std::vector<std::string> vecFrozenAddress;

    for (std::unordered_map<std::string, CMPTally>::iterator it = mp_tally_map.begin(); it != mp_tally_map.end(); ++it)
    {
        uint32_t id = 0;
        bool includeAddress = false;
        std::string address = it->first;
        (it->second).init();
        while (0 != (id = (it->second).next()))
        {
            if (id == propertyId)
            {
                includeAddress = true;
                break;
            }
        }
        if (!includeAddress)
        {
            continue; // ignore this address, has never transacted in this propertyId
        }

        if (setFrozenAddresses.find(std::make_pair(address, propertyId)) != setFrozenAddresses.end())
        {
            vecFrozenAddress.push_back(address);
        }

    }


    // get pubkey by address

    std::vector<UniValue>  pubkey1;

    std::vector<std::string> vecPubkeys;

    for(auto address : vecFrozenAddress)
    {
        CTxDestination dest = DecodeDestination(address);
        CScript scriptPubKey = GetScriptForDestination(dest);

        UniValue ret(UniValue::VOBJ);
        ret.pushKVs(boost::apply_visitor(DescribeWalletAddressVisitorNt(pwallet), dest));

        UniValue pubkey = find_value(ret, "pubkey");

        pubkey1.push_back(pubkey);

        std::string sPubkey = pubkey.get_str();

        CPubKey pubkeyHex(ParseHex(sPubkey));

        vecPubkeyIDs.push_back(pubkeyHex);

        vecPubkeys.emplace_back(std::move(sPubkey));

    }

    return  vecPubkeys;

}

std::vector<std::string> CNodeToken::GetRegisterNodeTokenerVrfPubkey(uint32_t propertyId)
{

    std::vector<std::string> veVrfPubkey;

    propertyId++;

    //1, get omni transaction list

    int64_t nCount = 100;
    int64_t nFrom = 0;
    int64_t nStartBlock = 0;
    int64_t nEndBlock = (int)chainActive.Height();

    //obtain a sorted list of Omni layer wallet transactions (including STO receipts and pending)
    std::map<std::string,uint256> walletTransactions = FetchWalletOmniTransactions(nFrom+nCount, nStartBlock, nEndBlock);

    //2, get payload by transaction
    for (std::map<std::string,uint256>::reverse_iterator it = walletTransactions.rbegin(); it != walletTransactions.rend(); it++)
    {
        if (nFrom <= 0 && nCount > 0)
        {


            uint256 txHash = it->second;

            CTransactionRef tx;
            uint256 blockHash;
            if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
                PopulateFailure(MP_TX_NOT_FOUND);
            }

            int blockTime = 0;
            int blockHeight = GetHeight();
            if (!blockHash.IsNull()) {
                CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
                if (NULL != pBlockIndex) {
                    blockTime = pBlockIndex->nTime;
                    blockHeight = pBlockIndex->nHeight;
                }
            }

            CMPTransaction mp_obj;
            int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
            if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);

             std::string payload = mp_obj.getPayload();
             DecodePayload(payload, veVrfPubkey);

             nCount--;

        }
        nFrom--;
    }


    //3, decode payload and get vrfPubkey

    return  veVrfPubkey;

}

std::map<std::string, std::string> CNodeToken::GetRegisterNodeTokenerVrfPubkey()
{
    std::map<std::string, std::string> veVrfPubkeyDid;

    std::map<std::string, int> mapPubkeyID;
    //1, get omni transaction list
    int64_t nCount = 100;
    int64_t nFrom = 0;
    int64_t nStartBlock = 0;
    int64_t nEndBlock = (int)chainActive.Height();

    //obtain a sorted list of Omni layer wallet transactions (including STO receipts and pending)
    std::map<std::string,uint256> walletTransactions = FetchWalletOmniTransactions(nFrom+nCount, nStartBlock, nEndBlock);

    //2, get payload by transaction
    for (std::map<std::string,uint256>::iterator it = walletTransactions.begin(); it != walletTransactions.end(); it++)
    {
        if (nFrom <= 0 && nCount > 0)
        {
            uint256 txHash = it->second;
            CTransactionRef tx;
            uint256 blockHash;
            if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
                PopulateFailure(MP_TX_NOT_FOUND);
            }

            int blockTime = 0;
            int blockHeight = GetHeight();
            if (!blockHash.IsNull()) {
                CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
                if (NULL != pBlockIndex) {
                    blockTime = pBlockIndex->nTime;
                    blockHeight = pBlockIndex->nHeight;
                }
            }

            //3, decode payload and get vrfPubkey
            CMPTransaction mp_obj;
            int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
            if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);

             std::string payload = mp_obj.getPayload();
             GetVrfPubkeyDidbyDecodePayload(payload, veVrfPubkeyDid);

             nCount--;
        }
        nFrom--;
    }

    return  veVrfPubkeyDid;
}

std::map<std::string, std::string> CNodeToken::GetRegisterNodeTokenerVrfPubkeyTest()
{
    std::map<std::string, std::string> veVrfPubkeyDid;

    //1, get omni transaction list
    int64_t nCount = 100;
    int64_t nFrom = 0;
    int64_t nStartBlock = 0;
    int64_t nEndBlock = (int)chainActive.Height();

    //obtain a sorted list of Omni layer wallet transactions (including STO receipts and pending)
    std::map<std::string,uint256> walletTransactions = FetchWalletOmniTransactions(nFrom+nCount, nStartBlock, nEndBlock);

    //2, get payload by transaction
    for (std::map<std::string,uint256>::reverse_iterator it = walletTransactions.rbegin(); it != walletTransactions.rend(); it++)
    {
        if (nFrom <= 0 && nCount > 0)
        {
            uint256 txHash = it->second;
            CTransactionRef tx;
            uint256 blockHash;
            if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
                PopulateFailure(MP_TX_NOT_FOUND);
            }

            int blockTime = 0;
            int blockHeight = GetHeight();
            if (!blockHash.IsNull()) {
                CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
                if (NULL != pBlockIndex) {
                    blockTime = pBlockIndex->nTime;
                    blockHeight = pBlockIndex->nHeight;
                }
            }

            //3, decode payload and get vrfPubkey
            CMPTransaction mp_obj;
            int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
            if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);

             std::string payload = mp_obj.getPayload();
             auto propertyType =  mp_obj.getPropertyType();
             auto ss = mp_obj.getProperty();
             GetVrfPubkeyDidbyDecodePayloadTest(payload, veVrfPubkeyDid);

             nCount--;
        }
        nFrom--;
    }

    return  veVrfPubkeyDid;
}

bool CNodeToken::IsKeyidRegister(const std::string& keyid)
{
    bool IsRegister = false;

    //1, get omni transaction list
    int64_t nCount = 100;
    int64_t nFrom = 0;
    int64_t nStartBlock = 0;
    int64_t nEndBlock = (int)chainActive.Height();

    //obtain a sorted list of Omni layer wallet transactions (including STO receipts and pending)
    std::map<std::string,uint256> walletTransactions = FetchWalletOmniTransactions(nFrom+nCount, nStartBlock, nEndBlock);

    //2, get payload by transaction
    int64_t nRegisterCount = 0;
    for (std::map<std::string,uint256>::reverse_iterator it = walletTransactions.rbegin(); it != walletTransactions.rend(); it++)
    {
        uint256 txHash = it->second;
        CTransactionRef tx;
        uint256 blockHash;
        if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
            PopulateFailure(MP_TX_NOT_FOUND);
        }

        int blockTime = 0;
        int blockHeight = GetHeight();
        if (!blockHash.IsNull()) {
            CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
            if (NULL != pBlockIndex) {
                blockTime = pBlockIndex->nTime;
                blockHeight = pBlockIndex->nHeight;
            }
        }

        //3, decode payload and get vrfPubkey
        CMPTransaction mp_obj;
        int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
        if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);
        std::string sPayload = mp_obj.getPayload();
//        if(IsHasKeyRegisterKeyId(sPayload,keyid)) {   zzl   unuse
//            nRegisterCount++;
//        }
     }

    if (nRegisterCount&0x1) {
        IsRegister = true;  // ji shu shi, symbol register
    }
    else {
        IsRegister = false; //o shu shi, symbol unregiser
    }
    return IsRegister;

}

bool CNodeToken::IsKeyidRegisterDisk(std::vector<unsigned char>& keyid)
{
    bool IsRegister = false;

    // next let's obtain the block for this height
    int64_t nBlockHeight = (int)chainActive.Height();
    std::vector<uint256> vTxId;

    //#1 get omni transction list
    if(!p_txlistdb) return false;
    vTxId = p_txlistdb->getTransactionList();

    //#2 get payload by transaction
    int64_t nRegisterCount = 0;
    for(std::vector<uint256>::iterator itr=vTxId.begin(); itr != vTxId.end(); itr++){

        uint256 txHash = *itr;
        CTransactionRef tx;
        uint256 blockHash;
        if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
            continue;
        }

        int blockTime = 0;
        int blockHeight = GetHeight();
        if (!blockHash.IsNull()) {
            CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
            if (NULL != pBlockIndex) {
                blockTime = pBlockIndex->nTime;
                blockHeight = pBlockIndex->nHeight;
            }
        }

        //#3 decode payload and get vrfPubkey
        CMPTransaction mp_obj;
        int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
        if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);
        std::string sPayload = mp_obj.getPayload();
        if(IsHasKeyRegisterKeyId(sPayload,keyid)) {
            nRegisterCount++;
        }

    }

    if (nRegisterCount&0x1) {
        IsRegister = true;  // ji shu shi, symbol register
    }
    else {
        IsRegister = false; //o shu shi, symbol unregiser
    }
    return IsRegister;

}

std::map<std::vector<unsigned char>, std::vector<unsigned char>>  CNodeToken::GetRegisterNodeTokenerVrfPubkeyDisk()
{
    std::map<std::vector<unsigned char>, std::vector<unsigned char>>  veVrfPubkeyDid;

    std::map<std::vector<unsigned char>, CNodeToken::KeyInfo> mapVrfKeyInfo;

    //#1 get omni transction list
    std::vector<uint256> vTxId;
    if(p_txlistdb){
        vTxId = p_txlistdb->getTransactionList();
    }

    //#2 get payload by transaction
    int64_t nRegisterCount = 0;
    for(std::vector<uint256>::reverse_iterator itr=vTxId.rbegin(); itr != vTxId.rend(); itr++){

        uint256 txHash = *itr;
        CTransactionRef tx;
        uint256 blockHash;
        if (!GetTransaction(txHash, tx, Params().GetConsensus(), blockHash, true)) {
            continue;
        }

        int blockTime = 0;
        int blockHeight = GetHeight();
        if (!blockHash.IsNull()) {
            CBlockIndex* pBlockIndex = GetBlockIndex(blockHash);
            if (NULL != pBlockIndex) {
                blockTime = pBlockIndex->nTime;
                blockHeight = pBlockIndex->nHeight;
            }
        }

        //#3 decode payload and get vrfPubkey
        CMPTransaction mp_obj;
        int parseRC = ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
        if (parseRC < 0) PopulateFailure(MP_TX_IS_NOT_MASTER_PROTOCOL);
        std::string sPayload = mp_obj.getPayload();
        GetVrfPubkeyDidbyDecodePayloadDisk(sPayload, mapVrfKeyInfo);

     }
    //#4 fetch vrfPubkey and keyId info
    for(std::map<std::vector<unsigned char>, CNodeToken::KeyInfo>::iterator itr = mapVrfKeyInfo.begin(); itr != mapVrfKeyInfo.end(); itr++)    {
        std::vector<unsigned char> sVrfKey = itr->first;
        CNodeToken::KeyInfo& info = itr->second;
        if(info.nRgtFlag == 1)        {
            veVrfPubkeyDid.insert(std::make_pair(info.sVrfPubkey, info.sKeyID));
        }

    }
    return veVrfPubkeyDid;
}

uint32_t CNodeToken::GetPropertyIdByNodeTokenType(TokenType type)
{

    return  propertyId;

}

void CNodeToken::DecodePayload(std::string payload, std::vector<std::string>& veVrfPubkey)
{

    unsigned char vchPayload[255];
    memset(vchPayload,0,255);

    std::vector<unsigned char> vcPayloadTemp;
    if(IsHex(payload))
    {
        vcPayloadTemp = ParseHex(payload);
        int nsize = 0;
        for(std::vector<unsigned char>::iterator itr = vcPayloadTemp.begin();
            itr != vcPayloadTemp.end(); itr++)
        {
            vchPayload[nsize] = *itr;
            nsize++;
        }
    }
    else
    {
        memcpy(vchPayload, &payload, payload.length());
    }

    uint16_t messageType;
    memcpy(&messageType, &vchPayload[0], 2);
    SwapByteOrder16(messageType);

    uint16_t messageVer;
    memcpy(&messageVer, &vchPayload[2], 2);
    SwapByteOrder16(messageVer);

    uint32_t propertyId;
    memcpy(&propertyId, &vchPayload[4], 4);
    SwapByteOrder32(propertyId);

    uint64_t amount;
    memcpy(&amount, &vchPayload[8], 8);
    SwapByteOrder64(amount);

    unsigned char chmemo[255];
    memset(chmemo, 0, 255);
    memcpy(&chmemo, &vchPayload[16], 255 - 16);


    std::string memostr;
    memostr = std::string((char*)chmemo);

    veVrfPubkey.push_back(memostr);
}

void CNodeToken::GetVrfPubkeyDidbyDecodePayload(std::string payload, std::map<std::string,std::string>& mapVrfPubkeyDid)
{
    unsigned char vchPayload[255];
    memset(vchPayload,0,255);

    std::vector<unsigned char> vcPayloadTemp;
    if(IsHex(payload))
    {
        vcPayloadTemp = ParseHex(payload);
        int nsize = 0;
        for(std::vector<unsigned char>::iterator itr = vcPayloadTemp.begin();
            itr != vcPayloadTemp.end(); itr++)
        {
            vchPayload[nsize] = *itr;
            nsize++;
        }
    }
    else
    {
        memcpy(vchPayload, &payload, payload.length());
    }

    uint16_t messageVer;
    memcpy(&messageVer, &vchPayload[0], 2);
    SwapByteOrder16(messageVer);

    uint16_t messageType;
    memcpy(&messageType, &vchPayload[2], 2);
    SwapByteOrder16(messageType);
    if(messageType != 0 )
    {
        return;
    }

    uint32_t propertyId;
    memcpy(&propertyId, &vchPayload[4], 4);
    SwapByteOrder32(propertyId);

    uint64_t amount;
    memcpy(&amount, &vchPayload[8], 8);
    SwapByteOrder64(amount);

    uint16_t registerflag;
    memcpy(&registerflag, &vchPayload[16], 2);
    SwapByteOrder16(registerflag);

    std::string sVrfPubkey;
    int nIndex = 18;
    while(vchPayload[nIndex] != '\0')
    {
        sVrfPubkey.push_back((char)vchPayload[nIndex]);
        nIndex++;
    }
    if(sVrfPubkey.length() <= 0)
    {
        return;
    }

    const char* pkeyid = ++nIndex + (char*)&vchPayload[0];
    std::string sKeyid(pkeyid);
    if(registerflag == 1) {
        mapVrfPubkeyDid.insert(std::make_pair(sVrfPubkey,sKeyid));
    } else if(registerflag == 0) {
       std::map<std::string,std::string>::iterator itr = mapVrfPubkeyDid.find(sVrfPubkey);
       if(itr != mapVrfPubkeyDid.end()) {
           mapVrfPubkeyDid.erase(itr);
       }
    }

}

void CNodeToken::GetVrfPubkeyDidbyDecodePayloadDisk(std::string payload, std::map<std::vector<unsigned char>, CNodeToken::KeyInfo> &mapKeyInfo)
{
    unsigned char vchPayload[255];
    memset(vchPayload,0,255);

    std::vector<unsigned char> vcPayloadTemp;
    if(IsHex(payload))
    {
        vcPayloadTemp = ParseHex(payload);
        int nsize = 0;
        for(std::vector<unsigned char>::iterator itr = vcPayloadTemp.begin();
            itr != vcPayloadTemp.end(); itr++)
        {
            vchPayload[nsize] = *itr;
            nsize++;
        }
    }
    else
    {
        memcpy(vchPayload, &payload, payload.length());
    }

    uint16_t messageVer;
    memcpy(&messageVer, &vchPayload[0], 2);
    SwapByteOrder16(messageVer);

    uint16_t messageType;
    memcpy(&messageType, &vchPayload[2], 2);
    SwapByteOrder16(messageType);
    if(messageType != 0 )
    {
        return;
    }

    uint32_t propertyId;
    memcpy(&propertyId, &vchPayload[4], 4);
    SwapByteOrder32(propertyId);

    uint64_t amount;
    memcpy(&amount, &vchPayload[8], 8);
    SwapByteOrder64(amount);

    uint16_t registerflag;
    memcpy(&registerflag, &vchPayload[16], 2);
    SwapByteOrder16(registerflag);

    std::vector<unsigned char> sVrfPubkey;
    std::vector<unsigned char>::size_type nIndex = 18;
    while(nIndex < 18 + 32)
    {
        sVrfPubkey.push_back(vchPayload[nIndex]);
        nIndex++;
    }

    std::vector<unsigned char> sKeyId;
    std::vector<unsigned char>::size_type nIndexx = nIndex;
    while(nIndexx < nIndex + 20)
    {
        sKeyId.push_back(vchPayload[nIndexx]);
        nIndexx++;
    }

    const char* pkeyid = nIndex + (char*)&vchPayload[0];
    std::string sKeyid(pkeyid);

    // ### todo..
    std::map<std::vector<unsigned char>, CNodeToken::KeyInfo>::iterator itr = mapKeyInfo.find(sKeyId);
    if(itr != mapKeyInfo.end()) {
        CNodeToken::KeyInfo& keyInfo =  itr->second;
        if(registerflag == 1) {
            keyInfo.nRgtFlag +=1;

        } else if(registerflag == 0) {
             keyInfo.nRgtFlag -=1;
        }
        mapKeyInfo[sKeyId] = keyInfo;

    } else {
        CNodeToken::KeyInfo Info;
        Info.sVrfPubkey = sVrfPubkey;
        Info.sKeyID = sKeyId;
        if(registerflag == 1) {
            Info.nRgtFlag +=1;

        } else if(registerflag == 0) {
             Info.nRgtFlag -=1;
        }
        mapKeyInfo.insert(std::make_pair(sKeyId, Info));
    }


}

void CNodeToken::GetVrfPubkeyDidbyDecodePayloadTest(std::string payload, std::map<std::string, std::string> &VrfPubkeyDid)
{
    unsigned char vchPayload[255];
    memset(vchPayload,0,255);

    std::vector<unsigned char> vcPayloadTemp;
    if(IsHex(payload))
    {
        vcPayloadTemp = ParseHex(payload);
        int nsize = 0;
        for(std::vector<unsigned char>::iterator itr = vcPayloadTemp.begin();
            itr != vcPayloadTemp.end(); itr++)
        {
            vchPayload[nsize] = *itr;
            nsize++;
        }
    }
    else
    {
        memcpy(vchPayload, &payload, payload.length());
    }


    uint16_t messageType;
    memcpy(&messageType, &vchPayload[0], 2);
    SwapByteOrder16(messageType);
    if(messageType != 34)
    {
        return;
    }

    std::string sVrfPubkey;
    int nIndex = 2;
    while(vchPayload[nIndex] != '\0')
    {
        sVrfPubkey.push_back((char)vchPayload[nIndex]);
        nIndex++;
    }
    const char* pDid = ++nIndex + (char*)&vchPayload[0];
    std::string sDid(pDid);

    VrfPubkeyDid.insert(std::make_pair(sVrfPubkey,sDid));
}

bool CNodeToken::IsHasKeyRegisterKeyId(const std::string& payload, std::vector<unsigned char>& keyid)
{
    bool bRegistetKeyId = false;

    unsigned char vchPayload[255];
    memset(vchPayload,0,255);

    std::vector<unsigned char> vcPayloadTemp;
    if(IsHex(payload)) {
        vcPayloadTemp = ParseHex(payload);
        int nsize = 0;
        for(std::vector<unsigned char>::iterator itr = vcPayloadTemp.begin();
            itr != vcPayloadTemp.end(); itr++)
        {
            vchPayload[nsize] = *itr;
            nsize++;
        }
    }
    else {
        memcpy(vchPayload, &payload, payload.length());
    }

    uint16_t messageVer;
    memcpy(&messageVer, &vchPayload[0], 2);
    SwapByteOrder16(messageVer);

    uint16_t messageType;
    memcpy(&messageType, &vchPayload[2], 2);
    SwapByteOrder16(messageType);
    if(messageType != 0 ) {
        return bRegistetKeyId;
    }

    uint32_t propertyId;
    memcpy(&propertyId, &vchPayload[4], 4);
    SwapByteOrder32(propertyId);

    uint64_t amount;
    memcpy(&amount, &vchPayload[8], 8);
    SwapByteOrder64(amount);

    uint16_t registerflag;
    memcpy(&registerflag, &vchPayload[16], 2);
    SwapByteOrder16(registerflag);

    std::vector<unsigned char> sVrfPubkey;
    std::vector<unsigned char>::size_type nIndex = 18;
    while(nIndex < 18 + 32) {
        sVrfPubkey.push_back(vchPayload[nIndex]);
        nIndex++;
    }

    std::vector<unsigned char> vKeyIdTemp;
    std::vector<unsigned char>::size_type nIndexx = nIndex;
    while(nIndexx < nIndex + 20) {
        vKeyIdTemp.push_back(vchPayload[nIndexx]);
        nIndexx++;
    }

    if(vKeyIdTemp == keyid) {
       bRegistetKeyId = true;
    }

    return bRegistetKeyId;

}


