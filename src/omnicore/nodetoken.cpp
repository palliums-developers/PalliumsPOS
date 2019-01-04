#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif
#include "wallet/rpcwallet.h"
#include "omnicore/omnicore.h"

#include "omnicore/errors.h"
#include "omnicore/utilsbitcoin.h"
#include "omnicore/tx.h"
#include "omnicore/dbtxlist.h"
#include "omnicore/rpc.h"
#include "nodetoken.h"

#include "validation.h"
#include "chainparams.h"

using namespace mastercore;
extern CMPTxList* mastercore::p_txlistdb;
extern CCriticalSection cs_main;

CNodeToken::CNodeToken()
{

}

CNodeToken::~CNodeToken()
{

}

bool CNodeToken::IsKeyidRegisterDisk(std::vector<unsigned char>& keyid)
{
    bool IsRegister = false;

    // next let's obtain the block for this height
    LOCK2(cs_main, cs_tally);
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
        ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
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
    LOCK2(cs_main, cs_tally);
    std::vector<uint256> vTxId;
    if(p_txlistdb){
        vTxId = p_txlistdb->getTransactionList();
    }

    //#2 get payload by transaction
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
        ParseTransaction(*tx, blockHeight, 0, mp_obj, blockTime);
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

    //# statistics of the vrf public key
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


