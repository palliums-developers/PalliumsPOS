#include "validation.h"
#include <witness.h>
#include <base58.h>
#include <wallet/wallet.h>
#include <rpc/mining.h>
#include <policy/policy.h>
#include <util.h>
#include <script/script.h>

bool GreaterSort(uint160 a,uint160 b){
    return a < b;
}

uint160 Address2uint160(const std::string& address)
{
    const CChainParams& params=Params();
    std::vector<unsigned char> data;
    uint160 hash;
    if (DecodeBase58Check(address, data)) {
        // base58-encoded Bitcoin addresses.
        // Public-key-hash-addresses have version 0 (or 111 testnet).
        // The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
        const std::vector<unsigned char>& pubkey_prefix = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
        if (data.size() == hash.size() + pubkey_prefix.size() && std::equal(pubkey_prefix.begin(), pubkey_prefix.end(), data.begin())) {
            std::copy(data.begin() + pubkey_prefix.size(), data.end(), hash.begin());
            return hash;
        }
        // Script-hash-addresses have version 5 (or 196 testnet).
        // The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
        const std::vector<unsigned char>& script_prefix = params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
        if (data.size() == hash.size() + script_prefix.size() && std::equal(script_prefix.begin(), script_prefix.end(), data.begin())) {
            std::copy(data.begin() + script_prefix.size(), data.end(), hash.begin());
            return hash;
        }
    }
    return uint160();
}

uint160 local_address;

std::vector<uint160> witness_keys;

bool GetLocalKeyID(CWallet* const pwallet)
{
    bool find=false;
    witness_keys.clear();
    for(auto &address:vWitnessAddresses)
    {
        uint160 u160addr = Address2uint160(address);
        if (u160addr.IsNull()) {
            LogPrintf("Error:address %s is invalid\n",address);
            return false;
        }
        witness_keys.push_back(u160addr);

        CTxDestination dest = DecodeDestination(address);
        auto keyid = GetKeyForDestination(*pwallet, dest);
        if (keyid.IsNull()) {
            continue;
        }
        CKey vchSecret;
        if (!pwallet->GetKey(keyid, vchSecret)) {
            continue;
        }
        local_address=u160addr;
        find = true;
    }
    std::sort(witness_keys.begin(),witness_keys.end(),GreaterSort);
    return find;
}


void ScheduleProductionLoop()
{
    std::shared_ptr<CWallet> const wallet = GetWallet("");
    CWallet* const pwallet = wallet.get();
    if (!pwallet||!EnsureWalletIsAvailable(pwallet, false))
    {
        LogPrintf("Wallet does not exist or is not loaded\n");
        throw;
    }
    while(!GetLocalKeyID(pwallet))
    {
        LogPrintf("Local witness address not find\n");
        MilliSleep(1000);
        continue;
    }

    LogPrintf("Launching block production for %d witnesses.", witness_keys.size());
    {
    }

    while (pwallet->IsLocked())
    {
        LogPrintf("Info: Minting suspended due to locked wallet.\n");;
        MilliSleep(1000);
    }

    while(true)
    {
        //XXX:Schedule for the next second's tick regardless of chain state
        // If we would wait less than 50ms, wait for the whole second.
        int64_t now = GetTimeMicros();
        int64_t time_to_next_second = 1000000 - (now % 1000000);
        if( time_to_next_second < 50000 )      // we must sleep for at least 50ms
            time_to_next_second += 1000000;
        int64_t next_wakeup_milli=(now + time_to_next_second)/1000;
        MilliSleep(next_wakeup_milli);//sleep for next_wakeup_milli ms
        LogPrintf("Witness Block Production");
    }
}

// minter thread
void static ThreadMinter(void* parg)
{
    LogPrintf("ThreadMinter started\n");
    try {
        ScheduleProductionLoop();
    }
    catch (std::exception& e) {
        error("%s ThreadMinter()", e.what());
    }
}


// minter
void MintStart(boost::thread_group& threadGroup)
{
    //  mint blocks in the background
    threadGroup.create_thread(boost::bind(&ThreadMinter, nullptr));
}


bool fUseIrreversibleBlock = true;

static Vote vote;
Vote& Vote::GetInstance()
{
    return vote;
}

CKeyID localKeyID;

std::vector<Delegate> Vote::GetTopDelegateInfo(uint64_t nMinHoldBalance, uint32_t nDelegateNum)
{
    std::shared_ptr<CWallet> const wallet = GetWallet("");
    CWallet* const pwallet = wallet.get();
    if (!pwallet||!EnsureWalletIsAvailable(pwallet, false))
    {
        LogPrintf("Wallet does not exist or is not loaded\n");
        throw;
    }
    std::vector<Delegate> result;
    std::set<CKeyID> delegates;

    for(auto &address:vWitnessAddresses)
    {
        CTxDestination dest = DecodeDestination(address);
        auto keyid = GetKeyForDestination(*pwallet, dest);
        if (keyid.IsNull()) {
            continue;
        }
        delegates.insert(keyid);
        CKey vchSecret;
        if (!pwallet->GetKey(keyid, vchSecret)) {
            continue;
        }
        localKeyID=keyid;
    }

    uint64_t vote_num=delegates.size()+nMinHoldBalance;
    for(auto it = delegates.rbegin(); it != delegates.rend(); ++it)
    {
        if(result.size() >= nDelegateNum) {
            break;
        }
        result.push_back(Delegate(*it,vote_num--));
    }
}

typedef boost::shared_lock<boost::shared_mutex> read_lock;
typedef boost::unique_lock<boost::shared_mutex> write_lock;

void Vote::DeleteInvalidVote(uint64_t height)
{
    //TODO:complete this function
    return;
}

static DPoS gDPoS;
static DPoS *gpDPoS = nullptr;

DPoS::~DPoS()
{
    WriteIrreversibleBlockInfo(cIrreversibleBlockInfo);
}

void DPoS::Init()
{
    nMaxMemory = gArgs.GetArg("-maxmemory", DEFAULT_MAX_MEMORY_SIZE);
    if(Params().NetworkIDString() == "main") {
        cSuperForgerAddress = "166D9UoFdPcDEGFngswE226zigS8uBnm3C";
        gDPoS.nDposStartTime = 1539181795;

        nMaxDelegateNumber = 101;
        nBlockIntervalTime = 3;
        nDposStartHeight = 7000;
    } else {
        cSuperForgerAddress = "my5ioJEbbhMjRzgyQpcnq6fmbfUMQgTqMZ";
        gDPoS.nDposStartTime = 0;

        nMaxDelegateNumber = 10;
        nBlockIntervalTime = 3;
        nDposStartHeight = 7000;
    }

    strIrreversibleBlockFileName = (GetDataDir() / "dpos" / "irreversible_block.dat").string();
    ReadIrreversibleBlockInfo(cIrreversibleBlockInfo);

    if(chainActive.Height() >= nDposStartHeight - 1) {
        SetStartTime(chainActive[nDposStartHeight -1]->nTime);
    }
}

DPoS& DPoS::GetInstance()
{
    if(gpDPoS == nullptr) {
        gDPoS.Init();
        gpDPoS = &gDPoS;
    }

    return gDPoS;
}

bool GetKeyID(const std::string& address,CKeyID& keyID)
{
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        return  false;
    }

    CKeyID *keyid = boost::get<CKeyID>(&dest);
    if (!keyid) {
        return  false;
    }
    keyID=*keyid;
    return true;
}

bool DPoS::IsMining(DelegateInfo& cDelegateInfo, const std::string& cAddress, time_t t)
{
    CBlockIndex* pBlockIndex = chainActive.Tip();
    if(pBlockIndex->nHeight < nDposStartHeight - 1) {
        if(cAddress == cSuperForgerAddress) {
            static time_t tLast = 0;
            if(t < tLast + nBlockIntervalTime) {
                return false;
            } else {
                tLast = t;
                return true;
            }
        } else {
            return false;
        }
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(t);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(t);
    uint64_t nPrevLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    uint32_t nPrevDelegateIndex = GetDelegateIndex(pBlockIndex->nTime);
    CKeyID keyid;
    if(!GetKeyID(cAddress,keyid)){
        LogPrintf("IsMining: get keyid failed");
        return false;
    }

    if(pBlockIndex->nHeight == nDposStartHeight - 1) {
        cDelegateInfo = DPoS::GetNextDelegates(t);
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].keyid == keyid) {
            return true;
        } else {
            return false;
        }
    }

    if(nCurrentLoopIndex > nPrevLoopIndex) {
        cDelegateInfo = DPoS::GetNextDelegates(t);
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].keyid == keyid) {
            return true;
        } else {
            return false;
        }
    } else if(nCurrentLoopIndex == nPrevLoopIndex && nCurrentDelegateIndex > nPrevDelegateIndex) {
        DelegateInfo cCurrentDelegateInfo;
        if(GetBlockDelegates(cCurrentDelegateInfo, pBlockIndex)) {
            if(nCurrentDelegateIndex + 1 > cCurrentDelegateInfo.delegates.size()) {
                return false;
            } else if(cCurrentDelegateInfo.delegates[nCurrentDelegateIndex].keyid == keyid) {
                //cDelegateInfo.delegates.clear();
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    return false;
}

DelegateInfo DPoS::GetNextDelegates(int64_t t)
{
    uint64_t nMinHoldBalance = 500000000000;

    std::vector<Delegate> delegates = Vote::GetInstance().GetTopDelegateInfo(nMinHoldBalance, nMaxDelegateNumber);

    LogPrintf("DPoS: GetNextDelegates start\n");
    for(auto i : delegates)
        LogPrintf("DPoS: delegate %s %lu\n", EncodeDestination(i.keyid), i.votes);
    LogPrintf("DPoS: GetNextDelegates end\n");

    Delegate delegate;
    GetKeyID(cSuperForgerAddress,delegate.keyid);
    delegate.votes = 7;
    delegates.insert(delegates.begin(), delegate);

    delegates.resize(nMaxDelegateNumber);

    DelegateInfo cDelegateInfo;
    cDelegateInfo.delegates = SortDelegate(delegates, t);

    return cDelegateInfo;
}

std::vector<char> GetRand(unsigned num, unsigned int seed)
{
    std::vector<char> r;
    std::vector<char> s(num, -1);

    while(r.size() < num) {
        uint64_t v;
        v = rand_r(&seed);
        v %= num;
        if(s[v] < 0) {
            s[v] = 1;
            r.push_back(v);
        }
    }
    return r;
}

std::vector<Delegate> DPoS::SortDelegate(const std::vector<Delegate>& delegates, uint64_t t)
{
    std::vector<Delegate> result;
    unsigned int seed = (unsigned int)t;
    std::vector<char>&& r = GetRand(delegates.size(), seed);
    for(auto& i : r) {
        result.push_back(delegates[i]);
    }
    return result;
}

bool DPoS::GetBlockDelegates(DelegateInfo& cDelegateInfo, CBlockIndex* pBlockIndex)
{
    bool ret = false;
    uint64_t nLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    while(pBlockIndex) {
        if(pBlockIndex->nHeight == nDposStartHeight || GetLoopIndex(pBlockIndex->pprev->nTime) < nLoopIndex) {
            CBlock block;
            if(ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) {
                ret = GetBlockDelegate(cDelegateInfo, block);
            }
            break;
        }

        pBlockIndex = pBlockIndex->pprev;
    }

    return ret;
}

bool DPoS::GetBlockDelegates(DelegateInfo& cDelegateInfo, const CBlock& block)
{
    CBlockIndex blockindex;
    blockindex.nTime = block.nTime;
    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("GetBlockDelegates find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }
    blockindex.pprev = miSelf->second;
    return GetBlockDelegates(cDelegateInfo, &blockindex);
}

uint64_t DPoS::GetLoopIndex(uint64_t time)
{
    if(time < nDposStartTime) {
        return 0;
    } else {
        return (time - nDposStartTime) / (nMaxDelegateNumber * nBlockIntervalTime);
    }
}

uint32_t DPoS::GetDelegateIndex(uint64_t time)
{
    if(time < nDposStartTime) {
        return 0;
    } else {
        return (time - nDposStartTime) % (nMaxDelegateNumber * nBlockIntervalTime) / nBlockIntervalTime;
    }
}

bool DPoS::CheckCoinbase(const CTransaction& tx, time_t t, int64_t height)
{
    bool ret = false;
    if(tx.vout.size() == 2) {
        CTxDestination dest;
        if (ExtractDestination(tx.vout[0].scriptPubKey, dest) ) {
            DelegateInfo cDelegateInfo;
            ret = ScriptToDelegateInfo(cDelegateInfo, t, tx.vout[1].scriptPubKey, &dest, true);
        }
    }

    if(ret == false) {
        LogPrintf("CheckCoinbase txhash:%s failed!", tx.GetHash().ToString());
    }
    return ret;
}

//OP_RETURN VECTOR<UNSIGNED CHAR>
//OP_RETURN PUBKEY SIG(t) DELEGATE_IDS
CScript DPoS::DelegateInfoToScript(const DelegateInfo& cDelegateInfo, const CKey& delegatekey, uint64_t t)
{
    const std::vector<Delegate>& delegates = cDelegateInfo.delegates;

    int nDataLen = 1 + delegates.size() * 20;
    std::vector<unsigned char> data;

    if(cDelegateInfo.delegates.empty() == false) {
        data.resize(nDataLen);
        data[0] = 0x7;

        unsigned char* pData = &data[1];
        for(unsigned int i =0; i < delegates.size(); ++i) {
            memcpy(pData, delegates[i].keyid.begin(), 20);
            pData += 20;
        }
    }

    std::vector<unsigned char> vchSig;
    std::string ts = std::to_string(t);
    delegatekey.Sign(Hash(ts.begin(), ts.end()), vchSig);

    CScript script;
    if(cDelegateInfo.delegates.empty() == false) {
        script << OP_RETURN << ToByteVector(delegatekey.GetPubKey()) << vchSig << data;
    } else {
        script << OP_RETURN << ToByteVector(delegatekey.GetPubKey()) << vchSig;
    }
    return script;
}

//OP_RETURN VECTOR<UNSIGNED CHAR>
//OP_RETURN PUBKEY SIG(t) DELEGATE_IDS
bool DPoS::ScriptToDelegateInfo(DelegateInfo& cDelegateInfo, uint64_t t, const CScript& script, const CTxDestination* paddress, bool fCheck)
{
    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator it = script.begin();
    script.GetOp(it, op);
    if(op == OP_RETURN) {
        std::vector<unsigned char> vctPublicKey;
        if(GetScriptOp(it,script.end(), op, &vctPublicKey) == false) {
            return false;
        }

        CPubKey pubkey(vctPublicKey);

        std::vector<unsigned char> vctSig;
        if(GetScriptOp(it,script.end(), op, &vctSig) == false) {
            return false;
        }

        std::string sh = std::to_string(t);
        auto hash = Hash(sh.begin(), sh.end());

        if(fCheck) {
            if(pubkey.Verify(hash, vctSig) == false) {
                return false;
            }
        }

        if(paddress!=nullptr) {
            auto keyid = boost::get<CKeyID>(paddress);
            if(pubkey.GetID() != *keyid) {
                return false;
            }
        }

        if(GetScriptOp(it,script.end(), op, &data)) {
            if((data.size() - (1)) % (20) == 0) {
                unsigned char* pData = &data[1];
                uint32_t nDelegateNum = (data.size() - (1)) / (20);
                for(unsigned int i =0; i < nDelegateNum; ++i) {
                    std::vector<unsigned char> vct(pData, pData + 20);
                    cDelegateInfo.delegates.push_back(Delegate(CKeyID(uint160(vct)), 0));
                    pData += 20;
                }

                return true;
            }
        }
    }
    return true;
}

std::string DPoS::GetBlockForgerAddress(const CBlock& block)
{
    auto& tx = block.vtx[0];

    std::string ret;
    if(tx->IsCoinBase() && tx->vout.size() == 2) {
        CTxDestination dest;
        if(ExtractDestination(tx->vout[0].scriptPubKey, dest)) {
            ret = EncodeDestination(dest);
        }
    }
    return ret;
}

bool DPoS::GetBlockForgerKeyID(CKeyID& keyid, const CBlock& block)
{
    bool ret = false;
    std::string address = GetBlockForgerAddress(block);
    ret = GetKeyID(address,keyid);
    return ret;
}

bool DPoS::GetBlockDelegate(DelegateInfo& cDelegateInfo, const CBlock& block)
{
    bool ret = false;

    auto tx = block.vtx[0];
    if(tx->IsCoinBase() && tx->vout.size() == 2) {
        opcodetype op;
        std::vector<unsigned char> vctData;
        {
            CScript::const_iterator it = tx->vout[0].scriptPubKey.begin();
            auto& script = tx->vout[0].scriptPubKey;
            GetScriptOp(it,script.end(), op, &vctData);
        }

        auto script = tx->vout[1].scriptPubKey;
        ret = ScriptToDelegateInfo(cDelegateInfo, block.nTime, script, nullptr, false);
    }

    return ret;
}

bool DPoS::CheckBlockDelegate(const CBlock& block)
{
    DelegateInfo cDelegateInfo;
    if(DPoS::GetBlockDelegate(cDelegateInfo, block) == false) {
        LogPrintf("CheckBlockDelegate GetBlockDelegate hash:%s error\n", block.GetHash().ToString().c_str());
        return false;
    }

    bool ret = true;
    DelegateInfo cNextDelegateInfo = GetNextDelegates(block.nTime);
    if(cDelegateInfo.delegates.size() == cNextDelegateInfo.delegates.size()) {
        for(unsigned int i =0; i < cDelegateInfo.delegates.size(); ++i) {
            if(cDelegateInfo.delegates[i].keyid != cNextDelegateInfo.delegates[i].keyid) {
                ret = false;
                break;
            }
        }
    }

    if(ret == false) {
        for(unsigned int i =0; i < cDelegateInfo.delegates.size(); ++i) {
            LogPrintf("CheckBlockDelegate BlockDelegate[%u]: %s\n", i, EncodeDestination(cDelegateInfo.delegates[i].keyid).c_str());
        }

        for(unsigned int i =0; i < cNextDelegateInfo.delegates.size(); ++i) {
            LogPrintf("CheckBlockDelegate NextBlockDelegate[%u]: %s %llu\n", i, EncodeDestination(cNextDelegateInfo.delegates[i].keyid).c_str(), cNextDelegateInfo.delegates[i].votes);
        }
    }

    return ret;
}

bool DPoS::CheckBlockHeader(const CBlockHeader& block)
{
    auto t = time(NULL) + 3;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - 3);
        return false;
    }

    if(block.hashPrevBlock.IsNull()) {
        return true;
    }

    return true;

    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("CheckBlockHeader find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }

    CBlockIndex* pPrevBlockIndex = miSelf->second;

    if(pPrevBlockIndex->nHeight == nDposStartHeight - 1) {
        //SetStartTime(chainActive[nDposStartHeight -1]->nTime);
        SetStartTime(pPrevBlockIndex->nTime);
    }

    if(pPrevBlockIndex->nHeight < nDposStartHeight) {
        return true;
    }

    bool ret = false;
    uint64_t nCurrentLoopIndex = GetLoopIndex(block.nTime);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(block.nTime);
    uint64_t nPrevLoopIndex = GetLoopIndex(pPrevBlockIndex->nTime);
    uint32_t nPrevDelegateIndex = GetDelegateIndex(pPrevBlockIndex->nTime);

    if(nCurrentLoopIndex > nPrevLoopIndex
            || (nCurrentLoopIndex == nPrevLoopIndex && nCurrentDelegateIndex > nPrevDelegateIndex)) {
        ret = true;
    } else {
        ret = false;
    }

    if(ret == false) {
        LogPrintf("DPoS CheckBlockHeader hash(%s) error\n", block.GetHash().ToString().c_str());
    }
    return ret;
}

bool DPoS::CheckBlock(const CBlockIndex& blockindex, bool fIsCheckDelegateInfo)
{
    if(chainActive.Height() == nDposStartHeight - 1) {
        SetStartTime(chainActive[nDposStartHeight -1]->nTime);
    }

    CBlock block;
    if(ReadBlockFromDisk(block, &blockindex, Params().GetConsensus()) == false) {
        return false;
    }

    return CheckBlock(block, fIsCheckDelegateInfo);
}

bool DPoS::CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo)
{
    auto t = time(NULL) + 3;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - 3);
        return false;
    }

    if(block.hashPrevBlock.IsNull()) {
        return true;
    }

    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("CheckBlock find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }

    CBlockIndex* pPrevBlockIndex = miSelf->second;

    int64_t nBlockHeight = pPrevBlockIndex->nHeight + 1;

    if(CheckCoinbase(*block.vtx[0], block.nTime, nBlockHeight) == false) {
        LogPrintf("CheckBlock CheckCoinbase error\n");
        return false;
    }

    if(nDposStartTime == 0 && chainActive.Height() >= nDposStartHeight - 1) {
        SetStartTime(chainActive[nDposStartHeight -1]->nTime);
    }

    if(nBlockHeight < nDposStartHeight) {
        if(GetBlockForgerAddress(block) == cSuperForgerAddress) {
            return true;
        } else {
            LogPrintf("CheckBlock nBlockHeight < nDposStartHeight ForgerAddress error\n");
            return false;
        }
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(block.nTime);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(block.nTime);
    uint64_t nPrevLoopIndex = 0;
    uint32_t nPrevDelegateIndex = 0;

    nPrevLoopIndex = GetLoopIndex(pPrevBlockIndex->nTime);
    nPrevDelegateIndex = GetDelegateIndex(pPrevBlockIndex->nTime);

    bool ret = false;
    DelegateInfo cDelegateInfo;

    if(nBlockHeight == nDposStartHeight) {
        if(fIsCheckDelegateInfo) {
            if(CheckBlockDelegate(block) == false) {
                return false;
            }
        }

        GetBlockDelegate(cDelegateInfo, block);
    } else if(nCurrentLoopIndex < nPrevLoopIndex) {
        LogPrintf("CheckBlock nCurrentLoopIndex < nPrevLoopIndex error\n");
        return false;
    } else if(nCurrentLoopIndex > nPrevLoopIndex) {
        if(fIsCheckDelegateInfo) {
            if(CheckBlockDelegate(block) == false) {
                return false;
            }
            ProcessIrreversibleBlock(nBlockHeight, block.GetHash());
        }

        GetBlockDelegate(cDelegateInfo, block);
        //} else if(nCurrentLoopIndex == nPrevLoopIndex) {
    } else {
        if(nCurrentDelegateIndex <= nPrevDelegateIndex) {
            LogPrintf("CheckBlock nCurrentDelegateIndex <= nPrevDelegateIndex error pretime:%u\n", pPrevBlockIndex->nTime);
            return false;
        }

        GetBlockDelegates(cDelegateInfo, pPrevBlockIndex);
    }

    CKeyID delegate;
    GetBlockForgerKeyID(delegate, block);
    if(nCurrentDelegateIndex < cDelegateInfo.delegates.size()
            && cDelegateInfo.delegates[nCurrentDelegateIndex].keyid == delegate) {
        ret = true;
    } else {
        LogPrintf("CheckBlock GetDelegateID blockhash:%s error\n", block.ToString().c_str());
    }

    return ret;
}

bool DPoS::IsOnTheSameChain(const std::pair<int64_t, uint256>& first, const std::pair<int64_t, uint256>& second)
{
    bool ret = false;

    BlockMap::iterator it = mapBlockIndex.find(second.second);
    if(it != mapBlockIndex.end()) {
        CBlockIndex *pindex = it->second;
        while(pindex->nHeight != first.first) {
            pindex = pindex->pprev;
        }

        if(*pindex->phashBlock == first.second) {
            ret = true;
        }
    }

    return ret;
}

IrreversibleBlockInfo DPoS::GetIrreversibleBlockInfo()
{
    return cIrreversibleBlockInfo;
}

void DPoS::SetIrreversibleBlockInfo(const IrreversibleBlockInfo& info)
{
    cIrreversibleBlockInfo = info;
}

bool DPoS::ReadIrreversibleBlockInfo(IrreversibleBlockInfo& info)
{
    if(fUseIrreversibleBlock == false) {
        return true;
    }

    bool ret = false;
    FILE *file = fopen(strIrreversibleBlockFileName.c_str(), "r");
    if(file) {
        char buff[128];
        char line[256];
        int64_t height;
        uint256 hash;

        while(fgets(line, sizeof(line), file)) {
            if(sscanf(line, "%ld;%s\n", &height, buff) > 0) {
                hash.SetHex(buff);
                AddIrreversibleBlock(height, hash);
            }
        }

        fclose(file);
        ret = true;
    }

    return ret;
}


bool DPoS::WriteIrreversibleBlockInfo(const IrreversibleBlockInfo& info)
{
    if(fUseIrreversibleBlock == false) {
        return true;
    }

    bool ret = false;
    if(cIrreversibleBlockInfo.mapHeightHash.empty()) {
        return true;
    }

    FILE *file = fopen(strIrreversibleBlockFileName.c_str(), "w");
    if(file) {
        for(auto& it : cIrreversibleBlockInfo.mapHeightHash) {
            fprintf(file, "%ld;%s\n", it.first, it.second.ToString().c_str());
        }
        fclose(file);
        ret = true;
    }

    return ret;
}


void DPoS::ProcessIrreversibleBlock(int64_t height, uint256 hash)
{
    if(fUseIrreversibleBlock == false) {
        return;
    }

    write_lock l(lockIrreversibleBlockInfo);

    int i = 0;
    for(i = nMaxConfirmBlockCount - 1; i >= 0; --i) {
        if(cIrreversibleBlockInfo.heights[i] < 0 || height <= cIrreversibleBlockInfo.heights[i]) {
            cIrreversibleBlockInfo.heights[i] = -1;
        } else {
            if(IsOnTheSameChain(std::make_pair(cIrreversibleBlockInfo.heights[i], cIrreversibleBlockInfo.hashs[i]), std::make_pair(height, hash))) {
                assert(height > cIrreversibleBlockInfo.heights[i]);
                if((height - cIrreversibleBlockInfo.heights[i]) * 100 >= nMaxDelegateNumber * nFirstIrreversibleThreshold) {
                    AddIrreversibleBlock(cIrreversibleBlockInfo.heights[i], cIrreversibleBlockInfo.hashs[i]);
                    LogPrintf("First NewIrreversibleBlock height:%ld hash:%s\n", cIrreversibleBlockInfo.heights[i], cIrreversibleBlockInfo.hashs[i].ToString().c_str());

                    //TODO:vote irreversible fix
                    //                    Vote::GetInstance().GetCommittee().NewIrreversibleBlock(cIrreversibleBlockInfo.heights[i]);
                    //                    Vote::GetInstance().GetBill().NewIrreversibleBlock(cIrreversibleBlockInfo.heights[i]);

                    for(auto k = 0; k < nMaxConfirmBlockCount; ++k) {
                        cIrreversibleBlockInfo.heights[k] = -1;
                    }
                    cIrreversibleBlockInfo.heights[0] = height;
                    cIrreversibleBlockInfo.hashs[0] = hash;
                    return;
                } else if((height - cIrreversibleBlockInfo.heights[i]) * 100 >= nMaxDelegateNumber * nSecondIrreversibleThreshold) {
                    if(i == nMaxConfirmBlockCount - 1) {
                        AddIrreversibleBlock(cIrreversibleBlockInfo.heights[i], cIrreversibleBlockInfo.hashs[i]);
                        LogPrintf("Second NewIrreversibleBlock height:%ld hash:%s\n", cIrreversibleBlockInfo.heights[i], cIrreversibleBlockInfo.hashs[i].ToString().c_str());

                        //TODO:vote irreversible fix
                        //                        Vote::GetInstance().GetCommittee().NewIrreversibleBlock(cIrreversibleBlockInfo.heights[i]);
                        //                        Vote::GetInstance().GetBill().NewIrreversibleBlock(cIrreversibleBlockInfo.heights[i]);

                        for(int j = 0; j < nMaxConfirmBlockCount -1; ++j) {
                            cIrreversibleBlockInfo.heights[j] = cIrreversibleBlockInfo.heights[j+1];
                            cIrreversibleBlockInfo.hashs[j] = cIrreversibleBlockInfo.hashs[j+1];
                        }

                        cIrreversibleBlockInfo.heights[nMaxConfirmBlockCount - 1] = height;
                        cIrreversibleBlockInfo.hashs[nMaxConfirmBlockCount - 1] = hash;
                        return;
                    } else {
                        cIrreversibleBlockInfo.heights[i+1] = height;
                        cIrreversibleBlockInfo.hashs[i+1] = hash;
                        return;
                    }
                } else {
                    for(auto k = 0; k < nMaxConfirmBlockCount; ++k) {
                        cIrreversibleBlockInfo.heights[k] = -1;
                    }
                    cIrreversibleBlockInfo.heights[0] = height;
                    cIrreversibleBlockInfo.hashs[0] = hash;
                    return;
                }
            } else {
                cIrreversibleBlockInfo.heights[i] = -1;
            }
        }
    }

    if(i < 0) {
        cIrreversibleBlockInfo.heights[0] = height;
        cIrreversibleBlockInfo.hashs[0] = hash;
        return;
    }
}

bool DPoS::IsValidBlockCheckIrreversibleBlock(int64_t height, uint256 hash)
{
    if(fUseIrreversibleBlock == false) {
        return true;
    }

    bool ret = true;
    read_lock l(lockIrreversibleBlockInfo);

    auto it = cIrreversibleBlockInfo.mapHeightHash.find(height);
    if(it != cIrreversibleBlockInfo.mapHeightHash.end()) {
        if(hash != it->second) {
            LogPrintf("CheckIrreversibleBlock[%ld:%s] invalid block[%ld:%s]\n", it->first, it->second.ToString().c_str(), height, hash.ToString().c_str());
            ret = false;
        }
    }

    return ret;
}

void DPoS::AddIrreversibleBlock(int64_t height, uint256 hash)
{
    while((int64_t)cIrreversibleBlockInfo.mapHeightHash.size() >= nMaxIrreversibleCount) {
        cIrreversibleBlockInfo.mapHeightHash.erase(cIrreversibleBlockInfo.mapHeightHash.begin());
    }

    cIrreversibleBlockInfo.mapHeightHash.insert(std::make_pair(height, hash));

    Vote::GetInstance().DeleteInvalidVote(height);
}
