#include "validation.h"
#include <witness.h>
#include <base58.h>
#include <rpc/mining.h>
#include <policy/policy.h>
#include <util.h>
#include <script/script.h>
#include <wallet/wallet.h>
#include <vrf/crypto_vrf.h>

bool fUseIrreversibleBlock = true;

typedef boost::shared_lock<boost::shared_mutex> read_lock;
typedef boost::unique_lock<boost::shared_mutex> write_lock;


static DPoS gDPoS;
static DPoS *gpDPoS = nullptr;

DPoS::~DPoS()
{
    WriteIrreversibleBlockInfo(cIrreversibleBlockInfo);
}

#define BLOCK_INTERVAL_TIME 5
#define MAX_DELEGATE_NUM 3

void DPoS::Init()
{
    nMaxMemory = gArgs.GetArg("-maxmemory", DEFAULT_MAX_MEMORY_SIZE);
    if(Params().NetworkIDString() == "main") {
        cSuperForgerPK = "62e70cb804cc9ca9283eb7e282a1ec4ecb6b5fa2dbcc5026d177a8939c9a101c";
        gDPoS.nDposStartTime = 0;

        nMaxDelegateNumber = MAX_DELEGATE_NUM;
        nBlockIntervalTime = BLOCK_INTERVAL_TIME;
        nDposStartHeight = 10;
    } else {
        cSuperForgerPK = "62e70cb804cc9ca9283eb7e282a1ec4ecb6b5fa2dbcc5026d177a8939c9a101c";
        gDPoS.nDposStartTime = 0;

        nMaxDelegateNumber = MAX_DELEGATE_NUM;
        nBlockIntervalTime = BLOCK_INTERVAL_TIME;
        nDposStartHeight = 10;
    }

    strIrreversibleBlockFileName = (GetDataDir() / "dpos" / "irreversible_block.dat").string();
    ReadIrreversibleBlockInfo(cIrreversibleBlockInfo);

    if(chainActive.Height() >= nDposStartHeight) {
        SetStartTime(chainActive[nDposStartHeight]->nTime);
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

bool DPoS::IsMining(DelegateInfo& cDelegateInfo, const std::vector<unsigned char> &vpk, const std::vector<unsigned char> &vsk, time_t t)
{
    CBlockIndex* pBlockIndex = chainActive.Tip();
    if(pBlockIndex->nHeight < nDposStartHeight - 1) {
        std::vector<unsigned char> pk = ParseHex(cSuperForgerPK);
        if(pk == vpk) {
            static time_t tLast = 0;
            if(t < tLast + nBlockIntervalTime) {
                return false;
            } else {
                tLast = t;
            }
        } else {
            return false;
        }
        if(pBlockIndex->nHeight == nDposStartHeight - 2){
            std::vector<unsigned char> veInit(64,0);
            cDelegateInfo = DPoS::GetNextDelegates(veInit);
        }
        LogPrintf("IsMining:super miner");
        return true;
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(t);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(t);
    uint64_t nPrevLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    uint32_t nPrevDelegateIndex = GetDelegateIndex(pBlockIndex->nTime);

    if(nCurrentLoopIndex > nPrevLoopIndex) {
        std::vector<unsigned char> vecNewProof;
        std::vector<unsigned char> vecNewVrfValue;// = GetBlockVRF(pBlockIndex);
        if(!CreateVrfProof(pBlockIndex,vsk,vecNewProof))
            return false;
        if(!VerifyVrfProof(pBlockIndex, vecNewVrfValue, vpk, vecNewProof))
            return false;
        cDelegateInfo = DPoS::GetNextDelegates(vecNewVrfValue);
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            LogPrintf("IsMining: true, nCurrentLoopIndex %d, nPrevLoopIndex %d, nCurrentDelegateIndex %d ,nPrevDelegateIndex %d",nCurrentLoopIndex, nPrevLoopIndex,nCurrentDelegateIndex,nPrevDelegateIndex);
            return true;
        } else {
            return false;
        }
    } else if(nCurrentLoopIndex == nPrevLoopIndex && nCurrentDelegateIndex > nPrevDelegateIndex) {
        DelegateInfo cCurrentDelegateInfo;
        if(GetBlockDelegates(cCurrentDelegateInfo, pBlockIndex)) {
            if(nCurrentDelegateIndex + 1 > cCurrentDelegateInfo.delegates.size()) {
                return false;
            } else if(cCurrentDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
                LogPrintf("IsMining: true, nCurrentLoopIndex %d, nPrevLoopIndex %d, nCurrentDelegateIndex %d ,nPrevDelegateIndex %d",nCurrentLoopIndex, nPrevLoopIndex,nCurrentDelegateIndex,nPrevDelegateIndex);
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

DelegateInfo DPoS::GetNextDelegates(std::vector<unsigned char> &vrfValue)
{
    uint64_t nMinHoldBalance = 500000000000;

    std::vector<Delegate> delegates = Selector::GetInstance().GetTopDelegateInfo(nMinHoldBalance, nMaxDelegateNumber,vrfValue);

    LogPrintf("DPoS: GetNextDelegates start\n");
    for(auto i : delegates)
        LogPrintf("DPoS: delegate %s %lu\n", HexStr(&(*i.vrfpk.begin()),&(*i.vrfpk.end())), i.votes);
    LogPrintf("DPoS: GetNextDelegates end\n");

    Delegate delegate;
    delegate.vrfpk = ParseHex(cSuperForgerPK);
    delegate.votes = 7;
    delegates.insert(delegates.begin(), delegate);

    delegates.resize(nMaxDelegateNumber);

    DelegateInfo cDelegateInfo;
    cDelegateInfo.delegates = delegates;
    return cDelegateInfo;
}

bool DPoS::GetBlockDelegates(DelegateInfo& cDelegateInfo, CBlockIndex* pBlockIndex)
{
    bool ret = false;
    uint64_t nLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    while(pBlockIndex) {
        if(pBlockIndex->nHeight==1 || pBlockIndex->nHeight == nDposStartHeight || GetLoopIndex(pBlockIndex->pprev->nTime) < nLoopIndex) {
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

bool DPoS::CheckCoinbase(const CTransaction& tx, const CBlock& block)
{
    bool ret = false;
    if(tx.vout.size() == 3) {
        ret = VRFScriptToDelegateInfo(nullptr, nullptr, tx.vout[1].scriptPubKey);
    }

    if(ret == false) {
        LogPrintf("CheckCoinbase txhash:%s failed!", tx.GetHash().ToString());
    }
    return ret;
}



CScript DPoS::VRFDelegateInfoToScript(const DelegateInfo& cDelegateInfo, const std::vector<unsigned char>& vpk, const std::vector<unsigned char>& vsk)
{
    const std::vector<Delegate>& delegates = cDelegateInfo.delegates;

    int nDataLen = 1 + delegates.size() * 32;
    std::vector<unsigned char> data;

    if(cDelegateInfo.delegates.empty() == false) {
        data.resize(nDataLen);
        data[0] = 0x7;

        unsigned char* pData = &data[1];
        for(unsigned int i =0; i < delegates.size(); ++i) {
            memcpy(pData, &delegates[i].vrfpk[0], 32);
            pData += 32;
        }
    }
    std::vector<unsigned char> vrf_value;
    LOCK(cs_main);
    CBlockIndex* pBlockIndex = chainActive.Tip();
    std::vector<unsigned char> proof(80);
    if(chainActive.Height() >= gDPoS.GetStartDPoSHeight()){
        if(!CreateVrfProof(pBlockIndex, vsk, proof))
            return CScript();
    }

    CScript script;
    if(cDelegateInfo.delegates.empty() == false) {
        script << OP_RETURN << vpk << proof << data;
    } else {
        script << OP_RETURN << vpk << proof;
    }
    return script;
}


bool DPoS::VRFScriptToDelegateInfo(DelegateInfo* pDelegateInfo, VrfInfo* pVrfInfo, const CScript& script)
{
    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator it = script.begin();
    script.GetOp(it, op);
    if(op == OP_RETURN) {
        std::vector<unsigned char> pk;
        if(GetScriptOp(it,script.end(), op, &pk) == false) {
            return false;
        }

        std::vector<unsigned char> proof;

        if(GetScriptOp(it,script.end(), op, &proof) == false) {
            return false;
        }
        if(pVrfInfo){
            pVrfInfo->pk=pk;
            pVrfInfo->proof=proof;
        }

        if(GetScriptOp(it,script.end(), op, &data)) {
            if((data.size() - (1)) % (32) == 0) {
                if(pDelegateInfo){
                    unsigned char* pData = &data[1];
                    uint32_t nDelegateNum = (data.size() - (1)) / (32);
                    for(unsigned int i =0; i < nDelegateNum; ++i) {
                        std::vector<unsigned char> vct(pData, pData + 32);
                        pDelegateInfo->delegates.push_back(Delegate(vct, 0));
                        pData += 32;
                    }
                }
                return true;
            }
        }
    }
    return true;
}

bool DPoS::GetBlockForgerPK(std::vector<unsigned char>& pk, const CBlock& block)
{
    auto& tx = block.vtx[0];
    if(tx->IsCoinBase() && tx->vout.size() == 3) {
        DelegateInfo cDelegateInfo;
        VrfInfo vrfInfo;
        if(VRFScriptToDelegateInfo(nullptr, &vrfInfo, tx->vout[1].scriptPubKey)){
            pk=vrfInfo.pk;
            return true;
        }
    }
    return false;
}

std::vector<unsigned char> DPoS::GetBlockVRF(const CBlock& block)
{
    std::vector<unsigned char> vecVrfValue;

    auto tx = block.vtx[0];
    if(tx->IsCoinBase() && tx->vout.size() == 3) {
        auto script = tx->vout[1].scriptPubKey;
        VrfInfo vrfInfo;
        if(VRFScriptToDelegateInfo(nullptr, &vrfInfo, script)){
            vecVrfValue.resize(64);
            crypto_vrf_proof_to_hash(&vecVrfValue[0], &vrfInfo.proof[0]);
        }
    }
    return vecVrfValue;
}

std::vector<unsigned char> DPoS::GetBlockVRF(CBlockIndex* pBlockIndex)
{
    uint64_t nLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    std::vector<unsigned char> vecVrfValue;
    while(pBlockIndex) {
        if((pBlockIndex->nHeight==1 || pBlockIndex->nHeight == nDposStartHeight || GetLoopIndex(pBlockIndex->pprev->nTime) < nLoopIndex)) {
            CBlock block;
            if(ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) {
                vecVrfValue = GetBlockVRF(block);
            }
            break;
        }
        pBlockIndex = pBlockIndex->pprev;
    }
    return vecVrfValue;
}

bool DPoS::GetBlockDelegate(DelegateInfo& cDelegateInfo, const CBlock& block)
{
    bool ret = false;

    auto tx = block.vtx[0];
    if(tx->IsCoinBase() && tx->vout.size() == 3) {
        auto script = tx->vout[1].scriptPubKey;
        ret = VRFScriptToDelegateInfo(&cDelegateInfo, nullptr, script);
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
    std::vector<unsigned char> vecVrfValue = GetBlockVRF(block);
    DelegateInfo cNextDelegateInfo = GetNextDelegates(vecVrfValue);
    if(cDelegateInfo.delegates.size() == cNextDelegateInfo.delegates.size()) {
        for(unsigned int i =0; i < cDelegateInfo.delegates.size(); ++i) {
            if(cDelegateInfo.delegates[i].vrfpk != cNextDelegateInfo.delegates[i].vrfpk) {
                ret = false;
                break;
            }
        }
    }

    if(ret == false) {
        for(unsigned int i =0; i < cDelegateInfo.delegates.size(); ++i) {
            LogPrintf("CheckBlockDelegate BlockDelegate[%u]: %s\n", i, HexStr(cDelegateInfo.delegates[i].vrfpk));
        }

        for(unsigned int i =0; i < cNextDelegateInfo.delegates.size(); ++i) {
            LogPrintf("CheckBlockDelegate NextBlockDelegate[%u]: %s %llu\n", i, HexStr(cNextDelegateInfo.delegates[i].vrfpk), cNextDelegateInfo.delegates[i].votes);
        }
    }

    return ret;
}

bool DPoS::CheckBlockHeader(const CBlockHeader& block)
{
    auto t = time(nullptr) + BLOCK_INTERVAL_TIME;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - BLOCK_INTERVAL_TIME);
        return false;
    }

    if(block.hashPrevBlock.IsNull()) {
        return true;
    }

    return true;
}

bool DPoS::CheckBlock(const CBlockIndex& blockindex, bool fIsCheckDelegateInfo)
{
    CBlock block;
    if(ReadBlockFromDisk(block, &blockindex, Params().GetConsensus()) == false) {
        return false;
    }

    //After the verification is passed, the block will be added to chainActive
    if(!CheckBlock(block, fIsCheckDelegateInfo)){
        LogPrintf("CheckBlock: false");
        return false;
    }
    if(nDposStartTime == 0 && chainActive.Height() >= nDposStartHeight - 1) {
        SetStartTime(chainActive[nDposStartHeight-1]->nTime + BLOCK_INTERVAL_TIME);
    }
    return true;
}

bool DPoS::CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo)
{
    auto t = time(nullptr) + BLOCK_INTERVAL_TIME;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - BLOCK_INTERVAL_TIME);
        return false;
    }

//    if(block.hashPrevBlock.IsNull()) {
//        return true;
//    }

    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("CheckBlock find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }

    CBlockIndex* pPrevBlockIndex = miSelf->second;

    int64_t nBlockHeight = pPrevBlockIndex->nHeight + 1;

    if(CheckCoinbase(*block.vtx[0], block) == false) {
        LogPrintf("CheckBlock CheckCoinbase error\n");
        return false;
    }

    if(nDposStartTime == 0 && chainActive.Height() >= nDposStartHeight-1) {
        SetStartTime(chainActive[nDposStartHeight-1]->nTime + BLOCK_INTERVAL_TIME);
    }

    if(nBlockHeight < nDposStartHeight) {
        std::vector<unsigned char> pk,superForgerPK;
        superForgerPK=ParseHex(cSuperForgerPK);
        if(GetBlockForgerPK(pk,block) && pk == superForgerPK) {
            return true;
        } else {
            LogPrintf("CheckBlock nBlockHeight < nDposStartHeight ForgerPK error\n");
            return false;
        }
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(block.nTime);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(block.nTime);
    uint64_t nPrevLoopIndex = 0;
    uint32_t nPrevDelegateIndex = 0;

    nPrevLoopIndex = GetLoopIndex(pPrevBlockIndex->nTime);
    nPrevDelegateIndex = GetDelegateIndex(pPrevBlockIndex->nTime);

    LogPrintf("CheckBlock: true, nCurrentLoopIndex %d, nPrevLoopIndex %d, nCurrentDelegateIndex %d ,nPrevDelegateIndex %d",nCurrentLoopIndex, nPrevLoopIndex,nCurrentDelegateIndex,nPrevDelegateIndex);

    bool ret = false;
    DelegateInfo cDelegateInfo;

    if(nBlockHeight == nDposStartHeight) {
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

    std::vector<unsigned char> delegate_pk;
    GetBlockForgerPK(delegate_pk, block);
    if(nCurrentDelegateIndex < cDelegateInfo.delegates.size()
            && cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == delegate_pk) {
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

    Selector::GetInstance().DeleteInvalidVote(height);
}

bool DPoS::VerifyVrfProof(CBlockIndex* pBlockIndex, std::vector<unsigned char> &output, const std::vector<unsigned char> &pk, std::vector<unsigned char> &proof)
{
    if(pBlockIndex){
        CBlock block;
        if (ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())){
             std::vector<unsigned char> msg;
            if(!CreateVrfData(block, msg)){
                LogPrintf("VerifyVrfProof: CreateVrfData() error");
                return false;
            }
            output.resize(64);
            if (crypto_vrf_verify(&output[0], &pk[0], &proof[0], &msg[0], msg.size()) != 0){
                LogPrintf("VerifyVrfProof: crypto_vrf_verify() error");
                return false;
            }
            return true;
        }
    }
    return false;
}


bool DPoS::CreateVrfData(const CBlock& block, std::vector<unsigned char> &msg)
{
    int64_t time=block.GetBlockTime() + BLOCK_INTERVAL_TIME;//new block time
    msg.resize(sizeof(int64_t));
    memcpy(&msg[0],&time,sizeof(int64_t));
    VrfInfo vrfInfo;
    DelegateInfo cDelegateInfo;
    if(!VRFScriptToDelegateInfo(nullptr, &vrfInfo, block.vtx[0]->vout[1].scriptPubKey))
        return false;
    uint256 hash = block.GetHash();
    int size=msg.size();
    msg.resize(size+hash.size()+vrfInfo.proof.size());
    memcpy(&msg[size],hash.begin(),hash.size());

    unsigned char vrfvalue[64];
    crypto_vrf_proof_to_hash(vrfvalue, &vrfInfo.proof[0]);
    memcpy(&msg[size+hash.size()],vrfvalue,sizeof (vrfvalue));
    return true;
}

bool DPoS::CreateVrfProof(CBlockIndex* pBlockIndex, const std::vector<unsigned char>& vsk, std::vector<unsigned char>& proof)
{
    std::vector<unsigned char> msg;
    if(pBlockIndex){
        CBlock block;
        if (ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus()))
            return CreateVrfProof(block, vsk, proof);
    }
}

bool DPoS::CreateVrfProof(const CBlock &block, const std::vector<unsigned char>& vsk, std::vector<unsigned char>& proof)
{
    std::vector<unsigned char> msg;
    if(!CreateVrfData(block, msg)){
        LogPrintf("CreateVrfProof: CreateVrfData() error");
        return false;
    }

    proof.resize(80);
    if(crypto_vrf_prove(&proof[0], &vsk[0], (const unsigned char*) &msg[0], msg.size()) != 0){
        LogPrintf("CreateVrfProof: crypto_vrf_prove() error");
        return false;
    }

    return true;
}
