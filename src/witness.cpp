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
#define LOOP_ROUND 3

void DPoS::Init()
{
    nMaxMemory = gArgs.GetArg("-maxmemory", DEFAULT_MAX_MEMORY_SIZE);
    if(Params().NetworkIDString() == "main") {
        gDPoS.nDposStartTime = 0;
        nMaxDelegateNumber = MAX_DELEGATE_NUM;
        nBlockIntervalTime = BLOCK_INTERVAL_TIME;
        nLoopRound=LOOP_ROUND;
    } else {
        gDPoS.nDposStartTime = 0;
        nMaxDelegateNumber = MAX_DELEGATE_NUM;
        nBlockIntervalTime = BLOCK_INTERVAL_TIME;
        nLoopRound=LOOP_ROUND;
    }

    strIrreversibleBlockFileName = (GetDataDir() / "dpos" / "irreversible_block.dat").string();
    ReadIrreversibleBlockInfo(cIrreversibleBlockInfo);

    if(chainActive.Height() > 0) {
        SetStartTime(chainActive[1]->nTime);
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
    if(pBlockIndex->nHeight == 0) {
        SetStartTime(t);
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(t);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(t);
    uint64_t nPrevLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    uint32_t nPrevDelegateIndex = GetDelegateIndex(pBlockIndex->nTime);

    LogPrintf("IsMining: nCurrentLoopIndex %d, nCurrentDelegateIndex %d, nPrevLoopIndex %d, nPrevDelegateIndex %d\n",nCurrentLoopIndex, nCurrentDelegateIndex, nPrevLoopIndex, nPrevDelegateIndex);

    if(pBlockIndex->nHeight == 0){
        std::vector<unsigned char> veInit(64,0);
        cDelegateInfo = DPoS::GetNextDelegates(veInit);
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            LogPrintf("IsMining0: true\n");
            cCurrentDelegateInfo = cDelegateInfo;
            return true;
        } else {
            return false;
        }
    }
    if(nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound == 0) {
        std::vector<unsigned char> vecNewProof;
        std::vector<unsigned char> vecNewVrfValue;
        if(!CreateVrfProof(pBlockIndex,vsk,vecNewProof)){
            LogPrintf("IsMining1: CreateVrfProof false\n");
            return false;
        }
        if(!VerifyVrfProof(pBlockIndex, vecNewVrfValue, vpk, vecNewProof)){
            LogPrintf("IsMining1: VerifyVrfProof false\n");
            return false;
        }
        cDelegateInfo = DPoS::GetNextDelegates(vecNewVrfValue);
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            LogPrintf("IsMining1: true\n");
            cCurrentDelegateInfo = cDelegateInfo;
            return true;
        } else {
            LogPrintf("IsMining1: false,pk=%s\n", HexStr(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk));
            return false;
        }
    } else if((nCurrentLoopIndex == nPrevLoopIndex && nCurrentDelegateIndex > nPrevDelegateIndex) || (nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound != 0)) {
        if(nCurrentDelegateIndex + 1 > cCurrentDelegateInfo.delegates.size()) {
            LogPrintf("IsMining2: false\n");
            return false;
        } else if(cCurrentDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            LogPrintf("IsMining2: true\n");
            cDelegateInfo = cCurrentDelegateInfo;
            return true;
        } else {
            LogPrintf("IsMining2: false,pk=%s\n", HexStr(cCurrentDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk));
            return false;
        }
    } else {
        LogPrintf("IsMining3: false\n");
        return false;
    }
    LogPrintf("IsMining4: false\n");
    return false;
}

DelegateInfo DPoS::GetNextDelegates(std::vector<unsigned char> &vrfValue)
{
    DelegateInfo cDelegateInfo;

    cDelegateInfo.delegates = Selector::GetInstance().GetTopDelegateInfo(nMaxDelegateNumber,vrfValue);

    LogPrintf("DPoS: GetNextDelegates start\n");
    for(auto i : cDelegateInfo.delegates)
        LogPrintf("DPoS: delegate %s\n", HexStr(&(*i.vrfpk.begin()),&(*i.vrfpk.end())));
    LogPrintf("DPoS: GetNextDelegates end\n");

    cDelegateInfo.delegates.resize(nMaxDelegateNumber);

    return cDelegateInfo;
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

bool DPoS::CheckCoinbase(const CTransaction& tx, DelegateInfo& cDelegateInfo, VrfInfo& vrfInfo)
{
    if(!VRFScriptToDelegateInfo(&cDelegateInfo, &vrfInfo, tx.vout[1].scriptPubKey)){
        LogPrintf("CheckCoinbase txhash:%s failed!", tx.GetHash().ToString());
        return false;
    }
    return true;
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
    LOCK(cs_main);
    CBlockIndex* pBlockIndex = chainActive.Tip();
    std::vector<unsigned char> proof(80);
    if(!CreateVrfProof(pBlockIndex, vsk, proof))
        return CScript();

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
                        pDelegateInfo->delegates.push_back(Delegate(vct));
                        pData += 32;
                    }
                }
                return true;
            }
        }
    }
    return true;
}

std::vector<unsigned char> DPoS::GetVRFValue(VrfInfo &vrfInfo)
{
    std::vector<unsigned char> vecVrfValue;
    vecVrfValue.resize(64);
    crypto_vrf_proof_to_hash(&vecVrfValue[0], &vrfInfo.proof[0]);
    return vecVrfValue;
}


bool DPoS::CheckBlockDelegate(DelegateInfo& cDelegateInfo, VrfInfo& vrfInfo)
{
    bool ret = true;
    std::vector<unsigned char> vecVrfValue = GetVRFValue(vrfInfo);
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
            LogPrintf("CheckBlockDelegate NextBlockDelegate[%u]: %s\n", i, HexStr(cNextDelegateInfo.delegates[i].vrfpk));
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
    if(!ReadBlockFromDisk(block, &blockindex, Params().GetConsensus())) {
        return false;
    }

    //After the verification is passed, the block will be added to chainActive
    if(!CheckBlock(block, fIsCheckDelegateInfo)){
        LogPrintf("CheckBlock: false");
        return false;
    }
    lastBestblock = block;
    return true;
}

bool DPoS::CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo)
{
    auto t = time(nullptr) + BLOCK_INTERVAL_TIME;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - BLOCK_INTERVAL_TIME);
        return false;
    }

    if(block.hashPrevBlock.IsNull()) {
        lastBestblock = block;
        return true;
    }

    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("CheckBlock find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }

    CBlockIndex* pPrevBlockIndex = miSelf->second;

    int64_t nBlockHeight = pPrevBlockIndex->nHeight + 1;
    DelegateInfo cDelegateInfo;
    VrfInfo vrfInfo;
    if(CheckCoinbase(*block.vtx[0], cDelegateInfo, vrfInfo) == false) {
        LogPrintf("CheckBlock CheckCoinbase error\n");
        return false;
    }

    if(nBlockHeight == 1) {
        SetStartTime(block.nTime);
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(block.nTime);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(block.nTime);

    uint64_t nPrevLoopIndex = GetLoopIndex(pPrevBlockIndex->nTime);

    LogPrintf("CheckBlock: nCurrentLoopIndex %d, nCurrentDelegateIndex %d\n",nCurrentLoopIndex, nCurrentDelegateIndex);

    bool ret = false;
    if(nBlockHeight == 1) {
        std::vector<unsigned char> veInit(64,0);
        cDelegateInfo = DPoS::GetNextDelegates(veInit);
        cCurrentDelegateInfo = cDelegateInfo;
    }
    else if(nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound == 0) {
        if(fIsCheckDelegateInfo) {
            if(CheckBlockDelegate(cDelegateInfo,vrfInfo) == false) {
                return false;
            }
            cCurrentDelegateInfo = cDelegateInfo;
            ProcessIrreversibleBlock(nBlockHeight, block.GetHash());
        }
        else
            cCurrentDelegateInfo = cDelegateInfo;
    }

    if(nCurrentDelegateIndex < cDelegateInfo.delegates.size() && cDelegateInfo.delegates == cCurrentDelegateInfo.delegates
            && cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vrfInfo.pk) {
        LogPrintf("CheckBlock:true\n");
        ret = true;
    } else {
        LogPrintf("CheckBlock GetDelegateID blockhash:%s error\n", block.ToString().c_str());
    }
    if(ret == true)
        lastBestblock = block;
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
        if(DPoS::GetInstance().GetLastBestBlock().GetHash() == *pBlockIndex->phashBlock)
             block = DPoS::GetInstance().GetLastBestBlock();
        else if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())){
            return false;
        }
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
    return false;
}

bool DPoS::CreateVrfData(const CBlock& block, std::vector<unsigned char> &msg)
{
    if(block.hashPrevBlock.IsNull()) {
        uint256 hash = block.GetHash();
        msg.resize(hash.size());
        memcpy(&msg[0],hash.begin(),hash.size());
        return true;
    }
    int64_t time=block.GetBlockTime() + BLOCK_INTERVAL_TIME;//new block time
    msg.resize(sizeof(int64_t));
    memcpy(&msg[0],&time,sizeof(int64_t));
    VrfInfo vrfInfo;
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
    if(pBlockIndex){
        CBlock block;
        if(DPoS::GetInstance().GetLastBestBlock().GetHash() == *pBlockIndex->phashBlock)
            block = DPoS::GetInstance().GetLastBestBlock();
        else if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())){
            return false;
        }
        return CreateVrfProof(block, vsk, proof);
    }
    return false;
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
