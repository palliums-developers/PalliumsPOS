#include <witness.h>
#include <policy/policy.h>
#include <util.h>
#include <chainparams.h>
#include <script/script.h>
#include <vrf/crypto_vrf.h>
#include <validation.h>
#include <utilstrencodings.h>
#include <consensus/merkle.h>
#include "omnicore/nodetoken.h"

typedef boost::shared_lock<boost::shared_mutex> read_lock;
typedef boost::unique_lock<boost::shared_mutex> write_lock;
static std::shared_ptr<const CBlock> most_recent_block;

static DPoS gDPoS;
static DPoS *gpDPoS = nullptr;

DPoS::~DPoS()
{
    WriteIrreversibleBlockInfo(cIrreversibleBlockInfo);
}

void DPoS::Init()
{
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

static std::shared_ptr<const CBlock> GetBlock(CBlockIndex *pindex){
    if(!most_recent_block || pindex->GetBlockHash() != most_recent_block->GetHash()){
        std::shared_ptr<CBlock> block_ptr = std::make_shared<CBlock>();
        if(!ReadBlockFromDisk(*block_ptr, pindex, Params().GetConsensus())) {
            LogPrintf("Cannot load block %d from disk", pindex->nHeight);
            return nullptr;
        }
        return block_ptr;
    }
    return most_recent_block;
}

bool DPoS::IsMining(DelegateInfo& cDelegateInfo, std::vector<unsigned char>& proof, const std::vector<unsigned char> &vpk, const std::vector<unsigned char> &vsk, time_t t)
{
    LOCK(cs_main);
    CBlockIndex* pBlockIndex = chainActive.Tip();
    if(pBlockIndex->nHeight == 0) {
        SetStartTime(t);
    }

    uint64_t nCurrentLoopIndex = GetLoopIndex(t);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(t);
    uint64_t nPrevLoopIndex = GetLoopIndex(pBlockIndex->nTime);
    uint32_t nPrevDelegateIndex = GetDelegateIndex(pBlockIndex->nTime);

    LogPrintf("IsMining: nCurrentLoopIndex %d, nCurrentDelegateIndex %d, nPrevLoopIndex %d, nPrevDelegateIndex %d\n",nCurrentLoopIndex, nCurrentDelegateIndex, nPrevLoopIndex, nPrevDelegateIndex);

    std::shared_ptr<const CBlock> block = GetBlock(pBlockIndex);

    VrfInfo vLastVrfInfo;
    DelegateInfo cLastBlockDelegateInfo;
    if(pBlockIndex->nHeight > 0 && !VRFScriptToDelegateInfo(&cLastBlockDelegateInfo, &vLastVrfInfo, block->vtx[0]->vout[1].scriptPubKey)){
        LogPrintf("IsMining: Get last block delegateinfo error\n");
        return false;
    }

    if(!CreateVrfProof(pBlockIndex->nHeight,vLastVrfInfo.proof, vsk, proof)){
        return false;
    }

    if(pBlockIndex->nHeight == 0){
        std::vector<unsigned char> veInit(64,0);
        cDelegateInfo = DPoS::GetNextDelegates(veInit);
        if(cDelegateInfo.delegates.size() < nMaxDelegateNumber){
            LogPrintf("IsMining: false, delegates number less than the minimum\n");
            return false;
        }
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            cCurrentDelegateInfo = cDelegateInfo;
            return true;
        } else {
            return false;
        }
    }

    if(pBlockIndex->nHeight > 1 && nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound == 0) {
        std::vector<unsigned char> vrfValue = GetVRFValue(vLastVrfInfo.proof);
        cDelegateInfo = DPoS::GetNextDelegates(vrfValue);
        if(cDelegateInfo.delegates.size() < nMaxDelegateNumber){
            LogPrintf("IsMining: false, delegates number less than the minimum\n");
            return false;
        }
        cCurrentDelegateInfo = cDelegateInfo;
        if(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            return true;
        } else {
            LogPrintf("IsMining: false,pk=%s\n", HexStr(cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk));
            return false;
        }
    } else if((nCurrentLoopIndex == nPrevLoopIndex && nCurrentDelegateIndex > nPrevDelegateIndex) || (nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound != 0)) {       
        cCurrentDelegateInfo = cLastBlockDelegateInfo;
        if(nCurrentDelegateIndex + 1 > cCurrentDelegateInfo.delegates.size()) {
            LogPrintf("IsMining: false, current index value is out of range\n");
            return false;
        } else if(cCurrentDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == vpk) {
            cDelegateInfo = cCurrentDelegateInfo;
            return true;
        } else {
            LogPrintf("IsMining: false, no turn to current node\n");
            return false;
        }
    }
    LogPrintf("IsMining: false, unknown error\n");
    return false;
}

DelegateInfo DPoS::GetNextDelegates(std::vector<unsigned char> &vrfValue)
{
    DelegateInfo cDelegateInfo;

    cDelegateInfo.delegates = GetTopDelegateInfo(nMaxDelegateNumber,vrfValue);

    LogPrintf("DPoS: GetNextDelegates start\n");
    for(auto i : cDelegateInfo.delegates)
        LogPrintf("DPoS: delegate %s\n", HexStr(&(*i.vrfpk.begin()),&(*i.vrfpk.end())));
    LogPrintf("DPoS: GetNextDelegates end\n");

    return cDelegateInfo;
}

std::vector<Delegate> DPoS::GetTopDelegateInfo(uint32_t nDelegateNum, std::vector<unsigned char> vrfValue)
{
    std::vector<Delegate> result;
    if(vrfValue == std::vector<unsigned char>(64,0)){
        for(auto &s:vGenesisMembers){
            std::vector<unsigned char> pk(ParseHex(s));
            result.push_back(Delegate(pk));
            if(result.size() >= nDelegateNum) {
                break;
            }
        }
        return result;
    }
    std::vector<std::vector<unsigned char>> delegates;
    for(auto &s:vGenesisMembers){
        std::vector<unsigned char> pk(ParseHex(s));
        delegates.push_back(pk);
    }
    mastercore::CNodeToken nodeToken;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> mapVrfDid = nodeToken.GetRegisterNodeTokenerVrfPubkeyDisk();
    for(auto iter=mapVrfDid.begin(); iter!=mapVrfDid.end(); iter++)
        delegates.push_back(iter->first);

    sort(delegates.begin(), delegates.end(), [&](const std::vector<unsigned char> &pk1, const std::vector<unsigned char> &pk2)
    {
        std::vector<unsigned char> data1(vrfValue.begin(),vrfValue.end());
        data1.insert(data1.end(),pk1.begin(),pk1.end());
        std::vector<unsigned char> data2(vrfValue.begin(),vrfValue.end());
        data2.insert(data2.end(),pk2.begin(),pk2.end());
        if(Hash160(data1) < Hash160(data2))
            return true;
        if(Hash160(data1) == Hash160(data2))
            return true;
        return false;
    }
    );

    for(auto it = delegates.rbegin(); it != delegates.rend(); ++it)
    {
        if(result.size() >= nDelegateNum) {
            break;
        }
        //TODO:vote num auto detect
        result.push_back(Delegate(*it));
    }
    return result;
}

bool DPoS::IsDelegateRegiste(const std::vector<unsigned char>& vrfpubkey)
{
    std::vector<std::vector<unsigned char>> delegates;
    for(auto &s:vGenesisMembers){
        std::vector<unsigned char> pk(ParseHex(s));
        delegates.push_back(pk);
    }

    mastercore::CNodeToken nodeToken;
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> mapVrfDid = nodeToken.GetRegisterNodeTokenerVrfPubkeyDisk();
    for(auto iter=mapVrfDid.begin(); iter!=mapVrfDid.end(); iter++)
        delegates.push_back(iter->first);

    for(auto &d:delegates)
    {
        if(d==vrfpubkey)
            return true;
    }
    return false;
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


CScript DPoS::VRFDelegateInfoToScript(const DelegateInfo& cDelegateInfo, const std::vector<unsigned char>& proof, const std::vector<unsigned char>& vpk, const std::vector<unsigned char>& vsk)
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
        if(pDelegateInfo)
            pDelegateInfo->delegates.clear();
        if(GetScriptOp(it,script.end(), op, &data)) {
            if((data.size() - (1)) % (32) == 0) {
                unsigned char* pData = &data[1];
                uint32_t nDelegateNum = (data.size() - (1)) / (32);
                for(unsigned int i =0; i < nDelegateNum; ++i) {
                    std::vector<unsigned char> vct(pData, pData + 32);
                    if(pDelegateInfo)
                        pDelegateInfo->delegates.push_back(Delegate(vct));
                    pData += 32;
                }
            }
        }
        if(pVrfInfo){
            std::vector<unsigned char> sign;
            if(GetScriptOp(it,script.end(), op, &sign) == false) {
                return false;
            }
            pVrfInfo->sign = sign;
        }
    }
    return true;
}

std::vector<unsigned char> DPoS::GetVRFValue(std::vector<unsigned char> &proof)
{
    std::vector<unsigned char> vecVrfValue;
    vecVrfValue.resize(64);
    crypto_vrf_proof_to_hash(&vecVrfValue[0], &proof[0]);
    return vecVrfValue;
}


bool DPoS::CheckBlockDelegate(DelegateInfo& cDelegateInfo, std::vector<unsigned char> proof)
{
    bool ret = true;
    std::vector<unsigned char> preVrfValue = GetVRFValue(proof);
    LogPrintf("CheckBlockDelegate: preProof = %s, preVrfValue = %s\n",HexStr(proof) ,HexStr(preVrfValue));
    DelegateInfo cNextDelegateInfo = GetNextDelegates(preVrfValue);
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

bool DPoS::CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo)
{
    auto t = time(nullptr) + BLOCK_INTERVAL_TIME;
    if(block.nTime > t) {
        LogPrintf("Block:%u time:%s error\n", block.nTime, t - BLOCK_INTERVAL_TIME);
        return false;
    }

    if(block.hashPrevBlock.IsNull()) {
        most_recent_block = std::make_shared<const CBlock>(block);
        return true;
    }

    if(most_recent_block != nullptr && most_recent_block->GetHash() == block.GetHash())
        return true;

    BlockMap::iterator miSelf = mapBlockIndex.find(block.hashPrevBlock);
    if(miSelf == mapBlockIndex.end()) {
        LogPrintf("CheckBlock find blockindex(%s) error\n", block.hashPrevBlock.ToString().c_str());
        return false;
    }

    CBlockIndex* pPrevBlockIndex = miSelf->second;

    int64_t nBlockHeight = pPrevBlockIndex->nHeight + 1;
    DelegateInfo cDelegateInfo;

    if(nBlockHeight == 1) {
        SetStartTime(block.nTime);
        std::vector<unsigned char> veInit(64,0);
        cDelegateInfo = DPoS::GetNextDelegates(veInit);
        cCurrentDelegateInfo = cDelegateInfo;
    }
    VrfInfo curVrfInfo;
    if(!VRFScriptToDelegateInfo(&cDelegateInfo, &curVrfInfo, block.vtx[0]->vout[1].scriptPubKey)){
        LogPrintf("CheckBlock get curVrfInfo error\n");
        return false;
    }

    std::shared_ptr<const CBlock> lastblock=GetBlock(pPrevBlockIndex);
    if(!lastblock)
        return false;

    DelegateInfo cLastDelegateInfo;
    VrfInfo lastVrfInfo;
    if(nBlockHeight > 1 && !VRFScriptToDelegateInfo(&cLastDelegateInfo, &lastVrfInfo, lastblock->vtx[0]->vout[1].scriptPubKey)){
        LogPrintf("CheckBlock get cCurrentDelegateInfo error\n");
        return false;
    }

    if(!VerifyVrfProof(pPrevBlockIndex->nHeight, lastVrfInfo.proof, curVrfInfo.pk, curVrfInfo.proof))
        return false;
    if(!VerifyBlockSign(block, curVrfInfo.pk, curVrfInfo.sign))
        return false;
    uint64_t nCurrentLoopIndex = GetLoopIndex(block.nTime);
    uint32_t nCurrentDelegateIndex = GetDelegateIndex(block.nTime);

    uint64_t nPrevLoopIndex = GetLoopIndex(pPrevBlockIndex->nTime);

    LogPrintf("CheckBlock: nCurrentLoopIndex %d, nCurrentDelegateIndex %d\n",nCurrentLoopIndex, nCurrentDelegateIndex);

    if(nBlockHeight > 2 && nCurrentLoopIndex > nPrevLoopIndex && nCurrentLoopIndex % nLoopRound == 0) {
        if(fIsCheckDelegateInfo) {
            VrfInfo preVrfInfo;
            if(!VRFScriptToDelegateInfo(nullptr, &preVrfInfo, lastblock->vtx[0]->vout[1].scriptPubKey)){
                LogPrintf("CheckBlock get preVrfInfo error\n");
                return false;
            }
            LogPrintf("CheckBlock:  blockheight = %d, blockhash = %s\n", pPrevBlockIndex->nHeight, lastblock->GetHash().ToString());
            if(CheckBlockDelegate(cDelegateInfo, preVrfInfo.proof) == false) {
                return false;
            }
            ProcessIrreversibleBlock(nBlockHeight, block.GetHash());
        }
        cCurrentDelegateInfo = cDelegateInfo;
    }
    else if(cCurrentDelegateInfo.delegates.size() == 0 || cDelegateInfo.delegates != cCurrentDelegateInfo.delegates){
        if(nBlockHeight == 1)
            cCurrentDelegateInfo = cDelegateInfo;
        else
            cCurrentDelegateInfo = cLastDelegateInfo;
    }

    if(nCurrentDelegateIndex < cDelegateInfo.delegates.size() && cDelegateInfo.delegates == cCurrentDelegateInfo.delegates
            && cDelegateInfo.delegates[nCurrentDelegateIndex].vrfpk == curVrfInfo.pk) {
        LogPrintf("CheckBlock:true\n");
        most_recent_block = std::make_shared<const CBlock>(block);
        return true;
    } else {
        LogPrintf("CheckBlock GetDelegateID blockhash:%s error\n", block.ToString().c_str());
    }
    return false;
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


static bool fUseIrreversibleBlock = true;

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
}

bool DPoS::VerifyVrfProof(const uint64_t nHeight, const std::vector<unsigned char> &lastproof, const std::vector<unsigned char> &pk, const std::vector<unsigned char> &curproof)
{
    std::vector<unsigned char> msg;
    if(!CreateVrfData(nHeight, lastproof, msg)){
        LogPrintf("VerifyVrfProof: CreateVrfData() error\n");
        return false;
    }
    unsigned char output[64];
    if (crypto_vrf_verify(output, &pk[0], &curproof[0], &msg[0], msg.size()) != 0){
        LogPrintf("VerifyVrfProof: crypto_vrf_verify() error\n");
        return false;
    }
    return true;
}

bool DPoS::CreateVrfData(const uint64_t nHeight, const std::vector<unsigned char> proof, std::vector<unsigned char> &msg)
{
    if(nHeight == 0) {
        char* c_smsg= "palliums";
        msg.assign(c_smsg, c_smsg + strlen(c_smsg));
        return true;
    }

    int64_t height = nHeight + 1;//new block height
    msg.assign((unsigned char *)&height, (unsigned char *)&height + sizeof(height));

    unsigned char vrfvalue[64];
    crypto_vrf_proof_to_hash(vrfvalue, &proof[0]);
    msg.insert(msg.end(), vrfvalue, vrfvalue + sizeof(vrfvalue));
    return true;
}

bool DPoS::CreateVrfProof(const uint64_t nHeight, const std::vector<unsigned char> &lastproof, const std::vector<unsigned char>& vsk, std::vector<unsigned char>& proof)
{
    std::vector<unsigned char> msg;
    if(!CreateVrfData(nHeight,lastproof , msg)){
        LogPrintf("CreateVrfProof: CreateVrfData() error");
        return false;
    }

    proof.resize(80);
    if(crypto_vrf_prove(&proof[0], &vsk[0], &msg[0], msg.size()) != 0){
        LogPrintf("CreateVrfProof: crypto_vrf_prove() error");
        return false;
    }
    return true;
}

bool DPoS::CreateBlockSign(std::shared_ptr<CBlock> pblock, const std::vector<unsigned char>& vsk)
{
    uint256&& hash = pblock->GetHash();
    std::vector<unsigned char> proof(80, 0);
    if(crypto_vrf_prove(&proof[0], &vsk[0], (const unsigned char*) hash.begin(), hash.size()) != 0){
        LogPrintf("CreateBlockSign failed");
        return false;
    }

    CTransactionRef txCoinbase = pblock->vtx[0];
    CMutableTransaction tmpTxCoinbase(*txCoinbase);
    tmpTxCoinbase.vout[1].scriptPubKey << proof;
    pblock->vtx[0] = MakeTransactionRef(std::move(tmpTxCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    return true;
}

bool DPoS::VerifyBlockSign(const CBlock &block, const std::vector<unsigned char> &pk, std::vector<unsigned char> &sign)
{
    CBlock tmpblock = block;
    CTransactionRef txCoinbase = block.vtx[0];
    CMutableTransaction tmpTxCoinbase(*txCoinbase);
    tmpTxCoinbase.vout[1].scriptPubKey.resize(tmpTxCoinbase.vout[1].scriptPubKey.size() - 82);
    tmpblock.vtx[0] = MakeTransactionRef(std::move(tmpTxCoinbase));
    tmpblock.hashMerkleRoot = BlockMerkleRoot(tmpblock);
    uint256 hash = tmpblock.GetHash();
    std::vector<unsigned char> output(64,0);
    if (crypto_vrf_verify(&output[0], &pk[0], &sign[0], hash.begin(), hash.size()) != 0){
        LogPrintf("VerifyBlockSign failed\n");
        return false;
    }

    return true;
}
