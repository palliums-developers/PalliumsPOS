#ifndef BITCOIN_WITNESS_H
#define BITCOIN_WITNESS_H

#include <string>
#include <vector>
#include <map>
#include <boost/thread.hpp>
#include <uint256.h>

#define BLOCK_INTERVAL_TIME 3
#define MAX_DELEGATE_NUM 21
#define LOOP_ROUND 3

class CBlock;
class CScript;
class CBlockHeader;

struct Delegate{
    std::vector<unsigned char> vrfpk;
    Delegate(){}
    Delegate(std::vector<unsigned char> &vrfpk) {
        this->vrfpk = vrfpk;
    }
    bool operator==(const Delegate& delegate)const{
        return this->vrfpk == delegate.vrfpk;
    }
};

struct VrfInfo{
    std::vector<unsigned char> pk;
    std::vector<unsigned char> proof;
};

struct DelegateInfo{
    std::vector<Delegate> delegates;
};

const int nMaxConfirmBlockCount = 2;
struct IrreversibleBlockInfo{
    int64_t heights[nMaxConfirmBlockCount];
    uint256 hashs[nMaxConfirmBlockCount];
    std::map<int64_t, uint256> mapHeightHash;

    IrreversibleBlockInfo()
    {
        for(auto i = 0; i < nMaxConfirmBlockCount; ++i) {
            heights[i] = -1;
        }
    }
};

static std::shared_ptr<const CBlock> most_recent_block;

class DPoS{
public:
    DPoS() { nDposStartTime = 0;}
    ~DPoS();
    static DPoS& GetInstance();
    void Init();

    bool IsMining(DelegateInfo& cDelegateInfo, std::vector<unsigned char>& proof, const std::vector<unsigned char> &vpk, const std::vector<unsigned char> &vsk, time_t t);

    DelegateInfo GetNextDelegates(std::vector<unsigned char> &vrfValue);
    bool CheckBlockDelegate(DelegateInfo& cDelegateInfo, std::vector<unsigned char> proof);
    std::vector<unsigned char> GetVRFValue(std::vector<unsigned char> &proof);
    bool CheckBlockHeader(const CBlockHeader& block);
    bool CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo);

    uint64_t GetLoopIndex(uint64_t time);
    uint32_t GetDelegateIndex(uint64_t time);

    static bool VRFScriptToDelegateInfo(DelegateInfo* pDelegateInfo, VrfInfo* pVrfInfo, const CScript& script);
    static CScript VRFDelegateInfoToScript(const DelegateInfo& cDelegateInfo, const std::vector<unsigned char>& proof, const std::vector<unsigned char>& vrf_pk, const std::vector<unsigned char>& vrf_sk);

    uint64_t GetStartTime() {return nDposStartTime;}
    void SetStartTime(uint64_t t) {nDposStartTime = t;}

    std::vector<Delegate> GetTopDelegateInfo(uint32_t nDelegateNum, std::vector<unsigned char> vrfValue);
    bool  IsDelegateRegiste(const std::vector<unsigned char>& vrfpubkey);

    bool ReadIrreversibleBlockInfo(IrreversibleBlockInfo& info);
    bool WriteIrreversibleBlockInfo(const IrreversibleBlockInfo& info);
    void ProcessIrreversibleBlock(int64_t height, uint256 hash);
    bool IsValidBlockCheckIrreversibleBlock(int64_t height, uint256 hash);
    void AddIrreversibleBlock(int64_t height, uint256 hash);

    static bool VerifyVrfProof(const CBlock &block, const std::vector<unsigned char> &pk, std::vector<unsigned char> &proof);
    static bool CreateVrfProof(const CBlock &block, const std::vector<unsigned char>& vsk, std::vector<unsigned char>& proof);
    static bool CreateVrfData(const CBlock& block, std::vector<unsigned char>& msg);



    const int nFirstIrreversibleThreshold = 90;
    const int nSecondIrreversibleThreshold = 67;
    const int nMaxIrreversibleCount = 1000;
private:
    bool IsOnTheSameChain(const std::pair<int64_t, uint256>& first, const std::pair<int64_t, uint256>& second);

private:
    int nMaxDelegateNumber;
    int nBlockIntervalTime;            //seconds
    int nLoopRound;
    uint64_t nDposStartTime;
    std::string strIrreversibleBlockFileName;
    IrreversibleBlockInfo cIrreversibleBlockInfo;
    boost::shared_mutex lockIrreversibleBlockInfo;
    DelegateInfo cCurrentDelegateInfo;
    uint64_t nLastDelegateUpdateLoopIndex;
};

#endif // BITCOIN_WITNESS_H
