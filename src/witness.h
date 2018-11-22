#ifndef BITCOIN_WITNESS_H
#define BITCOIN_WITNESS_H

#include <string>
#include <vector>
#include <functional>
#include <fs.h>
#include <boost/thread.hpp>
#include <uint256.h>
#include <sync.h>
#include <chain.h>
#include <key_io.h>
#include <rpc/server.h>
#include <selector.h>

extern bool fUseIrreversibleBlock;

struct Delegate{
    std::vector<unsigned char> vrfpk;
    uint64_t votes;
    Delegate(){votes = 0;}
    Delegate(std::vector<unsigned char> &vrfpk, uint64_t votes) {this->vrfpk = vrfpk; this->votes = votes;}
};

struct VrfInfo{
    std::vector<unsigned char> pk;
    std::vector<unsigned char> proof;
    Delegate(std::vector<unsigned char> &pk, std::vector<unsigned char> &proof) {this->pk=pk; this->proof=proof;}
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


class DPoS{
public:
    DPoS() { nDposStartTime = 0;}
    ~DPoS();
    static DPoS& GetInstance();
    void Init();

    bool IsMining(DelegateInfo& cDelegateInfo, const std::vector<unsigned char> vrfpk, time_t t);

    DelegateInfo GetNextDelegates(std::vector<unsigned char> vrfValue);
    bool GetBlockDelegates(DelegateInfo& cDelegateInfo, CBlockIndex* pBlockIndex);
    bool GetBlockDelegates(DelegateInfo& cDelegateInfo, const CBlock& block);
    bool CheckBlockDelegate(const CBlock& block);
    bool CheckBlockHeader(const CBlockHeader& block);
    bool CheckBlock(const CBlockIndex& blockindex, bool fIsCheckDelegateInfo);
    bool CheckCoinbase(const CTransaction& tx, const CBlock& block);

    uint64_t GetLoopIndex(uint64_t time);
    uint32_t GetDelegateIndex(uint64_t time);

    static bool DataToDelegate(DelegateInfo& cDelegateInfo, const std::string& data);
    static std::string DelegateToData(const DelegateInfo& cDelegateInfo);

//    static bool ScriptToDelegateInfo(DelegateInfo& cDelegateInfo, uint64_t t, const CScript& script, const CTxDestination* paddress, bool fCheck);
    static bool VRFScriptToDelegateInfo(DelegateInfo& cDelegateInfo, const CScript& script);
//    static CScript DelegateInfoToScript(const DelegateInfo& cDelegateInfo, const CKey& delegatekey, uint64_t t);
    static CScript VRFDelegateInfoToScript(const DelegateInfo& cDelegateInfo, const std::vector<unsigned char>& vrf_pk, const std::vector<unsigned char>& vrf_sk);

    static bool GetBlockForgerPK(std::vector<unsigned char>& pk, const CBlock& block);
    static bool GetBlockDelegate(DelegateInfo& cDelegateInfo, const CBlock& block);

    int32_t GetStartDPoSHeight() {return nDposStartHeight;}
    std::string GetSuperForgerPK() {return cSuperForgerPK;}

    uint64_t GetStartTime() {return nDposStartTime;}
    void SetStartTime(uint64_t t) {nDposStartTime = t;}

    int GetMaxMemory() {return nMaxMemory;}

    IrreversibleBlockInfo GetIrreversibleBlockInfo();
    void SetIrreversibleBlockInfo(const IrreversibleBlockInfo& info);
    bool ReadIrreversibleBlockInfo(IrreversibleBlockInfo& info);
    bool WriteIrreversibleBlockInfo(const IrreversibleBlockInfo& info);
    void ProcessIrreversibleBlock(int64_t height, uint256 hash);
    bool IsValidBlockCheckIrreversibleBlock(int64_t height, uint256 hash);
    void AddIrreversibleBlock(int64_t height, uint256 hash);

    static bool VrfVerify(std::vector<unsigned char> output,std::vector<unsigned char> pk,std::vector<unsigned char> proof,std::vector<unsigned char> msg);
    static void MakeVrfMessage(const CBlock& block,std::vector<unsigned char>& msg);

    const int nFirstIrreversibleThreshold = 90;
    const int nSecondIrreversibleThreshold = 67;
    const int nMaxIrreversibleCount = 1000;

private:
    bool CheckBlock(const CBlock& block, bool fIsCheckDelegateInfo);
    std::vector<Delegate> SortDelegate(const std::vector<Delegate>& delegates, uint64_t t);

    bool IsOnTheSameChain(const std::pair<int64_t, uint256>& first, const std::pair<int64_t, uint256>& second);

private:
    int nMaxMemory;                    //GB
    int nMaxDelegateNumber;
    int nBlockIntervalTime;            //seconds
    int nDposStartHeight;
    uint64_t nDposStartTime;
    std::string cSuperForgerPK;
    std::string strIrreversibleBlockFileName;
    IrreversibleBlockInfo cIrreversibleBlockInfo;
    boost::shared_mutex lockIrreversibleBlockInfo;
};

#endif // BITCOIN_WITNESS_H
