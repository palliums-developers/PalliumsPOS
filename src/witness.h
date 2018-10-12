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

extern CCriticalSection cs_main;
/** Best header we've seen so far (used for getheaders queries' starting points). */
extern CBlockIndex *pindexBestHeader;

void MintStart(boost::thread_group& threadGroup);


class CWitnessProperty
{
public:
//    CCriticalSection cs_wPro;
    CWitnessProperty(){
        time = 1539140632;
        dynamicFlags=0;
        witnessBudget=0;
//        recentSlotsFilled=std::numeric_limits<uint128_t>::max();
    }

public:
    uint32_t HeadBlockNum(){
        return headBlockNumber;
    }

    void UpdateBestBlockHeader(CBlockIndex *pBlockHeader)
    {
        LOCK(cs_main);
        pindexBestHeader=pBlockHeader;
        headBlockNumber=pindexBestHeader->nHeight+1;
        time=pindexBestHeader->GetBlockTime();
    }

public:
    uint32_t          headBlockNumber = 0;
    /**
     * @brief time is headblocktime since epoch
     */
    uint64_t          time = 1539140632;
    uint160           currentWitness;
    uint64_t          nextMaintenanceTime;
    uint64_t          lastBudgetTime;
    uint64_t          witnessBudget;
    uint32_t          accountsRegisteredThisInterval = 0;
    /**
       *  Every time a block is missed this increases by
       *  RECENTLY_MISSED_COUNT_INCREMENT,
       *  every time a block is found it decreases by
       *  RECENTLY_MISSED_COUNT_DECREMENT.  It is
       *  never less than 0.
       *
       *  If the recentlyMissedCount hits 2*UNDO_HISTORY then no new blocks may be pushed.
       */
    uint32_t          recentlyMissedCount = 0;

    /**
       * The current absolute slot number.  Equal to the total
       * number of slots since genesis.  Also equal to the total
       * number of missed slots plus head_block_number.
       */
    uint64_t          currentAbsoluteSlot = 0;

    /**
       * used to compute witness participation.
       */
//    uint128_t          recentSlotsFilled;

    /**
       * dynamicFlags specifies chain state properties that can be
       * expressed in one bit.
       */
    uint32_t dynamicFlags = 0;

    uint32_t lastIrreversibleBlockNum = 0;

    enum DynamicFlagBits
    {
        /**
          * If maintenanceFlag is set, then the head block is a
          * maintenance block.  This means
          * GetTimeSlot(1) - HeadBlockTime() will have a gap
          * due to maintenance duration.
          */
        maintenanceFlag = 0x01
    };

    CBlockIndex *pindexBestHeader;
};

class CWitnessObject
{
   public:
      uint64_t         lastAbsoluteSlot = 0;
      uint160          witnessPubkey;
      uint64_t         totalMissed = 0;
      uint32_t         lastConfirmedBlockNum = 0;
};

class CWitnessScheduleObject
{
   public:
      std::vector<CWitnessObject> witnesses;
};

#endif // BITCOIN_WITNESS_H
