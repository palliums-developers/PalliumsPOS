#include <util.h>
#include <witness.h>
#include <pubkey.h>
#include <key_io.h>
#include <base58.h>
#include <wallet/wallet.h>
#include <rpc/mining.h>


#define PRODUCE_NODE_COUNT 6

/**GRAPHENE_100_PERCENT percentage fields are fixed point with a denominator of 10,000 */
#define GRAPHENE_100_PERCENT                                  10000
#define GRAPHENE_1_PERCENT                                    (GRAPHENE_100_PERCENT/100)
#define GRAPHENE_RECENTLY_MISSED_COUNT_INCREMENT             4
#define GRAPHENE_RECENTLY_MISSED_COUNT_DECREMENT             3

uint32_t _required_witness_participation = 33 * GRAPHENE_1_PERCENT;

uint64_t block_interval=5;//5s
std::vector<uint160> witness_keys;
std::shared_ptr<CWitnessProperty> dynGlobalPropperty(new CWitnessProperty());

uint32_t maintenance_skip_slots=3;

void UpdateGlobalDynamicData( CBlockIndex *pblock_index, const uint32_t missed_blocks )
{
    auto& _dgp = *dynGlobalPropperty;

    // dynamic global properties updating
    uint32_t block_num=pblock_index->nHeight+1;
    if(block_num == 1)
        _dgp.recentlyMissedCount=0;
    else if(missed_blocks)
        _dgp.recentlyMissedCount=GRAPHENE_RECENTLY_MISSED_COUNT_INCREMENT*missed_blocks;
    else if( _dgp.recentlyMissedCount > GRAPHENE_RECENTLY_MISSED_COUNT_INCREMENT )
        _dgp.recentlyMissedCount -= GRAPHENE_RECENTLY_MISSED_COUNT_DECREMENT;
    else if( _dgp.recentlyMissedCount > 0 )
        _dgp.recentlyMissedCount--;

    _dgp.UpdateBestBlockHeader(pblock_index);
    //   _dgp.currentWitness = pblock_index->witness;
//    _dgp.recentSlotsFilled = ((_dgp.recentSlotsFilled << 1)+ 1) << missed_blocks;
    _dgp.currentAbsoluteSlot += missed_blocks+1;
}


uint160 GetScheduledWitness( uint32_t slot_num )
{
    uint64_t current_aslot = dynGlobalPropperty->currentAbsoluteSlot + slot_num;
    return witness_keys[ current_aslot % witness_keys.size()];
}


//second
uint64_t GetSlotTime(uint8_t slot_num)
{
    if( slot_num == 0 )
        return 0;
    auto interval = block_interval;
    CWitnessProperty& dpo =*dynGlobalPropperty;
    if( dpo.HeadBlockNum() == 0 )
    {
        // n.b. first block is at genesis_time plus one block interval
        uint64_t genesis_time=dpo.time;
        return genesis_time + slot_num * interval;
    }

    //time takes an integer
    uint64_t head_block_abs_slot = dpo.time / interval;
    uint64_t head_slot_time=head_block_abs_slot*interval;

    if( dpo.dynamicFlags & CWitnessProperty::maintenanceFlag )
        slot_num += maintenance_skip_slots;

    // "slot 0" is head_slot_time
    // "slot 1" is head_slot_time,
    //   plus maint interval if head block is a maint block
    //   plus block interval if head block is not a maint block
    return head_slot_time + (slot_num * interval);
}

uint8_t GetSlotAtTime(uint64_t when)
{
    uint64_t first_slot_time = GetSlotTime( 1 );
    if( when < first_slot_time )
        return 0;
    return (when - first_slot_time) / block_interval + 1;
}

uint32_t UpdateWitnessMissedBlocks( const CBlockIndex *pblock_index )
{
    uint32_t missed_blocks = GetSlotAtTime(pblock_index->GetBlockHeader().GetBlockTime());
    assert( missed_blocks != 0);
    missed_blocks--;
    if(missed_blocks<witness_keys.size())
    {
        //        for( uint32_t i = 0; i < missed_blocks; ++i ) {
        //           const auto& witness_missed = GetScheduledWitness( i+1 );
        //           modify( witness_missed, []( witness_object& w ) {
        //              w.total_missed++;
        //           });
        //        }
    }

    return 0;
}



void NewChainBanner()
{
    std::cerr << "\n"
                 "********************************\n"
                 "*                              *\n"
                 "*   ------- NEW CHAIN ------   *\n"
                 "*   -- Welcome to Sinnga! --   *\n"
                 "*   ------------------------   *\n"
                 "*                              *\n"
                 "********************************\n"
                 "\n";
    if( GetSlotAtTime(GetTime()) > 200 )
    {
        std::cerr << "Your genesis seems to have an old timestamp\n"
                     "Please consider using the --genesis-timestamp option to give your genesis a recent timestamp\n"
                     "\n"
                     ;
    }
}

enum BlockProductionConditionEnum
{
    Produced = 0,
    NotSynced = 1,
    NotMyTurn = 2,
    NotTimeYet = 3,
    NoPrivateKey = 4,
    LowParticipation = 5,
    Lag = 6,
    Consecutive = 7,
    ExceptionProducingBlock = 8
};


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

uint32_t WitnessParticipationRate()
{
    CWitnessProperty& dpo =*dynGlobalPropperty;
    return 100;
//    return uint64_t(GRAPHENE_100_PERCENT) * dpo.recentSlotsFilled.popcount() / 128;
}

//Determine whether the conditions for block production are met and produce blocks
BlockProductionConditionEnum MaybeProduceBlock(CWallet* const pwallet)
{
    int64_t now_fine = GetTimeMillis();
    int64_t now = (now_fine + 500000)/1000000ll;

    // If the next block production opportunity is in the present or future, we're synced.
    if(GetSlotTime(1) < now)
        return NotSynced;

    // is anyone scheduled to produce now or one second in the future?
    uint32_t slot = GetSlotAtTime(now);
    if( slot == 0 )
    {
        return NotTimeYet;
    }

    //
    // this assert should not fail, because now <= db.head_block_time()
    // should have resulted in slot == 0.
    //
    // if this assert triggers, there is a serious bug in get_slot_at_time()
    // which would result in allowing a later block to have a timestamp
    // less than or equal to the previous block
    //
    assert( now > dynGlobalPropperty->time );

    uint160 scheduled_witness = GetScheduledWitness( slot );
    // we must control the witness scheduled to produce the next block.
    if( scheduled_witness != local_address )
    {
        LogPrintf("not my turn to produce blcok\n", scheduled_witness);
        return NotMyTurn;
    }

    uint64_t scheduled_time=GetSlotTime(slot);

    uint32_t prate = WitnessParticipationRate();
    if( prate < _required_witness_participation )
    {
        LogPrintf("prate is %d,low participation\n", uint32_t(100*uint64_t(prate) / GRAPHENE_1_PERCENT));
        return LowParticipation;
    }
    /*seconds to microseconds*/
    if( std::llabs((scheduled_time - now)*1000) > 500 )
    {
        LogPrintf("scheduled_time is %d,now is %d,lag\n", scheduled_time,now);
        return Lag;
    }

    LogPrintf("Info:Generate block,time pass:%d\n",now);
    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbase_script) {
        LogPrintf("Error: Keypool ran out, please call keypoolrefill first\n");
        return NoPrivateKey;
    }

    //throw an error if no script was provided
    if (coinbase_script->reserveScript.empty()) {
        LogPrintf("No coinbase script available\n");
        return ExceptionProducingBlock;
    }

    generateBlocks(coinbase_script, 1, 100000, true);
    return Produced;
}


BlockProductionConditionEnum BlockProductionLoop(CWallet* const pwallet)
{
    BlockProductionConditionEnum result;

    try
    {
        result = MaybeProduceBlock(pwallet);
    }
    catch( std::exception &e )
    {
        //We're trying to exit. Go ahead and let this one out.
        LogPrintf("Got exception while generating block:%s",e.what());
        throw;
    }
    catch(...)
    {
        throw;
    }

    switch( result )
    {
    case Produced:
        LogPrintf("Generated block #%d with timestamp %d",pindexBestHeader->nHeight,GetTime());
        break;
    case NotSynced:
        LogPrintf("Not producing block because production is disabled until we receive a recent block");
        break;
    case NotMyTurn:
        break;
    case NotTimeYet:
        break;
    case NoPrivateKey:
        LogPrintf("Not producing block because don't have the private key");
        break;
    case LowParticipation:
        LogPrintf("Not producing block because node appears to be on a minority fork");
        break;
    case Lag:
        LogPrintf("Not producing block because node didn't wake up within 500ms of the slot time.");
        break;
    case Consecutive:
        LogPrintf("Not producing block because the last block was generated by the same witness.\nThis node is probably disconnected from the network so block production has been disabled");
        break;
    case ExceptionProducingBlock:
        LogPrintf( "exception producing block" );
        break;
    }
    return result;
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
        LOCK(cs_main);
        if(pindexBestHeader==nullptr||pindexBestHeader->nHeight==0){
            NewChainBanner();
        }
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

        BlockProductionLoop(pwallet);
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
