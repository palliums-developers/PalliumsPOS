#ifndef BITCOIN_SELECTOR_H
#define BITCOIN_SELECTOR_H

#include <boost/thread.hpp>
#include<pubkey.h>

class Delegate;

class Selector{
public:
    static Selector& GetInstance();
    std::vector<Delegate> GetTopDelegateInfo(uint64_t nMinHoldBalance, uint32_t nDelegateNum);
    void DeleteInvalidVote(uint64_t height);
    CKeyID GetDelegate(const std::string& name);
    std::string GetDelegate(const CKeyID& keyid);
private:
    boost::shared_mutex lockMapHashHeightInvalidVote;
};


#endif
