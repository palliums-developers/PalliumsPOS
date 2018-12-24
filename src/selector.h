#ifndef BITCOIN_SELECTOR_H
#define BITCOIN_SELECTOR_H

#include <boost/thread.hpp>
#include<pubkey.h>

class Delegate;

class Selector{
public:
    static Selector& GetInstance();
    std::vector<Delegate> GetTopDelegateInfo(uint32_t nDelegateNum, std::vector<unsigned char> vrfValue);
    void DeleteInvalidVote(uint64_t height);
    CKeyID GetDelegate(const std::string& name);
    std::string GetDelegate(const std::vector<unsigned char>& vrfpubkey);
    int GetVrfKeypairFromPrivKey(unsigned char *pk, unsigned char *sk,const unsigned char *privkey);
private:
    boost::shared_mutex lockMapHashHeightInvalidVote;
};


#endif
