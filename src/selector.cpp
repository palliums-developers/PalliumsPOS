#include <selector.h>
#include <witness.h>
#include <util.h>
#include <utilstrencodings.h>
#include <wallet/wallet.h>

static Selector selector;

Selector& Selector::GetInstance()
{
    return selector;
}

std::vector<Delegate> Selector::GetTopDelegateInfo(uint64_t nMinHoldBalance, uint32_t nDelegateNum)
{
    std::vector<Delegate> result;
    std::set<CKeyID> delegates;

    for(auto &publickey:vWitnessPublickeys)
    {
        std::vector<unsigned char> data(ParseHex(publickey));
        CPubKey pubKey(data.begin(), data.end());
        if (!pubKey.IsFullyValid())
            LogPrintf("Pubkey % is not a valid public key",publickey);
        auto keyid = pubKey.GetID();
        if (keyid.IsNull()) {
            continue;
        }
        delegates.insert(keyid);
    }

    uint64_t vote_num=delegates.size()+nMinHoldBalance;
    for(auto it = delegates.rbegin(); it != delegates.rend(); ++it)
    {
        if(result.size() >= nDelegateNum) {
            break;
        }
        //TODO:vote num auto detect
        result.push_back(Delegate(*it,vote_num--));
    }
    return result;
}

void Selector::DeleteInvalidVote(uint64_t height)
{
    //TODO:complete this function
    return;
}

std::string Selector::GetDelegate(const CKeyID &keyid)
{
    for(auto &publickey:vWitnessPublickeys)
    {
        std::vector<unsigned char> data(ParseHex(publickey));
        CPubKey pubKey(data.begin(), data.end());
        if (!pubKey.IsFullyValid())
            LogPrintf("Pubkey % is not a valid public key",publickey);
        auto kid = pubKey.GetID();
        if (kid.IsNull()) {
            continue;
        }
        if(kid==keyid)
            return publickey;
    }
    return std::string();
}
