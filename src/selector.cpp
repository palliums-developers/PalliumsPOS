#include <selector.h>
#include <witness.h>
#include <util.h>
#include <utilstrencodings.h>
#include <wallet/wallet.h>
#include <vrf/crypto_vrf.h>

static Selector selector;

Selector& Selector::GetInstance()
{
    return selector;
}

std::vector<Delegate> Selector::GetTopDelegateInfo(uint32_t nDelegateNum, std::vector<unsigned char> vrfValue)
{
    std::vector<Delegate> result;
    if(vrfValue == std::vector<unsigned char>(64,0)){
        for(auto &s:vWitnessPublickeys){
            std::vector<unsigned char> pk(ParseHex(s));
            result.push_back(Delegate(pk));
            if(result.size() >= nDelegateNum) {
                break;
            }
        }
        return result;
    }

    std::map<CKeyID,std::vector<unsigned char>> delegates;
    for(auto &s:vWitnessPublickeys)
    {
        std::vector<unsigned char> pk(ParseHex(s));
        std::vector<unsigned char> data(vrfValue.begin(),vrfValue.end());
        data.insert(data.end(),pk.begin(),pk.end());
        auto keyid = CKeyID(Hash160(data));
        if (keyid.IsNull()) {
            continue;
        }
        delegates.insert(std::make_pair(keyid,pk));
    }

    for(auto it = delegates.rbegin(); it != delegates.rend(); ++it)
    {
        if(result.size() >= nDelegateNum) {
            break;
        }
        //TODO:vote num auto detect
        result.push_back(Delegate(it->second));
    }
    return result;
}

void Selector::DeleteInvalidVote(uint64_t height)
{
    //TODO:complete this function
    return;
}

std::string Selector::GetDelegate(const std::vector<unsigned char>& vrfpubkey)
{
    for(auto &str_vrf_pubkey:vWitnessPublickeys)
    {
        std::vector<unsigned char> data(ParseHex(str_vrf_pubkey));
        if(data==vrfpubkey)
            return str_vrf_pubkey;
    }
    return std::string();
}

int Selector::GetVrfKeypairFromPrivKey(unsigned char *pk, unsigned char *sk, const unsigned char *privkey)
{
    return crypto_vrf_ietfdraft03_keypair_from_seed(pk, sk, privkey);
}
