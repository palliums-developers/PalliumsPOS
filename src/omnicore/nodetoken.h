#ifndef NODETOKEN_H
#define NODETOKEN_H

#include "pubkey.h"
#include <set>
#include <vector>
#include <wallet/wallet.h>

class CNodeToken
{
public:
    CNodeToken();
    ~CNodeToken();

public:
    std::vector<std::string> GetNodeTokenerPubkey(uint32_t propertyId, CWallet* pwallet);

};

#endif // NODETOKEN_H
