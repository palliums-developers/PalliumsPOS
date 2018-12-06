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

    enum TokenType
    {
        TOKEN_TYPE_GENERAL_NODE = 0,
        TOKEN_TYPE_SUPER_NODE   = 1,
        TOKEN_TYPE_BLOCK_NODE   = 2,

    };


public:
    std::vector<std::string> GetNodeTokenerPubkey(uint32_t propertyId, CWallet* pwallet);

private:
    uint32_t GetPropertyIdByNodeTokenType(TokenType type);

private:
    uint32_t propertyId;

    std::vector<CPubKey> vecPubkeyIDs;

};

#endif // NODETOKEN_H
