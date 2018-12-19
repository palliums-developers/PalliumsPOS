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
    std::vector<std::string> GetRegisterNodeTokenerVrfPubkey(uint32_t propertyId);   // old, maybe unused
    std::map<std::string,std::string> GetRegisterNodeTokenerVrfPubkey();

    std::map<std::string,std::string> GetRegisterNodeTokenerVrfPubkeyTest();

    static bool IsKeyidRegister(const std::string& keyid); // keyid is Hex string

private:
    uint32_t GetPropertyIdByNodeTokenType(TokenType type);
    void DecodePayload(std::string payload, std::vector<std::string>& veVrfPubkey); // Parase omni paylaod
    void GetVrfPubkeyDidbyDecodePayload(std::string payload, std::map<std::string,std::string>& VrfPubkeyDid); // Parase omni paylaod

    void GetVrfPubkeyDidbyDecodePayloadTest(std::string payload, std::map<std::string,std::string>& VrfPubkeyDid); // Parase omni paylaod

    static bool IsHasKeyRegisterKeyId(const std::string& payload, const std::string& keyid); //acquire registerd count of keyid
private:
    uint32_t propertyId;

    std::vector<CPubKey> vecPubkeyIDs;

};


#endif // NODETOKEN_H
