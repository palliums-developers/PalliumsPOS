#ifndef NODETOKEN_H
#define NODETOKEN_H
#include <string>
#include <vector>
#include <map>
namespace mastercore
{

class CNodeToken
{
public:
    CNodeToken();
    ~CNodeToken();

    struct KeyInfo
    {
        KeyInfo(){
            nRgtFlag = 0;
        }
        std::vector<unsigned char> sVrfPubkey;
        std::vector<unsigned char> sKeyID;
        int nRgtFlag; //1,register; 0,unregister;
    };

public:
    static bool IsKeyidRegisterDisk(std::vector<unsigned char>& keyid); //# keyid is Hex string

    std::map<std::vector<unsigned char>, std::vector<unsigned char>>  GetRegisterNodeTokenerVrfPubkeyDisk(); //# from disk

private:
    void GetVrfPubkeyDidbyDecodePayloadDisk(std::string payload, std::map<std::vector<unsigned char>, KeyInfo>& mapKeyInfo); //# Parase omni paylaod  

    static bool IsHasKeyRegisterKeyId(const std::string& payload, std::vector<unsigned char>& keyid); //acquire registerd count of keyid
};

}

#endif // NODETOKEN_H
