#include <key_io.h>
#include <univalue.h>
#include <utilstrencodings.h>
#include <rpc/util.h>
#include <wallet/wallet.h>
#include <script/standard.h>
#include <rpc/server.h>

#include "omnicore/omnicore.h"
#include "omnicore/tally.h"

#include "nodetoken.h"

using namespace mastercore;

extern std::set<std::pair<std::string,uint32_t> > setFrozenAddresses;


class DescribeWalletAddressVisitorNt : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    void ProcessSubScript(const CScript& subscript, UniValue& obj, bool include_addresses = false) const
    {
        // Always present: script type and redeemscript
        txnouttype which_type;
        std::vector<std::vector<unsigned char>> solutions_data;
        Solver(subscript, which_type, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));

        CTxDestination embedded;
        UniValue a(UniValue::VARR);
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(detail);
            UniValue wallet_detail = boost::apply_visitor(*this, embedded);
            subobj.pushKVs(wallet_detail);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript.begin(), subscript.end()));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
            if (include_addresses) a.push_back(EncodeDestination(embedded));
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) a.push_back(EncodeDestination(key.GetID()));
                pubkeys.push_back(HexStr(key.begin(), key.end()));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys using their P2PKH address.
        // For that reason, only add the 'addresses' field when needed for backward compatibility. New applications
        // can use the 'embedded'->'address' field for P2SH or P2WSH wrapped addresses, and 'pubkeys' for
        // inspecting multisig participants.
        if (include_addresses) obj.pushKV("addresses", std::move(a));
    }

    explicit DescribeWalletAddressVisitorNt(CWallet* _pwallet) : pwallet(_pwallet) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj, IsDeprecatedRPCEnabled("validateaddress"));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const { return UniValue(UniValue::VOBJ); }
};



CNodeToken::CNodeToken()
{

}

CNodeToken::~CNodeToken()
{

}

std::vector<std::string> CNodeToken::GetNodeTokenerPubkey(uint32_t propertyId, CWallet* pwallet)
{

    // Get Address of Token

    std::vector<std::string> vecFrozenAddress;

    for (std::unordered_map<std::string, CMPTally>::iterator it = mp_tally_map.begin(); it != mp_tally_map.end(); ++it)
    {
        uint32_t id = 0;
        bool includeAddress = false;
        std::string address = it->first;
        (it->second).init();
        while (0 != (id = (it->second).next()))
        {
            if (id == propertyId)
            {
                includeAddress = true;
                break;
            }
        }
        if (!includeAddress)
        {
            continue; // ignore this address, has never transacted in this propertyId
        }

        if (setFrozenAddresses.find(std::make_pair(address, propertyId)) != setFrozenAddresses.end())
        {
            vecFrozenAddress.push_back(address);
        }

    }


    // get pubkey by address

    std::vector<UniValue>  pubkey1;

    std::vector<std::string> vecPubkeys;

    for(auto address : vecFrozenAddress)
    {
        CTxDestination dest = DecodeDestination(address);
        CScript scriptPubKey = GetScriptForDestination(dest);

        UniValue ret(UniValue::VOBJ);
        ret.pushKVs(boost::apply_visitor(DescribeWalletAddressVisitorNt(pwallet), dest));

        UniValue pubkey = find_value(ret, "pubkey");

        pubkey1.push_back(pubkey);

        std::string sPubkey = pubkey.get_str();

        CPubKey pubkeyHex(ParseHex(sPubkey));

        vecPubkeyIDs.push_back(pubkeyHex);

        vecPubkeys.emplace_back(std::move(sPubkey));

    }

    return  vecPubkeys;

}

uint32_t CNodeToken::GetPropertyIdByNodeTokenType(TokenType type)
{

    return  propertyId;

}
