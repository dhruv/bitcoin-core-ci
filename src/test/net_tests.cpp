// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <crypto/bip324_suite.h>
#include <cstdint>
#include <key.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ios>
#include <memory>
#include <optional>
#include <string>

using namespace std::literals;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    BOOST_REQUIRE(LookupHost("0.0.0.0", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "0.0.0.0");

    // IPv4, INADDR_NONE
    BOOST_REQUIRE(LookupHost("255.255.255.255", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "255.255.255.255");

    // IPv4, casual
    BOOST_REQUIRE(LookupHost("12.34.56.78", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "12.34.56.78");

    // IPv6, in6addr_any
    BOOST_REQUIRE(LookupHost("::", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "::");

    // IPv6, casual
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    BOOST_REQUIRE(LookupHost(scoped_addr, addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
    BOOST_REQUIRE(LookupHost(link_local + "%0", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), link_local);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        CNetAddr net_addr;
        BOOST_REQUIRE(LookupHost(input_address, net_addr, false));
        BOOST_REQUIRE(net_addr.IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.ToString(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{ParseHex(
        "02"                                  // network type (IPv6)
        "10"                                  // address length
        "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd + sha256("bitcoin")[0:5] +
                                              // sha256(name)[0:10]
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << Span{ParseHex("04"                               // network type (TORv3)
                       "20"                               // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f"
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"             // network type (unknown)
                       "fe00000002"     // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CAddress{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);
    SetReachable(NET_I2P, false);
    SetReachable(NET_CJDNS, false);

    BOOST_CHECK(!IsReachable(NET_IPV4));
    BOOST_CHECK(!IsReachable(NET_IPV6));
    BOOST_CHECK(!IsReachable(NET_ONION));
    BOOST_CHECK(!IsReachable(NET_I2P));
    BOOST_CHECK(!IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);
    SetReachable(NET_I2P, true);
    SetReachable(NET_CJDNS, true);

    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    BOOST_CHECK(IsReachable(NET_UNROUTABLE)); // Ignored for both networks
    BOOST_CHECK(IsReachable(NET_INTERNAL));
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    SetReachable(NET_IPV4, true);
    BOOST_CHECK(IsReachable(addr));

    SetReachable(NET_IPV4, false);
    BOOST_CHECK(!IsReachable(addr));

    SetReachable(NET_IPV4, true); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    SetReachable(NET_IPV4, true);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};
    const CNetMsgMaker msg_maker{PROTOCOL_VERSION};

    // Force Chainstate::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    TestChainState& chainstate =
        *static_cast<TestChainState*>(&m_node.chainman->ActiveChainstate());
    chainstate.JumpOutOfIbd();

    m_node.peerman->InitializeNode(peer, NODE_NETWORK);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        msg_maker.Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time, services, peer_us);
    CDataStream msg_version_stream{msg_version.data, SER_NETWORK, PROTOCOL_VERSION};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);

    const auto msg_verack = msg_maker.Make(NetMsgType::VERACK);
    CDataStream msg_verack_stream{msg_verack.data, SER_NETWORK, PROTOCOL_VERSION};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        Span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            CDataStream s(data, SER_NETWORK, PROTOCOL_VERSION);
            std::vector<CAddress> addresses;

            s >> addresses;

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    m_node.peerman->SendMessages(&peer);

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainstate.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the internal state
    // in timedata.cpp and later confuses the test "timedata_tests/addtimedata". Thus reset
    // that state as it was before our test was run.
    TestOnlyResetTimeData();
}

BOOST_AUTO_TEST_CASE(bip324_derivation_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
    static const std::string initiator_ellswift_str = "b654960dff0ba8808a34337f46cc68ba7619c9df76d0550639dea62de07d17f9cb61b85f2897834ce12c50b1aefa281944abf2223a5fcf0a2a7d8c022498db35";
    static const std::string responder_ellswift_str = "ea57aae33e8dd38380c303fb561b741293ef97c780445184cabdb5ef207053db628f2765e5d770f666738112c94714991362f6643d9837e1c89cbd9710b80929";

    auto initiator_ellswift = ParseHex(initiator_ellswift_str);
    auto responder_ellswift = ParseHex(responder_ellswift_str);

    CKey initiator_key = DecodeSecret(strSecret1);
    CKey responder_key = DecodeSecret(strSecret2C);

    auto initiator_secret = initiator_key.ComputeBIP324ECDHSecret(MakeByteSpan(responder_ellswift), MakeByteSpan(initiator_ellswift), true);
    BOOST_CHECK(initiator_secret.has_value());
    auto responder_secret = responder_key.ComputeBIP324ECDHSecret(MakeByteSpan(initiator_ellswift), MakeByteSpan(responder_ellswift), false);
    BOOST_CHECK(responder_secret.has_value());
    BOOST_CHECK(initiator_secret.value() == responder_secret.value());
    BOOST_CHECK_EQUAL("85ac83c8b2cd328293d49b9ed999d9eff79847e767a6252dc17ae248b0040de0", HexStr(initiator_secret.value()));
    BOOST_CHECK_EQUAL("85ac83c8b2cd328293d49b9ed999d9eff79847e767a6252dc17ae248b0040de0", HexStr(responder_secret.value()));

    BIP324Session initiator_session, responder_session;

    DeriveBIP324Session(std::move(initiator_secret.value()), initiator_session);
    DeriveBIP324Session(std::move(responder_secret.value()), responder_session);

    BOOST_CHECK(initiator_session.initiator_L == responder_session.initiator_L);
    BOOST_CHECK_EQUAL("6bb300568ba8c0e19d78a0615854748ca675448e402480f3f260a8ccf808335a", HexStr(initiator_session.initiator_L));

    BOOST_CHECK(initiator_session.initiator_P == responder_session.initiator_P);
    BOOST_CHECK_EQUAL("128962f7dc651d92a9f4f4925bbf4a58f77624d80b9234171a9b7d1ab15f5c05", HexStr(initiator_session.initiator_P));

    BOOST_CHECK(initiator_session.responder_L == responder_session.responder_L);
    BOOST_CHECK_EQUAL("e3a471e934b306015cb33727ccdc3c458960792d48d2207e14b5b0b88fd464c2", HexStr(initiator_session.responder_L));

    BOOST_CHECK(initiator_session.responder_P == responder_session.responder_P);
    BOOST_CHECK_EQUAL("1b251c795df35bda9351f3b027834517974fc2a092b450e5bf99152ebf159746", HexStr(initiator_session.responder_P));

    BOOST_CHECK(initiator_session.session_id == responder_session.session_id);
    BOOST_CHECK_EQUAL("e7047d2a41c8f040ea7f278fbf03e40b40d70ed3d555b6edb163d91af518cf6b", HexStr(initiator_session.session_id));

    BOOST_CHECK(initiator_session.rekey_salt == responder_session.rekey_salt);
    BOOST_CHECK_EQUAL("23b2a623754403ac894a965340152e12ac9a01d945eb15", HexStr(initiator_session.rekey_salt));

    BOOST_CHECK(initiator_session.garbage_terminator == responder_session.garbage_terminator);
    BOOST_CHECK_EQUAL("0a45201bb53870da", HexStr(initiator_session.garbage_terminator));

    SelectParams(CBaseChainParams::REGTEST);
}

void message_serialize_deserialize_test(bool v2, const std::vector<CSerializedNetMsg>& test_msgs)
{
    // use keys with all zeros
    BIP324Key key_L, key_P;
    std::array<std::byte, BIP324_REKEY_SALT_LEN> rekey_salt;
    memset(key_L.data(), 1, BIP324_KEY_LEN);
    memset(key_P.data(), 2, BIP324_KEY_LEN);
    memset(rekey_salt.data(), 3, BIP324_REKEY_SALT_LEN);

    // construct the serializers
    std::unique_ptr<TransportSerializer> serializer;
    std::unique_ptr<TransportDeserializer> deserializer;

    if (v2) {
        serializer = std::make_unique<V2TransportSerializer>(V2TransportSerializer(key_L, key_P, rekey_salt));
        deserializer = std::make_unique<V2TransportDeserializer>(V2TransportDeserializer((NodeId)0, key_L, key_P, rekey_salt));
    } else {
        serializer = std::make_unique<V1TransportSerializer>(V1TransportSerializer());
        deserializer = std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), (NodeId)0, SER_NETWORK, INIT_PROTO_VERSION));
    }
    // run 100 times through all messages with the same cipher suite instances
    for (unsigned int i = 0; i < 100; i++) {
        for (size_t msg_index = 0; msg_index < test_msgs.size(); msg_index++) {
            const CSerializedNetMsg& msg_orig = test_msgs[msg_index];
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.m_type = msg_orig.m_type;

            std::vector<unsigned char> serialized_header;
            serializer->prepareForTransport(msg, serialized_header);

            // read two times
            //  first: read header
            size_t read_bytes{0};
            Span<const uint8_t> span_header(serialized_header.data(), serialized_header.size());
            if (serialized_header.size() > 0) read_bytes += deserializer->Read(span_header);
            //  second: read the encrypted payload (if required)
            Span<const uint8_t> span_msg(msg.data.data(), msg.data.size());
            if (msg.data.size() > 0) read_bytes += deserializer->Read(span_msg);
            if (msg.data.size() > read_bytes) {
                Span<const uint8_t> span_msg(msg.data.data() + read_bytes, msg.data.size() - read_bytes);
                read_bytes += deserializer->Read(span_msg);
            }
            // message must be complete
            BOOST_CHECK(deserializer->Complete());
            BOOST_CHECK_EQUAL(read_bytes, msg.data.size() + serialized_header.size());

            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer->GetMessage(GetTime<std::chrono::microseconds>(), reject_message, disconnect, {})};
            // The first v2 message is reject by V2TransportDeserializer as a placeholder for transport version messages
            BOOST_CHECK(!v2 || (i == 0 && msg_index == 0) || !reject_message);
            BOOST_CHECK(!disconnect);
            if (reject_message) continue;
            BOOST_CHECK_EQUAL(result.m_type, msg_orig.m_type);
            BOOST_CHECK_EQUAL(result.m_message_size, msg_orig.data.size());
            if (!msg_orig.data.empty()) {
                BOOST_CHECK_EQUAL(0, memcmp(result.m_recv.data(), msg_orig.data.data(), msg_orig.data.size()));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(net_v2)
{
    // create some messages where we perform serialization and deserialization
    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));
    CDataStream stream(ParseHex("020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"), SER_NETWORK, PROTOCOL_VERSION);
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TX, CTransaction(deserialize, stream)));
    std::vector<CInv> vInv;
    for (unsigned int i = 0; i < 1000; i++) {
        vInv.push_back(CInv(MSG_BLOCK, Params().GenesisBlock().GetHash()));
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::INV, vInv));

    // add a dummy message
    std::string dummy;
    for (unsigned int i = 0; i < 100; i++) {
        dummy += "020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000";
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make("foobar", dummy));

    message_serialize_deserialize_test(true, test_msgs);
    message_serialize_deserialize_test(false, test_msgs);
}

struct P2PV2Peer {
    CKey key;
    std::array<uint8_t, 32> ellswift_r32;
    EllSwiftPubKey expected_ellswift;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> aad_0;
    std::vector<uint8_t> ciphertext_0;
    std::vector<uint8_t> ciphertext_999;
    std::vector<uint8_t> ciphertext_0_beginswith;
    std::vector<uint8_t> ciphertext_0_endswith;
    std::vector<uint8_t> ciphertext_999_beginswith;
    std::vector<uint8_t> ciphertext_999_endswith;
};

struct P2PV2TestVector {
    P2PV2Peer initiator;
    P2PV2Peer responder;
    ECDHSecret expected_ecdh_secret;
    BIP324Session expected_bip324_session;
};

#define PARSE_HEX_COPY(X, Y)  \
    parsed_hex = ParseHex(X); \
    memcpy(Y.data(), parsed_hex.data(), parsed_hex.size())

P2PV2TestVector parse_test_vector(const char* initiator_privkey, const char* responder_privkey,
                                  const char* initiator_ellswift_r32, const char* responder_ellswift_r32,
                                  const char* initiator_ellswift, const char* responder_ellswift,
                                  const std::vector<uint8_t>& initiator_contents,
                                  const std::vector<uint8_t>& responder_contents,
                                  const char* initiator_aad_0,
                                  const char* responder_aad_0,
                                  const char* shared_ecdh_secret,
                                  const char* initiator_L, const char* initiator_P,
                                  const char* responder_L, const char* responder_P,
                                  const char* session_id,
                                  const char* rekey_salt,
                                  const char* garbage_terminator,
                                  const char* initiator_ciphertext_0, const char* initiator_ciphertext_999,
                                  const char* responder_ciphertext_0, const char* responder_ciphertext_999,
                                  const char* initiator_ct_0_prefix="", const char* initiator_ct_0_suffix="",
                                  const char* initiator_ct_999_prefix="", const char* initiator_ct_999_suffix="",
                                  const char* responder_ct_0_prefix="", const char* responder_ct_0_suffix="",
                                  const char* responder_ct_999_prefix="", const char* responder_ct_999_suffix="")
{
    P2PV2TestVector ret;
    auto parsed_hex = ParseHex(initiator_privkey);
    ret.initiator.key.Set(parsed_hex.begin(), parsed_hex.end(), false);
    parsed_hex = ParseHex(responder_privkey);
    ret.responder.key.Set(parsed_hex.begin(), parsed_hex.end(), false);

    PARSE_HEX_COPY(initiator_ellswift_r32, ret.initiator.ellswift_r32);
    PARSE_HEX_COPY(responder_ellswift_r32, ret.responder.ellswift_r32);
    PARSE_HEX_COPY(initiator_ellswift, ret.initiator.expected_ellswift);
    PARSE_HEX_COPY(responder_ellswift, ret.responder.expected_ellswift);
    PARSE_HEX_COPY(shared_ecdh_secret, ret.expected_ecdh_secret);
    PARSE_HEX_COPY(initiator_L, ret.expected_bip324_session.initiator_L);
    PARSE_HEX_COPY(initiator_P, ret.expected_bip324_session.initiator_P);
    PARSE_HEX_COPY(responder_L, ret.expected_bip324_session.responder_L);
    PARSE_HEX_COPY(responder_P, ret.expected_bip324_session.responder_P);
    PARSE_HEX_COPY(session_id, ret.expected_bip324_session.session_id);
    PARSE_HEX_COPY(rekey_salt, ret.expected_bip324_session.rekey_salt);
    PARSE_HEX_COPY(garbage_terminator, ret.expected_bip324_session.garbage_terminator);
    ret.initiator.plaintext = initiator_contents;
    ret.initiator.aad_0 = ParseHex(initiator_aad_0);
    ret.initiator.ciphertext_0 = ParseHex(initiator_ciphertext_0);
    ret.initiator.ciphertext_0_beginswith = ParseHex(initiator_ct_0_prefix);
    ret.initiator.ciphertext_0_endswith = ParseHex(initiator_ct_0_suffix);
    ret.initiator.ciphertext_999_beginswith = ParseHex(initiator_ct_999_prefix);
    ret.initiator.ciphertext_999_endswith = ParseHex(initiator_ct_999_suffix);
    ret.initiator.ciphertext_999 = ParseHex(initiator_ciphertext_999);
    ret.responder.plaintext = responder_contents;
    ret.responder.aad_0 = ParseHex(responder_aad_0);
    ret.responder.ciphertext_0 = ParseHex(responder_ciphertext_0);
    ret.responder.ciphertext_999 = ParseHex(responder_ciphertext_999);
    ret.responder.ciphertext_0_beginswith = ParseHex(responder_ct_0_prefix);
    ret.responder.ciphertext_0_endswith = ParseHex(responder_ct_0_suffix);
    ret.responder.ciphertext_999_beginswith = ParseHex(responder_ct_999_prefix);
    ret.responder.ciphertext_999_endswith = ParseHex(responder_ct_999_suffix);

    return ret;
}

void bip324_assert_test_vector(const P2PV2TestVector& tv)
{
    auto initiator_ellswift = tv.initiator.key.EllSwiftEncode(tv.initiator.ellswift_r32).value();
    BOOST_CHECK_EQUAL(HexStr(initiator_ellswift), HexStr(tv.initiator.expected_ellswift));

    auto responder_ellswift = tv.responder.key.EllSwiftEncode(tv.responder.ellswift_r32).value();
    BOOST_CHECK_EQUAL(HexStr(responder_ellswift), HexStr(tv.responder.expected_ellswift));

    auto initiator_ecdh_secret = tv.initiator.key.ComputeBIP324ECDHSecret(
            MakeByteSpan(responder_ellswift), MakeByteSpan(initiator_ellswift), true).value();
    auto responder_ecdh_secret = tv.responder.key.ComputeBIP324ECDHSecret(
            MakeByteSpan(initiator_ellswift), MakeByteSpan(responder_ellswift), false).value();
    BOOST_CHECK_EQUAL(HexStr(initiator_ecdh_secret), HexStr(responder_ecdh_secret));
    BOOST_CHECK_EQUAL(HexStr(initiator_ecdh_secret), HexStr(tv.expected_ecdh_secret));

    BIP324Session v2_session;
    DeriveBIP324Session(std::move(initiator_ecdh_secret), v2_session);

    BOOST_CHECK_EQUAL(HexStr(v2_session.initiator_L), HexStr(tv.expected_bip324_session.initiator_L));
    BOOST_CHECK_EQUAL(HexStr(v2_session.initiator_P), HexStr(tv.expected_bip324_session.initiator_P));
    BOOST_CHECK_EQUAL(HexStr(v2_session.responder_L), HexStr(tv.expected_bip324_session.responder_L));
    BOOST_CHECK_EQUAL(HexStr(v2_session.responder_P), HexStr(tv.expected_bip324_session.responder_P));
    BOOST_CHECK_EQUAL(HexStr(v2_session.session_id), HexStr(tv.expected_bip324_session.session_id));
    BOOST_CHECK_EQUAL(HexStr(v2_session.rekey_salt), HexStr(tv.expected_bip324_session.rekey_salt));
    BOOST_CHECK_EQUAL(HexStr(v2_session.garbage_terminator), HexStr(tv.expected_bip324_session.garbage_terminator));

    auto initiator_suite = BIP324CipherSuite(v2_session.initiator_L, v2_session.initiator_P, v2_session.rekey_salt);
    BIP324HeaderFlags flags{BIP324_NONE};
    std::vector<std::byte> ciphertext_mac;
    ciphertext_mac.resize(BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + tv.initiator.plaintext.size() + RFC8439_EXPANSION);
    for (int i = 0; i < 1000; i++) {
        Span<const std::byte> aad = {};
        if (i == 0) {
            aad = MakeByteSpan(tv.initiator.aad_0);
        }
        BOOST_CHECK(initiator_suite.Crypt(aad,
                                          MakeByteSpan(tv.initiator.plaintext),
                                          MakeWritableByteSpan(ciphertext_mac), flags, true));
        if (i == 0) {
            if (!tv.initiator.ciphertext_0.empty()) {
                BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.initiator.ciphertext_0));
            } else if(!tv.initiator.ciphertext_0_beginswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            } else if(!tv.initiator.ciphertext_0_endswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            }
        } else if (i == 999) {
            if (!tv.initiator.ciphertext_999.empty()) {
                BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.initiator.ciphertext_999));
            } else if(!tv.initiator.ciphertext_999_beginswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            } else if(!tv.initiator.ciphertext_999_endswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            }
        }
    }

    auto responder_suite = BIP324CipherSuite(v2_session.responder_L, v2_session.responder_P, v2_session.rekey_salt);
    ciphertext_mac.resize(BIP324_LENGTH_FIELD_LEN + BIP324_HEADER_LEN + tv.responder.plaintext.size() + RFC8439_EXPANSION);
    for (int i = 0; i < 1000; i++) {
        Span<const std::byte> aad = {};
        if (i == 0) {
            aad = MakeByteSpan(tv.responder.aad_0);
        }
        BOOST_CHECK(responder_suite.Crypt(aad,
                                          MakeByteSpan(tv.responder.plaintext),
                                          MakeWritableByteSpan(ciphertext_mac), flags, true));
        if (i == 0) {
            if (!tv.responder.ciphertext_0.empty()) {
                BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.responder.ciphertext_0));
            } else if(!tv.responder.ciphertext_0_beginswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            } else if(!tv.responder.ciphertext_0_endswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            }
        } else if (i == 999) {
            if (!tv.responder.ciphertext_999.empty()) {
                BOOST_CHECK_EQUAL(HexStr(ciphertext_mac), HexStr(tv.responder.ciphertext_999));
            } else if(!tv.responder.ciphertext_999_beginswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            } else if(!tv.responder.ciphertext_999_endswith.empty()) {
                BOOST_TEST_MESSAGE("@@@");
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(bip324_vectors_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);

    std::array<std::byte, V2_MAX_GARBAGE_BYTES> initiator_large_aad;
    memset(initiator_large_aad.data(), 0x3F, initiator_large_aad.size());
    std::array<std::byte, V2_MAX_GARBAGE_BYTES> responder_large_aad;
    memset(responder_large_aad.data(), 0x21, responder_large_aad.size());
    std::vector<uint8_t> initiator_large_contents;
    initiator_large_contents.resize(4000001);
    memset(initiator_large_contents.data(), 0x01, initiator_large_contents.size());
    std::vector<uint8_t> responder_large_contents;
    responder_large_contents.resize(4000001);
    memset(responder_large_contents.data(), 0x02, responder_large_contents.size());

    std::array<P2PV2TestVector, 8> vectors{
        parse_test_vector(
            /* initiator_privkey */ "9cdfc7df74056ddebee98e3310026ecb11578cad9c5d09457194cc2162a1973b",
            /* responder_privkey */ "2030aaaf44a1437c07c938aa33c58751a6aee0c0e48e285f8031b137f498921d",
            /* initiator_ellswift_r32*/ "c1efb3a6738a6d612f5f27dc35959c7e5c7d3ec15ffae3ca3159abd1582e8db7",
            /* responder_ellswift_r32 */ "cb9dfe3802ae4caf320971d52f36f284ad88ddb976976cc2deb6bb39d0a79fde",
            /* initiator_ellswift */ "9b006371b8ceab1a95e87de3e24022c22946f1949a19baee6de14f3abf2d559a95c385732c3d4cf345d158bf72dfc142093a7708c02e96355c010f456f47422d",
            /* responder_ellswift */ "19a4af4fa003a1ea67c0d25771ba90a81a92490a9a19690eab1b8598744c35aa1ade90c6ce36f122ea909c539115e95907488312e30e90d3c519018f5693b664",
            /* initiator_contents */ ParseHex("9b"),
            /* responder_contents */ ParseHex("28"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "cdd947f606ef0075de1a453c6fb412c876656fe3fdca2221ed5f340c86ecd7fe",
            /* initiator_L */ "1fd73066880c958207b07d7d3af7bc0ad6bca393c29bf0c32f28c8958eb22ca0",
            /* initiator_P */ "bbe8988a174a52c7064a2ee1ff289eb5d2a8ca1a4c576965b2b2271335d779b9",
            /* responder_L */ "be8d7a8a2a32a13d4c8f3fca95f0e6bd5e89f36aae0ade88eb71f5688e424cbf",
            /* responder_P */ "37a1eb3e4c8d00e2806908f81c12e0932b0a042621666aecd6de8a075c290a03",
            /* session_id */ "60963a88a8511745cd4895837d1d33b630fcb6cf1944a771174c566a693bc28f",
            /* rekey_salt */ "6994f20646a7ea40a10b889019a957994ea2975fb17bc6",
            /* garbage_terminator */ "48367e65a72f0814",
            /* initiator_ciphertext_0 */ "08667198a72487edc887bb3e8b6d3c19184a0ce8bc",
            /* initiator_ciphertext_999 */ "a8adb974fee92e29a70589454f8ea831d2bdfbc016",
            /* responder_ciphertext_0 */ "36877689f82ed7ee1cc1f294fae0f7a80fad59bb4b",
            /* responder_ciphertext_999 */ "d6baa1815af9fe0f5a0fda001bc90b20bf5f0d3aba"),

        parse_test_vector(
            /* initiator_privkey */ "9cdfc7df74056ddebee98e3310026ecb11578cad9c5d09457194cc2162a1973b",
            /* responder_privkey */ "2030aaaf44a1437c07c938aa33c58751a6aee0c0e48e285f8031b137f498921d",
            /* initiator_ellswift_r32*/ "c1efb3a6738a6d612f5f27dc35959c7e5c7d3ec15ffae3ca3159abd1582e8db7",
            /* responder_ellswift_r32 */ "cb9dfe3802ae4caf320971d52f36f284ad88ddb976976cc2deb6bb39d0a79fde",
            /* initiator_ellswift */ "9b006371b8ceab1a95e87de3e24022c22946f1949a19baee6de14f3abf2d559a95c385732c3d4cf345d158bf72dfc142093a7708c02e96355c010f456f47422d",
            /* responder_ellswift */ "19a4af4fa003a1ea67c0d25771ba90a81a92490a9a19690eab1b8598744c35aa1ade90c6ce36f122ea909c539115e95907488312e30e90d3c519018f5693b664",
            /* initiator_contents */ ParseHex("9bc0f24442a76af47b9daa9f0c99d41381c0c06698ffc4ad069acf3d20928277433818565904cdd66ea93b1b755a3293d1d154110faa8add3dcafed2328fffea"),
            /* responder_contents */ ParseHex("2822acbe87f9e1a284f2eaa9a56f948fc0de0c91f342ae541722b758d7956c9a8fe25b082789a2fb5b23da639d05e438461e7fcf92262dbeaeebbacbf01dcfb2"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "cdd947f606ef0075de1a453c6fb412c876656fe3fdca2221ed5f340c86ecd7fe",
            /* initiator_L */ "1fd73066880c958207b07d7d3af7bc0ad6bca393c29bf0c32f28c8958eb22ca0",
            /* initiator_P */ "bbe8988a174a52c7064a2ee1ff289eb5d2a8ca1a4c576965b2b2271335d779b9",
            /* responder_L */ "be8d7a8a2a32a13d4c8f3fca95f0e6bd5e89f36aae0ade88eb71f5688e424cbf",
            /* responder_P */ "37a1eb3e4c8d00e2806908f81c12e0932b0a042621666aecd6de8a075c290a03",
            /* session_id */ "60963a88a8511745cd4895837d1d33b630fcb6cf1944a771174c566a693bc28f",
            /* rekey_salt */ "6994f20646a7ea40a10b889019a957994ea2975fb17bc6",
            /* garbage_terminator */ "48367e65a72f0814",
            /* initiator_ciphertext_0 */ "49667198a7a436855253ab7b4afe2d2b175d8de9d893d70af12666b4059c0a33d24fd959c1c7fde900874577065fe37b58d8532efda65589b0266a41abff44bc1c4c4abbdd3f6ffcff4fa4881307f2ffe2a5ab45",
            /* initiator_ciphertext_999 */ "e9adb974fe1a878cc73afaf4e26a48b0bfa8d34da6e7ae77dd78a429b688a967982b140e6fd4ad2956a6d7c2537c6d8fb4c8cef2794fc318afe8741524c1fa51890434a00de763b1a119d7a108db213613774b22",
            /* responder_ciphertext_0 */ "77877689f874c64ac33c9d5075f0b540aed647c0466dd1189125160a1291dde56f552842ab36328f21bd438d8b20fae4970f66653475b4941bcfe251b669f9b8056abd1000e8abbe6e2e264c491f967a54bfb700",
            /* responder_ciphertext_999 */ "97baa1815aeed54e54e3ae6b698b66fa469e9335fd9791a86271e6bbaad3c31975932624976570bdbd465029b749aa9bc91ff563c7d67c9a549e45ef4bc80659c8677d394f7f12ab09cb9a819e355bb80a5f6b65"),

        parse_test_vector(
            /* initiator_privkey */ "44e5fe764c43d1f7a60ead0acd0e74a4b14f7b7fc056984a993dede99e04c743",
            /* responder_privkey */ "fe6065b12cdfd53b9cd9b55c491063d60abdccc3090d2cdba17bf093fe363f09",
            /* initiator_ellswift_r32*/ "f54a836324dcb9c5701c3f73edf96ebfea053a2af1be4e7bb178bf721bad5e4d",
            /* responder_ellswift_r32 */ "ef7cd5de28f2b6b77f59ef3b4d00939841e0ab9ab5fdd351e83ce0626c90e866",
            /* initiator_ellswift */ "bd439a4b0cdf1a6ec5a3f10acb97ac2fe11d4c10266c24008f8d963ec40c5468b113ab984858531ecd134d716e31ca6f536bc23b4c56439bfd253f3c74c71883",
            /* responder_ellswift */ "c6eac141d4740187069e62a07c3549f5e179f676d90a8e333cda843c53127843aa3c5272baae373b3548d2e414c818aeaabc74938059b34c36c915d0e2f08840",
            /* initiator_contents */ ParseHex("a4874343279f3ca57427a8649833a7d276023e1035f85a7bfe19597055657192b9d2c102c69f0c8b2fdaeb064cc7432e549614e5aef603f9cf41e44a2f0b41b0"),
            /* responder_contents */ ParseHex("dc77639158727bd733b8accc7c4bd27d329653bceace8be353b02fa56dda8598ff52c833e6aa826c9b7458d978490b24e6cd267afe6f4f1f47edf732e6d08beb"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "ab9c6c533a41976b0c8ee0de0bd45c627300f60b1008aa2fb964e84c8a17da82",
            /* initiator_L */ "183df1ce9a65a2d0499e378c3bfc9ce62039c8d4fa9818fa9ec4e298a1f09e7c",
            /* initiator_P */ "5ef004836831f60005ed07457d96c6af4c6ef737ad4bed600e408934d7c9583a",
            /* responder_L */ "85fffb25b3f3631c22401a84ae2ec5a1aa4b198fffdebf79292a25635d4adc9a",
            /* responder_P */ "52499ba5781402b56a007f1f21ce1533c44de9d4474e4305d3cae8eb0f4462c1",
            /* session_id */ "2e3cd741f4d22a44e84837508b5d940340f41c7ebc8d0392386c2a646c513bf8",
            /* rekey_salt */ "e123e66ef17408ae5cae563432cd85e6ded1f554dce1a5",
            /* garbage_terminator */ "9ace3ea54b43eb13",
            /* initiator_ciphertext_0 */ "e695377c638c0c3b2e3f29e7fdb04ee8e12331eb2f01cee13e3538f9c38b5ff2b056a8464ca176cd870ae4f6db43c5b4559bc608fdcedebb6d69db6d9e40162d0dbd2d0456eea5ab94e3bb78c9e3bdb316e95ed6",
            /* initiator_ciphertext_999 */ "aec3e7c8cb16b6bc90c8f9a77497fb916e3cb60e59f039224ee705e25828325d362b3d29f487a525249b683f58c43ce5a01a8d41e9625cd6140aa1e66b4ee2cd92b22021cc64b604e00fffef272780d15eac36a0",
            /* responder_ciphertext_0 */ "0f9ffa01207908985cb055d85cc765bcf3cc3f7bf49ecd0f2e3afa2469a958cdae43ae8b90046f487dde9e5e97718ef1ea3083ce9ecd63fcf701ead67ba3d21ace40c45a7993ddf3a41aa827defe3d9b81389f3f",
            /* responder_ciphertext_999 */ "a4f07c92703dd21a9bf8076bffc063360fb3d0e9318b79bdb72a6784c38461e8b847027f7f001ca9f0180c63c2eb92039b8314c8fe04d2cf5d84c2a6512d87cf286ac904956281678cea5abe6ca21b0a2244af47"),

        parse_test_vector(
            /* initiator_privkey */ "2e26264ea126f08b8baa90f394defc2af8e5e1a3392c1cf6456ba7879494cc29",
            /* responder_privkey */ "9fc639ee5a340b6d646d3c0ab35e634c565d25d8dde5fa2ca2e79fad07c9a6d5",
            /* initiator_ellswift_r32*/ "794d7f24d16def675f37c41277349fc7186bfa38943f3e349fb98a9c28cd92a8",
            /* responder_ellswift_r32 */ "2b8e3b215a08098a43604a9f0305a2ec5f5dc0cc624293fc285c6e5f1ad412f9",
            /* initiator_ellswift */ "2a5ec3ace440508588d706cbd08ea7bf04b46df6c5bb41c9ca7b07e30fdefc0fb124bb825a4004a56d570860996faba49ad53dd731b27f8482c8eaccc495fcc1",
            /* responder_ellswift */ "e979b78addd7cf3534214c67a4e11edc772166162bad7ac5eb4f903300e401f7e85189a75aeb741ce5d8812d7be79c514748018123ee3e5a0f0aa34e1515517a",
            /* initiator_contents */ ParseHex("868d3648fbd816c72c54c12f403127503ba305eeb1a65a144009fae2b6e3bea4c76034a88ccee3a3396c69a970b4fff2f381097d33943a0d455f6f3303a4d3dd"),
            /* responder_contents */ ParseHex("ba67e844fa8d7aa6b77dbb1737c3080da7b65c36b219d91da499b2fb58b6e6e711e7d2960ce744d1e15351badf205a829f7b55b74e971e0a9547d88ec3c30686"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "1dbfb470f3cd3ba50c12cb8a35188f4e1c18b173cd81c3be70b6bc8b4369f2d3",
            /* initiator_L */ "920ebaae8b143f4c159018bf3bf437ebc4a7877c7e2dd43c5a0668bc708d3154",
            /* initiator_P */ "5b65f85a8a492472aa7d0b8cac54bfa607213b82716638babd4afb16dfcb1e1d",
            /* responder_L */ "fd2e328b6800b82336b2322edf746b30d4bf74d62499e159f694d302c5838898",
            /* responder_P */ "e878b3404d68aed887f7a9550cf62dd7df15a244d7b1125b98587da5c4ab8c4b",
            /* session_id */ "bb98987d00e4528c4affd17cd932881db550949a53aebf1b9c7af427443a3809",
            /* rekey_salt */ "102be4ead3e400287ce04f8d0134861c1d6bee0ae9067c",
            /* garbage_terminator */ "08ed8f04c6113ac2",
            /* initiator_ciphertext_0 */ "6d34bb2ee92bc56dda1e8e51cdb8b3cb322f9efdcb6346139a2f74cbc26a38a3f1fac67bc526d5358502958372f68fb833b4ec030a4ee95c63ce8b301e3c5196eecdc21768b48a0435ad7137fbf2d76ec2ec41c3",
            /* initiator_ciphertext_999 */ "036d79e26d7dee458d5a563fca695efcde187e71bcba417430f96d124bc2bebe7063c2a1ea40581b5d2b4ddb9d21c00c361e255ca3925ec89c25d0b74c6f30c20d4865fc6894876ec57d4d8e38841fe93eb3750a",
            /* responder_ciphertext_0 */ "fb6ac1610c6c38450aadb6a1b7e2c632a59f20975f49f2803db90da45d4ebc331d9373bec7ec79b5a270e061fc5c19a99333f3fe0a1246e70f51117b50666d529488f27ab5341659a65e705b382b485bc1f6170e",
            /* responder_ciphertext_999 */ "c2114aef9474528c40019e764aa8e90051f69c2a08ba803473413a8ab6dd540688c67f260b29b256d37fa284e109c4543fe65028f41bf005b6e3fe5ba9a768a6fbd854382941dd636816089c7ddf3e5b5b473497"),

        parse_test_vector(
            /* initiator_privkey */ "a371e20223e60e967233fe079f052aeabd30f6c6781314f3e7c44e049c648b7d",
            /* responder_privkey */ "8063aec031db643874c6629942c402e48f7d74abaf97a8faf8d4628010e46ba4",
            /* initiator_ellswift_r32*/ "ec23b3eab32028a9981ff20851abdd10846951b88989950cc31565bd9a3cda79",
            /* responder_ellswift_r32 */ "546bfd88292d90a9bbf697380c68f017fdf911d20acad6c3c7e900eff0205a83",
            /* initiator_ellswift */ "141cbda0eb0435e5a7c7317dc5360eb37932951373f3df0d87ec293f859da12c5cfe0c2271b40669388556825f74cb1d8cb1511831230a388dc27dcc1fb51ee6",
            /* responder_ellswift */ "1c8d9559b0ebebf6e6c7a65f21c4aa1db33ece37cae8affab4150894470b2ffcfe2b80be24710896b47e8c47566e652e4a433fea997fbc06d41f2359a47e2fd4",
            /* initiator_contents */ ParseHex("3e7443578c300b7210860c17168c9e11414781f6168710968777b567f1c27165bc8118ef402150549c18de9b567b85d4046fbef91f502f8cf4c298888ddd434b"),
            /* responder_contents */ ParseHex("7f6c9fbae0c003bb38ee2e73c31b248d639cc63b0d5d57b05f57c8b82122d61e401af33d481304a7d956b9ca730500890908682b14933cde958bf497cbcbbd45"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "5ea12a5905298f193b324f640d7fbc7e0e1cb60d4d09b936cea365f0ea6e1324",
            /* initiator_L */ "668f8d529781c640f2e0065ae11876793dfcfd7b4e964fb0fc0cbca2a78a3d7f",
            /* initiator_P */ "4ae20c5f96990683e13930a71fdc763a696d6c04a7bed826a4a09ebd75a20847",
            /* responder_L */ "73b6e6b6be52035c4550b87d7d3e9b8349af5bce6cd8f6067d80ca262f35bc7a",
            /* responder_P */ "5f7a18ffc2e002a547fe64fdee3e4f434bfc279313712e5a40db84a1d3c2c07e",
            /* session_id */ "760640e5ad64057042081cf402e9ece226bc41c71302f7e943bfd04c93cb5bd3",
            /* rekey_salt */ "db9bb1062a1720c133fa56ecac3d6b284515c1e6e01772",
            /* garbage_terminator */ "900c44a2b53502bd",
            /* initiator_ciphertext_0 */ "557206bc3072da71eee75162cad463c8f14bd0f776ac6d39c2ef123758db177d939ec202181437194784e2ef0be6c829834b3031e364f22bf367976d6782ae00215c16cccc56b8211521a2a568c704809f517591",
            /* initiator_ciphertext_999 */ "d8eef0fb876150b52c201f88e6b3d31701c9e3ae4f637be52fd32073c6b712c1fc9bf7c7af37ce68a22e32465c4e3765f713f9d9d9ac19fcc41f4bab85858a1598ceed1c7b6cd5d9780ce80807b54f09e2afe01f",
            /* responder_ciphertext_0 */ "af0d0f3d7f2e0fe4c1a227885ff550c45a9bdfd4108148e3eb0c3b5b0a8e088bb56196bbcadf5c74c6a97ec649c2a50412da5383f306ecc2dc283b4f9878f7127a1516ee3397cd0594e31c9f857222524e4a53c5",
            /* responder_ciphertext_999 */ "ed94054621b09d8bf5e1c4c29a2e9b6d645f0f45245483ff55097b3efd2a475850d0f0f51d21fb31bd609ca43899c2547c4bfc529e36b6a034ca8d611604a55de7d1e336b4c9a55f52e7669d85491652e312ba18"),

        parse_test_vector(
            /* initiator_privkey */ "928861cf12421b8174bce71bdbdf4397213e17977e40116d79fd42372dfce856",
            /* responder_privkey */ "1b06ce10bfdeb76e002d370df40120eb0472b432c5f6535d6a47cff44e126255",
            /* initiator_ellswift_r32*/ "1f909dc3ba59acbc6d24f589712cba5ac3926d7c8bc79f02316f4d1adb4f1b26",
            /* responder_ellswift_r32 */ "8bc6a59833a8e94810665ac0360b8c976d3f6dfec9573ae8333759e7d5fa8af8",
            /* initiator_ellswift */ "762f4b6ea5069f5ed6ee7abe37cb6f2c05487412413895cdd4b5c6ded9dade9e9c11019949cbb4ae4a109fca90de116010327c5b863dae85b1b85d2694656e2e",
            /* responder_ellswift */ "ad041b394e0819c9da64559351d09405cd434081d9d43137e1dd6727e5f8c7a85b64b19af0a0e401af0daab8928ef3a26634f28b325586d5c9dccd4fa51a70d7",
            /* initiator_contents */ ParseHex("7ab5826761ecf971d0aeff4c14eed091a206d29ddd84681c206b333bf0e121fcc5f8d45a266ce9ded4f7476edd0ab941c59cf4bca47f9327cf26a78ab4c9e7d6"),
            /* responder_contents */ ParseHex("dee314b076651a31f0e7451f4e0c3cebddeb6ce82d937b14e036cfa8ae8a91d3afd2760351c0c146fe8740874a3e281fb298cb00a1d9e58a1081f173466ceed6"),
            /* initiator_aad_0 */ "",
            /* responder_aad_0 */ "",
            /* shared_ecdh_secret */ "9643234828155404cbefe6160f5ff1a9376cf0be1a66797b558161f8e277e654",
            /* initiator_L */ "7b747764f7893d9bef2902eee6b1608331b14f40e0fabefd484560d5793bbbcc",
            /* initiator_P */ "62e7d1dda15efddf9b444635547c89e90be6f671e50262f6ebbafc5f03bfd9ed",
            /* responder_L */ "1436db0a90eb38ba13846b3ac8d46294092b759f252152814dcda63d2624d764",
            /* responder_P */ "40335231c3b5d62eaef2e8578083ecb4231f3bd1029a5acd75a933ef858ca9a1",
            /* session_id */ "4c5ff92a5b5f3568690c560b760ad00822b029bb2d3b7fe3dfc85687977209d7",
            /* rekey_salt */ "fa4e2e17dab8b6226c6397d631dc0eec54caaad4e549df",
            /* garbage_terminator */ "751d933b7103262e",
            /* initiator_ciphertext_0 */ "f518fdc5be9e37592b460f1e3ef065ebe698e09c90d34505fa34e142cc8f3be057a4eaea01e15d6f112afd599fae4b09001fa57bcc5ef53c1c4eaa78da9f6fb12bcfb8810e924557d4d545a17273e8eaa25e93e1",
            /* initiator_ciphertext_999 */ "13d0f4cc580e0e54862f4e05539146c2e42c87e3964c5c47a76314ea4e78f4a51d388b4d5bdcfe3bb63622dccbab31c9a3bfeb2df8e033f6d1a0d190b12a555101ceb00e32383a15da7b82d5f976042c7f57c558",
            /* responder_ciphertext_0 */ "6d330fcb8c97c9338bac296aed825f40332e9f38c2463a7161d76065be42128eba42687aa9935a519de73de44225b8312d1b80c8c6bc50f3bc8dba888a41bd69ea333669452ffd64da9bbf814e1a410cb751f2f9",
            /* responder_ciphertext_999 */ "8df6ea625ca7802c3c46bff36ddce949b5262e68309e16ca0ac1306e4e6da13a6a1eb857c0a8cee75116a75fe387909965d738fdd451fdcc60e931c7cac3a10909727a6099042a7ce3bfa1fcef4b912644f908ec"),


        // Changing the aad_0 should change the MAC tag on ciphertext_0
        parse_test_vector(
            /* initiator_privkey */ "928861cf12421b8174bce71bdbdf4397213e17977e40116d79fd42372dfce856",
            /* responder_privkey */ "1b06ce10bfdeb76e002d370df40120eb0472b432c5f6535d6a47cff44e126255",
            /* initiator_ellswift_r32*/ "1f909dc3ba59acbc6d24f589712cba5ac3926d7c8bc79f02316f4d1adb4f1b26",
            /* responder_ellswift_r32 */ "8bc6a59833a8e94810665ac0360b8c976d3f6dfec9573ae8333759e7d5fa8af8",
            /* initiator_ellswift */ "762f4b6ea5069f5ed6ee7abe37cb6f2c05487412413895cdd4b5c6ded9dade9e9c11019949cbb4ae4a109fca90de116010327c5b863dae85b1b85d2694656e2e",
            /* responder_ellswift */ "ad041b394e0819c9da64559351d09405cd434081d9d43137e1dd6727e5f8c7a85b64b19af0a0e401af0daab8928ef3a26634f28b325586d5c9dccd4fa51a70d7",
            /* initiator_contents */ ParseHex("7ab5826761ecf971d0aeff4c14eed091a206d29ddd84681c206b333bf0e121fcc5f8d45a266ce9ded4f7476edd0ab941c59cf4bca47f9327cf26a78ab4c9e7d6"),
            /* responder_contents */ ParseHex("dee314b076651a31f0e7451f4e0c3cebddeb6ce82d937b14e036cfa8ae8a91d3afd2760351c0c146fe8740874a3e281fb298cb00a1d9e58a1081f173466ceed6"),
            /* initiator_aad_0 */ HexStr(MakeUCharSpan(initiator_large_aad)).c_str(),
            /* responder_aad_0 */ HexStr(MakeUCharSpan(responder_large_aad)).c_str(),
            /* shared_ecdh_secret */ "9643234828155404cbefe6160f5ff1a9376cf0be1a66797b558161f8e277e654",
            /* initiator_L */ "7b747764f7893d9bef2902eee6b1608331b14f40e0fabefd484560d5793bbbcc",
            /* initiator_P */ "62e7d1dda15efddf9b444635547c89e90be6f671e50262f6ebbafc5f03bfd9ed",
            /* responder_L */ "1436db0a90eb38ba13846b3ac8d46294092b759f252152814dcda63d2624d764",
            /* responder_P */ "40335231c3b5d62eaef2e8578083ecb4231f3bd1029a5acd75a933ef858ca9a1",
            /* session_id */ "4c5ff92a5b5f3568690c560b760ad00822b029bb2d3b7fe3dfc85687977209d7",
            /* rekey_salt */ "fa4e2e17dab8b6226c6397d631dc0eec54caaad4e549df",
            /* garbage_terminator */ "751d933b7103262e",
            /* initiator_ciphertext_0 */ "f518fdc5be9e37592b460f1e3ef065ebe698e09c90d34505fa34e142cc8f3be057a4eaea01e15d6f112afd599fae4b09001fa57bcc5ef53c1c4eaa78da9f6fb12bcfb88120bce732f853c5141f3bde44c1c8c3ca",
            /* initiator_ciphertext_999 */ "13d0f4cc580e0e54862f4e05539146c2e42c87e3964c5c47a76314ea4e78f4a51d388b4d5bdcfe3bb63622dccbab31c9a3bfeb2df8e033f6d1a0d190b12a555101ceb00e32383a15da7b82d5f976042c7f57c558",
            /* responder_ciphertext_0 */ "6d330fcb8c97c9338bac296aed825f40332e9f38c2463a7161d76065be42128eba42687aa9935a519de73de44225b8312d1b80c8c6bc50f3bc8dba888a41bd69ea333669b72f5cb0c5fe48f63b4fa23f5f976dc7",
            /* responder_ciphertext_999 */ "8df6ea625ca7802c3c46bff36ddce949b5262e68309e16ca0ac1306e4e6da13a6a1eb857c0a8cee75116a75fe387909965d738fdd451fdcc60e931c7cac3a10909727a6099042a7ce3bfa1fcef4b912644f908ec"),

        parse_test_vector(
            /* initiator_privkey */ "928861cf12421b8174bce71bdbdf4397213e17977e40116d79fd42372dfce856",
            /* responder_privkey */ "1b06ce10bfdeb76e002d370df40120eb0472b432c5f6535d6a47cff44e126255",
            /* initiator_ellswift_r32*/ "1f909dc3ba59acbc6d24f589712cba5ac3926d7c8bc79f02316f4d1adb4f1b26",
            /* responder_ellswift_r32 */ "8bc6a59833a8e94810665ac0360b8c976d3f6dfec9573ae8333759e7d5fa8af8",
            /* initiator_ellswift */ "762f4b6ea5069f5ed6ee7abe37cb6f2c05487412413895cdd4b5c6ded9dade9e9c11019949cbb4ae4a109fca90de116010327c5b863dae85b1b85d2694656e2e",
            /* responder_ellswift */ "ad041b394e0819c9da64559351d09405cd434081d9d43137e1dd6727e5f8c7a85b64b19af0a0e401af0daab8928ef3a26634f28b325586d5c9dccd4fa51a70d7",
            /* initiator_contents */ initiator_large_contents,
            /* responder_contents */ responder_large_contents,
            /* initiator_aad_0 */ HexStr(MakeUCharSpan(initiator_large_aad)).c_str(),
            /* responder_aad_0 */ HexStr(MakeUCharSpan(responder_large_aad)).c_str(),
            /* shared_ecdh_secret */ "9643234828155404cbefe6160f5ff1a9376cf0be1a66797b558161f8e277e654",
            /* initiator_L */ "7b747764f7893d9bef2902eee6b1608331b14f40e0fabefd484560d5793bbbcc",
            /* initiator_P */ "62e7d1dda15efddf9b444635547c89e90be6f671e50262f6ebbafc5f03bfd9ed",
            /* responder_L */ "1436db0a90eb38ba13846b3ac8d46294092b759f252152814dcda63d2624d764",
            /* responder_P */ "40335231c3b5d62eaef2e8578083ecb4231f3bd1029a5acd75a933ef858ca9a1",
            /* session_id */ "4c5ff92a5b5f3568690c560b760ad00822b029bb2d3b7fe3dfc85687977209d7",
            /* rekey_salt */ "fa4e2e17dab8b6226c6397d631dc0eec54caaad4e549df",
            /* garbage_terminator */ "751d933b7103262e",
            /* initiator_ciphertext_0 */ "",
            /* initiator_ciphertext_999 */ "",
            /* responder_ciphertext_0 */ "",
            /* responder_ciphertext_999 */ "",
            "123",
            "123",
            "123",
            "123",
            "123",
            "123",
            "123",
            "123"),
    };

    for (const auto& tv : vectors) {
        bip324_assert_test_vector(tv);
    }
    SelectParams(CBaseChainParams::REGTEST);
}
BOOST_AUTO_TEST_SUITE_END()
