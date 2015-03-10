// Structs from netinet. They reside in their own namespace to avoid confusion.

#ifndef FLOWPARSER_SNIFF_H
#define	FLOWPARSER_SNIFF_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <cstdint>
#include <iostream>
#include <string>

namespace flowparser {
namespace pcap {

// Ethernet headers are always exactly 14 bytes
static constexpr size_t kSizeEthernet = 14;

// Ethernet addresses are 6 bytes
static constexpr size_t kEthernetAddressLen = 6;

// UDP header size is always constant
static constexpr size_t kSizeUDP = 6;

// ICMP minimum length
static constexpr size_t kSizeICMP = ICMP_MINLEN;

typedef ip SniffIp;
typedef tcphdr SniffTcp;
typedef udphdr SniffUdp;
typedef icmp SniffIcmp;

// An empty dummy struct used when passing values to an unknown flow.
struct SniffUnknown {
};

}  // namespace pcap

static std::string IPToString(uint32_t ip) {
  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN);
  return std::string(str);
}

}  // namespace flowparser

#endif	/* FLOWPARSER_SNIFF_H */

