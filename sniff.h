// Structs from netinet. They reside in their own namespace to avoid confustion.

#ifndef FLOWPARSER_SNIFF_H
#define	FLOWPARSER_SNIFF_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

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
}  // namespace flowparser

#endif	/* FLOWPARSER_SNIFF_H */

