// Structs from libpcap. They reside in their own namespace to avoid confustion.

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
#include <arpa/inet.h>

namespace flowparser {
namespace pcap {

// Ethernet headers are always exactly 14 bytes
static constexpr size_t kSizeEthernet = 14;

// Ethernet addresses are 6 bytes
static constexpr size_t kEthernetAddressLen = 6;

// UDP header size is always constant
static constexpr size_t kSizeUDP = 6;

// Ethernet header
struct SniffEthernet {
  u_char ether_dhost[kEthernetAddressLen];  // destination host address
  u_char ether_shost[kEthernetAddressLen];  // source host address
  u_short ether_type;  // IP? ARP? RARP? etc
};

// IP header
struct SniffIp {
  u_char ip_vhl;  // version << 4 | header length >> 2
  u_char ip_tos;  // type of service
  u_short ip_len;  // total length
  u_short ip_id;  // identification
  u_short ip_off;  // fragment offset field
#define IP_RF 0x8000            // reserved fragment flag
#define IP_DF 0x4000            // dont fragment flag
#define IP_MF 0x2000            // more fragments flag
#define IP_OFFMASK 0x1fff       // mask for fragmenting bits
  u_char ip_ttl;  // time to live
  u_char ip_p;  // protocol
  u_short ip_sum;  // checksum
  struct in_addr ip_src, ip_dst;  // source and dest address
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// TCP header
struct SniffTcp {
  u_short th_sport;  // source port
  u_short th_dport;  // destination port
  u_int th_seq;  // sequence number
  u_int th_ack;  // acknowledgment number
  u_char th_offx2;  // data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;  // window
  u_short th_sum;  // checksum
  u_short th_urp;  // urgent pointer
};

// UDP header
struct SniffUdp {
  u_short uh_sport;  // source port
  u_short uh_dport;  // destination port
  u_short uh_ulen;  // datagram length
  u_short uh_sum;  // datagram checksum
};

}  // namespace pcap
}  // namespace flowparser

#endif	/* FLOWPARSER_SNIFF_H */

