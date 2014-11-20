// Defines a simple packet generator used in tests.

#ifndef FLOWPARSER_COMMON_TEST_H
#define FLOWPARSER_COMMON_TEST_H

#include <random>

#include "sniff.h"

namespace flowparser {
namespace test {

// A very crude random packet generator. It only populates some of the fields
// in the header, leaving 0s in the the others.
class TCPPktGen {
 public:
  TCPPktGen(uint32_t seed)
      : rnd_(seed),
        uint_dist_(0, std::numeric_limits<uint32_t>::max()),
        ushort_dist_(0, std::numeric_limits<uint16_t>::max()),
        uchar_dist_(0, std::numeric_limits<uint8_t>::max()) {
  }

  pcap::SniffIp GenerateIpHeader() {
    uint32_t src = ushort_dist_(rnd_);
    uint32_t dst = src;
    while (dst == src) {
      dst = ushort_dist_(rnd_);
    }

    return GenerateIpHeader(src, dst);
  }

  pcap::SniffIp GenerateIpHeader(uint32_t src_ip, uint32_t dst_ip) {
    pcap::SniffIp ip_header;

    ip_header.ip_src.s_addr = htonl(src_ip);
    ip_header.ip_dst.s_addr = htonl(dst_ip);
    ip_header.ip_id = ushort_dist_(rnd_);
    ip_header.ip_len = ushort_dist_(rnd_);
    ip_header.ip_tos = uchar_dist_(rnd_);
    ip_header.ip_ttl = uchar_dist_(rnd_);
    ip_header.ip_off = 0;
    ip_header.ip_p = 0;
    ip_header.ip_sum = 0;
    ip_header.ip_vhl = 0;

    return ip_header;
  }

  pcap::SniffTcp GenerateTCPHeader() {
    uint16_t sport = ushort_dist_(rnd_);
    uint16_t dport = sport;
    while (dport == sport) {
      dport = ushort_dist_(rnd_);
    }

    return GenerateTCPHeader(sport, dport);
  }

  pcap::SniffTcp GenerateTCPHeader(uint16_t sport, uint16_t dport) {
    pcap::SniffTcp tcp_header;

    tcp_header.th_sport = htons(sport);
    tcp_header.th_dport = htons(dport);
    tcp_header.th_ack = uint_dist_(rnd_);
    tcp_header.th_flags = uchar_dist_(rnd_);
    tcp_header.th_seq = uint_dist_(rnd_);
    tcp_header.th_win = ushort_dist_(rnd_);
    tcp_header.th_offx2 = 0;
    tcp_header.th_sum = 0;
    tcp_header.th_urp = 0;

    return tcp_header;
  }

 private:
  std::default_random_engine rnd_;

  // Different random distributions for the different field types.
  std::uniform_int_distribution<uint32_t> uint_dist_;
  std::uniform_int_distribution<uint16_t> ushort_dist_;
  std::uniform_int_distribution<uint8_t> uchar_dist_;
};

static void AssertIPHeadersEqual(const pcap::SniffIp& pcap_header,
                                 uint64_t timestamp,
                                 const IPHeader& ip_header) {
  uint16_t ip_id = ntohs(pcap_header.ip_id);
  uint16_t ip_len = ntohs(pcap_header.ip_len);

  ASSERT_EQ(timestamp, ip_header.timestamp);
  ASSERT_EQ(ip_id, ip_header.id);
  ASSERT_EQ(ip_len, ip_header.length);
  ASSERT_EQ(pcap_header.ip_ttl, ip_header.ttl);
}

static void AssertTCPHeadersEqual(const pcap::SniffTcp& pcap_header,
                                  const TCPHeader& tcp_header) {
  uint16_t th_win = ntohs(pcap_header.th_win);

  ASSERT_EQ(th_win, tcp_header.win);
  ASSERT_EQ(ntohl(pcap_header.th_seq), tcp_header.seq);
  ASSERT_EQ(ntohl(pcap_header.th_ack), tcp_header.ack);
  ASSERT_EQ(pcap_header.th_flags, tcp_header.flags);
}

}
}

#endif  /* FLOWPARSER_COMMON_TEST_H */
