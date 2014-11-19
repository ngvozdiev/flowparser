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
    pcap::SniffIp ip_header;

    ip_header.ip_dst.s_addr = uint_dist_(rnd_);
    ip_header.ip_src.s_addr = uint_dist_(rnd_);
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
    pcap::SniffTcp tcp_header;

    tcp_header.th_ack = uint_dist_(rnd_);
    tcp_header.th_dport = ushort_dist_(rnd_);
    tcp_header.th_flags = uchar_dist_(rnd_);
    tcp_header.th_seq = uint_dist_(rnd_);
    tcp_header.th_sport = ushort_dist_(rnd_);
    tcp_header.th_win = ushort_dist_(rnd_);
    tcp_header.th_offx2 = 0;
    tcp_header.th_sum = 0;
    tcp_header.th_urp = 0;

    return tcp_header;
  }

 private:
  std::default_random_engine rnd_;

  std::uniform_int_distribution<uint32_t> uint_dist_;

  std::uniform_int_distribution<uint16_t> ushort_dist_;

  std::uniform_int_distribution<uint8_t> uchar_dist_;
};


}
}

#endif  /* FLOWPARSER_COMMON_TEST_H */
