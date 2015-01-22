#include "gtest/gtest.h"

#include <random>

#include "flows.h"
#include "common_test.h"

namespace flowparser {
namespace test {

constexpr uint64_t kInitTimestamp = 10000;
constexpr uint64_t kDefaultTimeout = 1000;

TEST(Flows, InfoInit) {


  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);

  auto info = tcp_flow.GetInfo();

  ASSERT_EQ(0.0, info.avg_bytes_per_period);
  ASSERT_EQ(0.0, info.avg_pkts_per_period);
  ASSERT_EQ(kInitTimestamp, info.first_rx);
  ASSERT_EQ(std::numeric_limits<uint64_t>::max(), info.last_rx);
  ASSERT_EQ(0, info.size_pkts);
  ASSERT_EQ(0, info.size_bytes);
}

TEST(Flows, Type) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  ASSERT_EQ(FlowType::TCP, tcp_flow.type());

  const Flow& flow = tcp_flow;
  ASSERT_EQ(FlowType::TCP, flow.type());

  UDPFlow udp_flow(kInitTimestamp, kDefaultTimeout);
  ASSERT_EQ(FlowType::UDP, udp_flow.type());

  ICMPFlow icmp_flow(kInitTimestamp, kDefaultTimeout);
  ASSERT_EQ(FlowType::ICMP, icmp_flow.type());

  UnknownFlow unknown_flow(kInitTimestamp, kDefaultTimeout);
  ASSERT_EQ(FlowType::UNKNONW, unknown_flow.type());
}

TEST(Flows, InfoAvgNoPkts) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);

  for (size_t i = 0; i < 100; ++i) {
    tcp_flow.UpdateAverages();
  }

  auto info = tcp_flow.GetInfo();

  ASSERT_EQ(0.0, info.avg_bytes_per_period);
  ASSERT_EQ(0.0, info.avg_pkts_per_period);
}

TEST(Flows, InfoAvgFivePkts) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  for (size_t i = 0; i < 100; ++i) {
    for (size_t j = 0; j < 5; ++j) {
      pcap::SniffIp ip_header = gen.GenerateIpHeader();
      ip_header.ip_len = htons(500);

      pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

      tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp);
    }

    tcp_flow.UpdateAverages();
  }

  auto info = tcp_flow.GetInfo();

  ASSERT_NEAR(5.0, info.avg_pkts_per_period, 0.01);
  ASSERT_NEAR(2500.0, info.avg_bytes_per_period, 25);
}

TEST(Flows, InfoAvgDecay) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  for (size_t j = 0; j < 5; ++j) {
    pcap::SniffIp ip_header = gen.GenerateIpHeader();
    ip_header.ip_len = htons(500);

    pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

    tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp);
  }

  for (size_t i = 0; i < 100; ++i) {
    tcp_flow.UpdateAverages();
  }

  auto info = tcp_flow.GetInfo();

  ASSERT_NEAR(0, info.avg_pkts_per_period, 0.01);
  ASSERT_NEAR(0.0, info.avg_bytes_per_period, 25);
}

TEST(Flows, PktRxSrcIpSameAsDstIp) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  pcap::SniffIp ip_header = gen.GenerateIpHeader(1, 1);
  pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

  ASSERT_FALSE(tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp).ok());
}

TEST(Flows, PktRxSrcPortSameAsDstPort) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  pcap::SniffIp ip_header = gen.GenerateIpHeader();
  pcap::SniffTcp tcp_header = gen.GenerateTCPHeader(1, 1);

  ASSERT_TRUE(tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp).ok());
}

TEST(Flows, InfoTotals) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  uint64_t size_total = 0;

  for (size_t i = 0; i < 100; ++i) {
    pcap::SniffIp ip_header = gen.GenerateIpHeader();
    size_total += ntohs(ip_header.ip_len);

    pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

    tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp);
  }

  auto info = tcp_flow.GetInfo();

  ASSERT_EQ(size_total, info.size_bytes);
  ASSERT_EQ(100, info.size_pkts);
}

TEST(Flows, InfoFirstLastRx) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  for (size_t i = 0; i < 100; ++i) {
    pcap::SniffIp ip_header = gen.GenerateIpHeader();
    pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

    tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp + 5 * i);
  }

  auto info = tcp_flow.GetInfo();

  ASSERT_EQ(kInitTimestamp, info.first_rx);
  ASSERT_EQ(kInitTimestamp + 5 * 99, info.last_rx);
}

// If the flow is only initialized, but has no packets it should be expired.
TEST(Flows, TimeLeftInit) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);

  ASSERT_GT(0, tcp_flow.TimeLeft(kInitTimestamp));
  ASSERT_GT(0, tcp_flow.TimeLeft(kInitTimestamp + kDefaultTimeout));
}

TEST(Flows, TimeLeft) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  tcp_flow.PacketRx(gen.GenerateIpHeader(), gen.GenerateTCPHeader(),
                    kInitTimestamp);

  ASSERT_EQ(kDefaultTimeout, tcp_flow.TimeLeft(kInitTimestamp));
  ASSERT_EQ(0, tcp_flow.TimeLeft(kInitTimestamp + kDefaultTimeout));
}

TEST(Flows, TimeLeftNegative) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  tcp_flow.PacketRx(gen.GenerateIpHeader(), gen.GenerateTCPHeader(),
                    kInitTimestamp);

  ASSERT_GT(0, tcp_flow.TimeLeft(kInitTimestamp + kDefaultTimeout + 1));
}

TEST(Flows, 1MIter) {
  TCPFlow tcp_flow(kInitTimestamp, kDefaultTimeout);
  TCPPktGen gen(1);

  std::vector<pcap::SniffIp> ip_headers;
  std::vector<pcap::SniffTcp> tcp_headers;

  for (size_t i = 0; i < 1000000; ++i) {
    pcap::SniffIp ip_header = gen.GenerateIpHeader();
    pcap::SniffTcp tcp_header = gen.GenerateTCPHeader();

    ip_headers.push_back(ip_header);
    tcp_headers.push_back(tcp_header);

    tcp_flow.PacketRx(ip_header, tcp_header, kInitTimestamp + i);
  }

  TCPFlowIterator it(tcp_flow);
  IPHeader flowparser_ip_header;
  TCPHeader flowparser_tcp_header;

  size_t i = 0;
  while (it.Next(&flowparser_ip_header, &flowparser_tcp_header)) {
    AssertIPHeadersEqual(ip_headers[i], kInitTimestamp + i,
                         flowparser_ip_header);
    AssertTCPHeadersEqual(tcp_headers[i], flowparser_tcp_header);
    ++i;
  }
}

}  // namespace test
}  // namespace flowparser
