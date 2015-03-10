#include "gtest/gtest.h"

#include <random>

#include "flows.h"
#include "common_test.h"

namespace flowparser {
namespace test {

constexpr uint64_t kInitTimestamp = 10000;

class FlowFixture : public ::testing::Test {
 protected:
  FlowFixture()
      : gen_(1) {
    pcap::SniffIp ip = gen_.GenerateIpHeader(1, 10);
    ip.ip_p = IPPROTO_TCP;

    key_ = std::make_unique<FlowKey>(ip, 10, 100);
  }

  // Updates given flow with a new packet that has the given timestamp and seq
  // and carries a given number of bytes.
  void UpdateTcpIp(uint64_t timestamp, uint16_t payload, uint32_t seq,
                   Flow* flow) {
    pcap::SniffIp ip_header = gen_.GenerateIpHeader();
    pcap::SniffTcp tcp_header = gen_.GenerateTCPHeader();

    ip_header.ip_hl = 5;
    ip_header.ip_p = IPPROTO_TCP;
    ip_header.ip_len = htons(40 + payload);
    tcp_header.th_off = 5;
    tcp_header.th_seq = htonl(seq);

    size_t dummy = 0;
    flow->TCPIpRx(ip_header, tcp_header, timestamp, &dummy);
  }

  std::unique_ptr<FlowKey> key_;
  FlowConfig flow_cfg_;
  TCPPktGen gen_;
};

TEST_F(FlowFixture, InfoInit) {
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  auto info = flow.GetInfo();

  ASSERT_EQ(kInitTimestamp, info.first_rx);
  ASSERT_EQ(std::numeric_limits<uint64_t>::max(), info.last_rx);
  ASSERT_EQ(0, info.pkts_seen);
  ASSERT_EQ(0, info.total_ip_len_seen);
  ASSERT_EQ(0, info.total_payload_seen);
}

TEST_F(FlowFixture, InfoTotals) {
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  uint64_t size_total = 0;
  uint64_t payload_total = 0;
  for (size_t i = 0; i < 100; ++i) {
    pcap::SniffIp ip_header = gen_.GenerateIpHeader();
    ip_header.ip_p = IPPROTO_TCP;
    pcap::SniffTcp tcp_header = gen_.GenerateTCPHeader();

    size_t header_overhead = ip_header.ip_hl * 4 + tcp_header.th_off * 4;
    size_t ip_len = ntohs(ip_header.ip_len);

    if (ip_len < header_overhead) {
      ip_header.ip_len = header_overhead;
    }

    size_total += ip_len;
    payload_total += ip_len - header_overhead;

    size_t dummy = 0;
    flow.TCPIpRx(ip_header, tcp_header, kInitTimestamp, &dummy);
  }

  auto info = flow.GetInfo();

  ASSERT_EQ(size_total, info.total_ip_len_seen);
  ASSERT_EQ(payload_total, info.total_payload_seen);
  ASSERT_EQ(100, info.pkts_seen);
}

TEST_F(FlowFixture, InfoFirstLastRx) {
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  for (size_t i = 0; i < 100; ++i) {
    pcap::SniffIp ip_header = gen_.GenerateIpHeader();
    ip_header.ip_p = IPPROTO_TCP;
    pcap::SniffTcp tcp_header = gen_.GenerateTCPHeader();

    size_t dummy = 0;
    flow.TCPIpRx(ip_header, tcp_header, kInitTimestamp + 5 * i, &dummy);
  }

  auto info = flow.GetInfo();

  ASSERT_EQ(kInitTimestamp, info.first_rx);
  ASSERT_EQ(kInitTimestamp + 5 * 99, info.last_rx);
}

TEST_F(FlowFixture, 1MIter) {
  flow_cfg_.SetField(FlowConfig::HF_IP_ID);
  flow_cfg_.SetField(FlowConfig::HF_IP_TTL);
  flow_cfg_.SetField(FlowConfig::HF_IP_LEN);
  flow_cfg_.SetField(FlowConfig::HF_TCP_SEQ);
  flow_cfg_.SetField(FlowConfig::HF_TCP_ACK);
  flow_cfg_.SetField(FlowConfig::HF_TCP_WIN);
  flow_cfg_.SetField(FlowConfig::HF_TCP_FLAGS);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  std::vector<pcap::SniffIp> ip_headers;
  std::vector<pcap::SniffTcp> tcp_headers;

  size_t mem_used = 0;
  for (size_t i = 0; i < 1000000; ++i) {
    pcap::SniffIp ip_header = gen_.GenerateIpHeader();
    ip_header.ip_p = IPPROTO_TCP;
    pcap::SniffTcp tcp_header = gen_.GenerateTCPHeader();

    ip_headers.push_back(ip_header);
    tcp_headers.push_back(tcp_header);

    flow.TCPIpRx(ip_header, tcp_header, kInitTimestamp + i, &mem_used);
  }

  ASSERT_TRUE(mem_used > 0);

  FlowIterator it(flow);

  const TrackedFields* fields;

  size_t i = 0;
  while ((fields = it.NextOrNull()) != nullptr) {
    AssertIPHeadersEqual(ip_headers[i], kInitTimestamp + i, *fields);
    AssertTCPHeadersEqual(tcp_headers[i], *fields);
    ++i;
  }
}

}  // namespace test
}  // namespace flowparser
