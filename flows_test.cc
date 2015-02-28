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

TEST_F(FlowFixture, RateEstimatorInit) {
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  const TCPRateEstimator* estimator = flow.EstimatorOrNull();
  ASSERT_FALSE(estimator->out_of_order());

  // The flow is empty -- there are no packets and estimating its Bps does not
  // make sense.
  ASSERT_THROW(estimator->GetBytesPerSecEstimate(kInitTimestamp),
               std::logic_error);
}

TEST_F(FlowFixture, RateEstimatorSameSecond) {
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  UpdateTcpIp(kInitTimestamp + kMillion / 2, 1500, 10, &flow);
  UpdateTcpIp(kInitTimestamp + kMillion, 1500, 1510, &flow);

  const TCPRateEstimator* estimator = flow.EstimatorOrNull();
  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(
      3000.0, estimator->GetBytesPerSecEstimate(kInitTimestamp + kMillion));
}

TEST_F(FlowFixture, RateEstimatorAverage) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Every 1300 bytes every 0.5 sec, should average to 2600 Bps
  for (size_t i = 0; i < 100; ++i) {
    UpdateTcpIp(kInitTimestamp + i * (kMillion / 2), 1300, i * 1300, &flow);

    // Immediately after the first update the rate should be 1300
    if (i == 0) {
      ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
    }
  }

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(2600, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorAverageOverflow) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Every 1300 bytes every 0.5 sec, should average to 2600 Bps
  uint32_t seq_base = std::numeric_limits<uint32_t>::max() - 10 * 1300;
  for (size_t i = 0; i < 100; ++i) {
    UpdateTcpIp(kInitTimestamp + i * (kMillion / 2), 1300, seq_base + i * 1300,
                &flow);

    // Immediately after the first update the rate should be 1300
    if (i == 0) {
      ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
    }
  }

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(2600, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorAverageTwo) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Every 1300 bytes every sec, should average to 1300 Bps
  for (size_t i = 0; i < 100; ++i) {
    UpdateTcpIp(kInitTimestamp + i * kMillion, 1300, i * 1300, &flow);
  }

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorAverageThree) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Every 1300 bytes every sec, should average to 1300 Bps, but we skip all
  // packets except the last one.
  UpdateTcpIp(kInitTimestamp, 1300, 0, &flow);
  UpdateTcpIp(kInitTimestamp + 99 * kMillion, 1300, 99 * 1300, &flow);

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorAverageThreeOverflow) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Every 1300 bytes every sec, should average to 1300 Bps, but we skip all
  // packets except the last one.
  uint32_t seq_base = std::numeric_limits<uint32_t>::max() - 10 * 1300;
  UpdateTcpIp(kInitTimestamp, 1300, seq_base, &flow);
  UpdateTcpIp(kInitTimestamp + 99 * kMillion, 1300, seq_base + 99 * 1300,
              &flow);

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorAverageFour) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  // Should die to 0
  UpdateTcpIp(kInitTimestamp, 1300, 0, &flow);
  UpdateTcpIp(kInitTimestamp + 99 * kMillion, 1300, 99 * 1300, &flow);
  UpdateTcpIp(kInitTimestamp + 199 * kMillion, 0, 100 * 1300, &flow);

  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_NEAR(0, estimator->GetBytesPerSecEstimate(flow.last_rx()), 0.00000001);
}

TEST_F(FlowFixture, RateEstimatorAverageFive) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);
  const TCPRateEstimator* estimator = flow.EstimatorOrNull();

  UpdateTcpIp(kInitTimestamp, 1300, 0, &flow);
  UpdateTcpIp(kInitTimestamp + 99 * kMillion, 0, 1300, &flow);
  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_NEAR(0, estimator->GetBytesPerSecEstimate(flow.last_rx()), 0.00000001);

  UpdateTcpIp(kInitTimestamp + 199 * kMillion, 0, 101 * 1300, &flow);
  ASSERT_FALSE(estimator->out_of_order());
  ASSERT_DOUBLE_EQ(1300, estimator->GetBytesPerSecEstimate(flow.last_rx()));
}

TEST_F(FlowFixture, RateEstimatorNextSecondNoTraffic) {
  flow_cfg_.set_tcp_estimator_ewma_alpha(0.8);
  Flow flow(kInitTimestamp, *key_, flow_cfg_);

  UpdateTcpIp(kInitTimestamp + kMillion / 2, 1500, 10, &flow);

  const TCPRateEstimator* estimator = flow.EstimatorOrNull();
  ASSERT_DOUBLE_EQ(
      1500.0, estimator->GetBytesPerSecEstimate(kInitTimestamp + kMillion));

  UpdateTcpIp(kInitTimestamp + 3 * kMillion / 2, 0, 1510, &flow);

  // No change in Bps -- the second second has not ended yet
  ASSERT_EQ(
      1500,
      estimator->GetBytesPerSecEstimate(kInitTimestamp + 3 * kMillion / 2));

  // Next second -- the estimate should drop
  ASSERT_GT(1500,
            estimator->GetBytesPerSecEstimate(kInitTimestamp + 2 * kMillion));
}

}  // namespace test
}  // namespace flowparser
