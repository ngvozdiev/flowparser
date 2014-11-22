#include "gtest/gtest.h"
#include "parser.h"

#include <map>

#include "common_test.h"

namespace flowparser {
namespace test {

// A fixture that sets up a single TCP parser. It also creates a random IP
// header with src 1 and dst 2, and a random TCP header with src port 5 and
// dst port 6.
class ParserTestFixtureBase : public ::testing::Test {
 protected:
  ParserTestFixtureBase(uint64_t timeout, uint64_t soft_mem_limit,
                        uint64_t hard_mem_limit)
      : pkt_gen_(1),
        fp_([this](const FlowKey& key, std::unique_ptr<TCPFlow> flow)
        { flows_.push_back( {key, std::move(flow)});},
            timeout, soft_mem_limit, hard_mem_limit),
        pcap_ip_hdr_(pkt_gen_.GenerateIpHeader(1, 2)),
        pcap_tcp_hdr_(pkt_gen_.GenerateTCPHeader(5, 6)) {
  }

  std::vector<std::pair<FlowKey, std::unique_ptr<TCPFlow>>>flows_;
  TCPPktGen pkt_gen_;
  TCPFlowParser fp_;

  pcap::SniffIp pcap_ip_hdr_;
  pcap::SniffTcp pcap_tcp_hdr_;
};

// A parser with no memory limits and a timeout ot 1000.
class ParserTestFixture : public ParserTestFixtureBase {
 protected:
  ParserTestFixture()
      : ParserTestFixtureBase(1000, std::numeric_limits<uint64_t>::max(),
                              std::numeric_limits<uint64_t>::max()) {
  }
};

// A parser with memory limits set to 0.
class NoMemParserTestFixture : public ParserTestFixtureBase {
 protected:
  NoMemParserTestFixture()
      : ParserTestFixtureBase(1000, 0, 0) {
  }
};

// A parser with memory limits set to [3/2 * sizeof(TCPFlow), inf].
class LittleMemParserTestFixture : public ParserTestFixtureBase {
 protected:
  LittleMemParserTestFixture()
      : ParserTestFixtureBase(1000, sizeof(TCPFlow) + sizeof(TCPFlow) / 2,
                              std::numeric_limits<uint64_t>::max()) {
  }
};

TEST_F(ParserTestFixture, Init) {
  fp_.CollectFlows();
  fp_.CollectAllFlows();

  ASSERT_TRUE(flows_.empty());
}

TEST_F(ParserTestFixture, KeyToString) {
  FlowKey key(pcap_ip_hdr_, pcap_tcp_hdr_);

  ASSERT_EQ("(src='0.0.0.1', dst='0.0.0.2', src_port=5, dst_port=6)",
            key.ToString());
}

TEST_F(ParserTestFixture, SinglePacket) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  // The single flow still has not expired.
  fp_.CollectFlows();
  ASSERT_TRUE(flows_.empty());

  fp_.CollectAllFlows();
  ASSERT_EQ(1, flows_.size());

  const FlowKey& key = flows_.at(0).first;
  ASSERT_EQ(1, key.src());
  ASSERT_EQ(2, key.dst());
  ASSERT_EQ(5, key.src_port());
  ASSERT_EQ(6, key.dst_port());
}

TEST_F(NoMemParserTestFixture, SinglePacket) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  // The single flow should get collected now, since there is no memory for it.
  fp_.CollectFlows();
  ASSERT_EQ(1, flows_.size());

  const FlowKey& key = flows_.at(0).first;
  ASSERT_EQ(1, key.src());
  ASSERT_EQ(2, key.dst());
  ASSERT_EQ(5, key.src_port());
  ASSERT_EQ(6, key.dst_port());
}

TEST_F(ParserTestFixture, TwoPacketsSameFlow) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  // The single flow still has not expired.
  fp_.CollectFlows();
  ASSERT_TRUE(flows_.empty());

  fp_.CollectAllFlows();
  ASSERT_EQ(1, flows_.size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffIpSrc) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  // The single flow still has not expired.
  fp_.CollectFlows();
  ASSERT_TRUE(flows_.empty());

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(LittleMemParserTestFixture, TwoFlows) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  // One of the two flows should get collected now, as there is only room for
  // one TCPFLow.
  fp_.CollectFlows();
  ASSERT_EQ(1, flows_.size());
  ASSERT_EQ(1, flows_.at(0).first.src());

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffIpDst) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_dst.s_addr = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffSrcPort) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_tcp_hdr_.th_sport = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffDstPort) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_tcp_hdr_.th_dport = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(ParserTestFixture, NonIncrementingTime) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  ASSERT_FALSE(fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 8).ok());
}

TEST_F(ParserTestFixture, SameTime) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  ASSERT_TRUE(fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10).ok());
}

TEST_F(ParserTestFixture, TwoPacketsFastCollection) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 1010);

  // The packets are from the same flow - even though the first one would have
  // expired, the second one "freshens" the flow and it is not collected.
  fp_.CollectFlows();
  ASSERT_TRUE(flows_.empty());

  fp_.CollectAllFlows();
  ASSERT_EQ(1, flows_.size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowsFastCollection) {
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_tcp_hdr_.th_dport = 10;
  fp_.HandlePkt(pcap_ip_hdr_, pcap_tcp_hdr_, 1010);

  // The packets are from different flows - the original flow should get
  // collected as the timeout is 1000.
  fp_.CollectFlows();
  ASSERT_EQ(1, flows_.size());

  // Check that the correct flow was collected.
  const FlowKey& key = flows_.at(0).first;
  ASSERT_EQ(1, key.src());
  ASSERT_EQ(2, key.dst());
  ASSERT_EQ(5, key.src_port());
  ASSERT_EQ(6, key.dst_port());

  fp_.CollectAllFlows();
  ASSERT_EQ(2, flows_.size());
}

TEST_F(ParserTestFixture, 1MPkts) {
  typedef std::pair<std::pair<uint32_t, uint32_t>, std::pair<uint16_t, uint16_t>> TestKey;
  typedef std::vector<std::pair<pcap::SniffIp, pcap::SniffTcp>> TestValue;
  std::map<TestKey, TestValue> model;

  uint64_t time = 0;

  // Will add about 1M packets iterating between 400 combinations of src, dst
  // sport and dport.
  for (size_t count = 0; count < 2500; count++) {
    for (size_t src = 0; src < 5; src++) {
      for (size_t dst = 0; dst < 5; dst++) {
        for (size_t src_port = 0; src_port < 5; src_port++) {
          for (size_t dst_port = 0; dst_port < 5; dst_port++) {
            if (src != dst && src_port != dst_port) {
              pcap::SniffIp ip_header = pkt_gen_.GenerateIpHeader(src, dst);
              pcap::SniffTcp tcp_header = pkt_gen_.GenerateTCPHeader(src_port,
                                                                     dst_port);
              model[ { { src, dst }, { src_port, dst_port } }].push_back( {
                  ip_header, tcp_header });

              ASSERT_TRUE(fp_.HandlePkt(ip_header, tcp_header, time).ok());
            }
          }
        }
      }
    }

    time += 100;
  }

  // No flows should be collected at this point.
  fp_.CollectFlows();
  ASSERT_EQ(0, flows_.size());

  fp_.CollectAllFlows();
  ASSERT_EQ(400, flows_.size());

  for (const auto& flow : flows_) {
    const FlowKey& key = flow.first;

    TestKey test_key = { { key.src(), key.dst() }, { key.src_port(), key
        .dst_port() } };

    // The test key should exist in the model map
    ASSERT_TRUE(model.count(test_key));

    const TestValue& test_value = model[test_key];

    TCPFlowIterator it(*flow.second);

    IPHeader ip_header;
    TCPHeader tcp_header;
    size_t count = 0;
    while (it.Next(&ip_header, &tcp_header)) {
      AssertIPHeadersEqual(test_value[count].first, count * 100, ip_header);
      AssertTCPHeadersEqual(test_value[count].second, tcp_header);

      count++;
    }
  }
}

}
}
