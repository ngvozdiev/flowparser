#include "gtest/gtest.h"
#include "parser.h"

#include <map>
#include <thread>

#include "common_test.h"

namespace flowparser {
namespace test {

// A fixture that sets up a single TCP parser. It also creates a random IP
// header with src 1 and dst 2, and a random TCP header with src port 5 and
// dst port 6.
class ParserTestFixtureBase : public ::testing::Test {
 protected:
  static ParserConfig GetConfig(uint64_t mem_limit) {
    ParserConfig cfg;
    cfg.set_soft_mem_limit(mem_limit);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_IP_ID);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_IP_LEN);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_IP_TTL);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_TCP_WIN);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_TCP_SEQ);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_TCP_ACK);
    cfg.mutable_flow_config()->SetField(FlowConfig::HF_TCP_FLAGS);

    return cfg;
  }

  ParserTestFixtureBase(uint64_t mem_limit)
      : queue_(std::make_shared<Parser::FlowQueue>()),
        pkt_gen_(1),
        parser_config_(GetConfig(mem_limit)),
        parser_(parser_config_, queue_),
        pcap_ip_hdr_(pkt_gen_.GenerateIpHeader(1, 2)),
        pcap_tcp_hdr_(pkt_gen_.GenerateTCPHeader(5, 6)) {
  }

  std::vector<std::unique_ptr<Flow>> DrainQueue() {
    std::vector<std::unique_ptr<Flow>> return_vector;
    queue_->Close();

    std::unique_ptr<Flow> flow_ptr;
    while (true) {
      flow_ptr = std::move(queue_->ConsumeOrBlock());
      if (!flow_ptr.get()) {
        break;
      }

      return_vector.push_back(std::move(flow_ptr));
    }

    return return_vector;
  }

  std::shared_ptr<Parser::FlowQueue> queue_;
  TCPPktGen pkt_gen_;
  ParserConfig parser_config_;
  Parser parser_;

  pcap::SniffIp pcap_ip_hdr_;
  pcap::SniffTcp pcap_tcp_hdr_;
};

// A parser with no memory limit.
class ParserTestFixture : public ParserTestFixtureBase {
 protected:
  ParserTestFixture()
      : ParserTestFixtureBase(std::numeric_limits<uint64_t>::max()) {
  }
};

// A parser with memory limit set to 0.
class NoMemParserTestFixture : public ParserTestFixtureBase {
 protected:
  NoMemParserTestFixture()
      : ParserTestFixtureBase(0) {
  }
};

// A parser with memory limit set to 3/2 * sizeof(TCPFlow).
class LittleMemParserTestFixture : public ParserTestFixtureBase {
 protected:
  LittleMemParserTestFixture()
      : ParserTestFixtureBase(sizeof(Flow) + sizeof(Flow) / 2) {
  }
};

TEST_F(ParserTestFixture, Init) {
  parser_.CollectAllFlows();

  ASSERT_TRUE(queue_->empty());
  ASSERT_TRUE(DrainQueue().empty());
}

TEST_F(ParserTestFixture, KeyToString) {
  FlowKey key(pcap_ip_hdr_, htons(5), htons(6));

  ASSERT_EQ("(src='0.0.0.1', dst='0.0.0.2', src_port=5, dst_port=6, proto=0)",
            key.ToString());
}

TEST_F(ParserTestFixture, SinglePacket) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  parser_.CollectAllFlows();
  auto flows = DrainQueue();
  ASSERT_EQ(1, flows.size());

  const FlowKey& key = flows.at(0)->key();
  ASSERT_EQ(1, key.src());
  ASSERT_EQ(2, key.dst());
  ASSERT_EQ(5, key.src_port());
  ASSERT_EQ(6, key.dst_port());
}

TEST_F(NoMemParserTestFixture, SinglePacket) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  // The single flow should get collected now, since there is no memory for it.
  ASSERT_EQ(1, queue_->size());
  auto flows = DrainQueue();
  ASSERT_EQ(1, flows.size());

  const FlowKey& key = flows.at(0)->key();
  ASSERT_EQ(1, key.src());
  ASSERT_EQ(2, key.dst());
  ASSERT_EQ(5, key.src_port());
  ASSERT_EQ(6, key.dst_port());
}

TEST_F(ParserTestFixture, TwoPacketsSameFlow) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  parser_.CollectAllFlows();
  ASSERT_EQ(1, queue_->size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffIpSrc) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  parser_.CollectAllFlows();
  ASSERT_EQ(2, queue_->size());
}

TEST_F(LittleMemParserTestFixture, TwoFlows) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  // One of the two flows should get collected now, as there is only room for
  // one Flow.
  ASSERT_EQ(1, queue_->size());
  auto flow_ptr = queue_->ConsumeOrBlock();

  ASSERT_EQ(1, flow_ptr->key().src());

  parser_.CollectAllFlows();
  ASSERT_EQ(1, queue_->size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffIpDst) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_dst.s_addr = 10;
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  parser_.CollectAllFlows();
  ASSERT_EQ(2, queue_->size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffSrcPort) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_tcp_hdr_.th_sport = 10;
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  parser_.CollectAllFlows();
  ASSERT_EQ(2, queue_->size());
}

TEST_F(ParserTestFixture, TwoPacketsDiffFlowDiffDstPort) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_tcp_hdr_.th_dport = 10;
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 910);

  parser_.CollectAllFlows();
  ASSERT_EQ(2, queue_->size());
}

TEST_F(ParserTestFixture, NonIncrementingTime) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;
  ASSERT_ANY_THROW(parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 8));
}

TEST_F(ParserTestFixture, SameTime) {
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);

  pcap_ip_hdr_.ip_src.s_addr = 10;

  // This should be ok
  parser_.TCPIpRx(pcap_ip_hdr_, pcap_tcp_hdr_, 10);
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

              parser_.TCPIpRx(ip_header, tcp_header, time);
            }
          }
        }
      }
    }

    time += 100;
  }

  std::vector<std::unique_ptr<Flow>> flows;
  std::thread th([this, &flows] {
    while (true) {
      std::unique_ptr<Flow> flow_ptr = queue_->ConsumeOrBlock();
      if (!flow_ptr) {
        break;
      }

      flows.push_back(std::move(flow_ptr));
    }
  });

  parser_.CollectAllFlows();
  th.join();

  ASSERT_EQ(400, flows.size());

  for (const auto& flow : flows) {
    const FlowKey& key = flow->key();

    TestKey test_key = { { key.src(), key.dst() }, { key.src_port(), key
        .dst_port() } };

    // The test key should exist in the model map
    ASSERT_TRUE(model.count(test_key));

    const TestValue& test_value = model[test_key];

    FlowIterator it(*flow);

    size_t count = 0;
    const TrackedFields* fields;
    while ((fields = it.NextOrNull()) != nullptr) {
      AssertIPHeadersEqual(test_value[count].first, count * 100, *fields);
      AssertTCPHeadersEqual(test_value[count].second, *fields);

      count++;
    }
  }
}

}
}
