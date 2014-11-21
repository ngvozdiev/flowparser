// This file contains only various end-to-end test of the tool.

#include <random>
#include <fstream>
#include <streambuf>
#include <map>

#include "gtest/gtest.h"
#include "flowparser.h"

namespace flowparser {
namespace test {

// (src_ip, dst_ip) -> total num of packets
typedef std::map<std::pair<uint32_t, uint32_t>, uint32_t> SummaryMap;

using std::string;

static void Split(const string& string_to_split, const string& delim,
                  std::vector<string>* elems) {
  size_t start = 0;
  size_t end = string_to_split.find(delim);
  while (end != std::string::npos) {
    elems->push_back(string_to_split.substr(start, end - start));
    start = end + delim.length();
    end = string_to_split.find(delim, start);
  }

  elems->push_back(string_to_split.substr(start, end));
}

static void ParseSummary(const string filename, SummaryMap* map) {
  std::ifstream in(filename);
  if (!in) {
    ASSERT_TRUE(false)<< "Unable to open summary file";
  }

  for (string line; getline(in, line);) {
    string inner = line.substr(0, line.size() - 2);

    std::vector<string> items;
    Split(inner, ",", &items);

    // Addresses are in host order already
    uint32_t src = strtoll(items[0].c_str(), nullptr, 10);
    uint32_t dst = strtoll(items[1].c_str(), nullptr, 10);
    uint32_t pkts = strtoll(items[2].c_str(), nullptr, 10);

    if (src > dst) {
      std::swap(src, dst);
    }

    map->insert( { { src, dst }, pkts });
  }
}

static void AddToSummary(const FlowKey& key, const FlowInfo& info,
                         SummaryMap* map) {
  uint32_t src = key.src();
  uint32_t dst = key.dst();

  if (src > dst) {
    std::swap(src, dst);
  }

  (*map)[ { src, dst }] += info.size_pkts;
}

static size_t CountPkts(const Flow& flow) {
  FlowIterator it(flow);
  IPHeader dummy;

  size_t count = 0;
  while (it.Next(&dummy)) {
    count++;
  }

  return count;
}

// A fixture that sets up a FlowParserConfig for tests.
class FlowParserFixture : public ::testing::Test {
 protected:
  void SetUp() override {
    cfg_.OfflineTrace("test_data/output_dump");

    cfg_.BadStatusCallback(
        [this](Status status) {bad_statuses_.push_back(status);});
    cfg_.InfoCallback([](const string&) {});
  }

  FlowParserConfig cfg_;
  std::vector<Status> bad_statuses_;
};

// Tests that opening a bad file fails.
TEST_F(FlowParserFixture, BadFileOpen) {
  cfg_.OfflineTrace("test_data/some_missing_dummy_file");

  FlowParser fp(cfg_);
  ASSERT_FALSE(fp.RunTrace().ok());
}

// In test_data/ there is a pcap file with 10K anonymized packets from a
// real-world trace. There is also a statistics file which lists the
// conversations as reported by WireShark. In this test the file will be parsed
// with FlowParser and the results compared to the WireShark results.
TEST_F(FlowParserFixture, EndToEnd) {
  SummaryMap model_map;
  SummaryMap map;

  ParseSummary("test_data/summary.csv", &model_map);

  cfg_.TCPCallback([&map](const FlowKey& key, unique_ptr<TCPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg_.UDPCallback([&map](const FlowKey& key, unique_ptr<UDPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg_.ICMPCallback([&map](const FlowKey& key, unique_ptr<ICMPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg_.ESPCallback([&map](const FlowKey& key, unique_ptr<ESPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});

  FlowParser fp(cfg_);
  ASSERT_TRUE(fp.RunTrace().ok());
  ASSERT_TRUE(bad_statuses_.empty());

  ASSERT_EQ(model_map, map);
}

// Tests the total number of packets as seen by iterators.
TEST_F(FlowParserFixture, IteratorPacketCount) {
  size_t count = 0;

  cfg_.TCPCallback([&count](const FlowKey& key, unique_ptr<TCPFlow> flow) {
    count += CountPkts(*flow);});
  cfg_.UDPCallback([&count](const FlowKey& key, unique_ptr<UDPFlow> flow) {
    count += CountPkts(*flow);});
  cfg_.ICMPCallback([&count](const FlowKey& key, unique_ptr<ICMPFlow> flow) {
    count += CountPkts(*flow);});
  cfg_.ESPCallback([&count](const FlowKey& key, unique_ptr<ESPFlow> flow) {
    count += CountPkts(*flow);});

  FlowParser fp(cfg_);
  ASSERT_TRUE(fp.RunTrace().ok());
  ASSERT_TRUE(bad_statuses_.empty());

  // The trace also has 24 IPv6 packets that we are not seeing - the default
  // BPF filter is "ip"
  ASSERT_EQ(9976, count);
}

// Reconstruct the headers of a single TCP flow from the trace
TEST_F(FlowParserFixture, SingleTCPFlow) {
  // The flow has 10 packets - here are the model values from the header fields.
  std::vector<uint16_t> len_model = { 1500, 1500, 1500, 1500, 1500, 1500, 1500,
      1500, 684, 652 };
  std::vector<uint16_t> id_model = { 42057, 42058, 42059, 42060, 42061, 42062,
      42063, 42064, 42065, 42066 };
  std::vector<uint32_t> seq_model = { 1, 1449, 2897, 4345, 5793, 7241, 8689,
      10137, 11585, 12217 };
  uint32_t seq_relative_to = 2585150390;
  std::vector<uint8_t> flags_model = { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
      0x10, 0x18, 0x18 };
  std::vector<uint32_t> ack_model(10, 438222783);
  std::vector<uint8_t> ttl_model(10, 89);
  std::vector<uint16_t> win_model(10, 404);

  // The flow is from 181.175.235.116:80 -> 71.126.3.230:65470
  pcap::SniffIp ip;
  inet_aton("181.175.235.116", &ip.ip_src);
  inet_aton("71.126.3.230", &ip.ip_dst);

  pcap::SniffTcp tcp;
  tcp.source = htons(80);
  tcp.dest = htons(65470);

  FlowKey key_model(ip, tcp);

  std::vector<IPHeader> ip_headers;
  std::vector<TCPHeader> tcp_headers;

  cfg_.TCPCallback([&key_model, &ip_headers, &tcp_headers]
  (const FlowKey& key, unique_ptr<TCPFlow> flow) {
    if (key == key_model) {
      TCPFlowIterator it(*flow);

      IPHeader ip_header;
      TCPHeader tcp_header;
      while (it.Next(&ip_header, &tcp_header)) {
        ip_headers.push_back(ip_header);
        tcp_headers.push_back(tcp_header);
      }
    }
  });

  FlowParser fp(cfg_);
  ASSERT_TRUE(fp.RunTrace().ok());
  ASSERT_TRUE(bad_statuses_.empty());

  ASSERT_EQ(10, ip_headers.size());

  for (size_t i = 0; i < 10; ++i) {
    ASSERT_EQ(len_model[i], ip_headers[i].length);
    ASSERT_EQ(id_model[i], ip_headers[i].id);
    ASSERT_EQ(ttl_model[i], ip_headers[i].ttl);

    ASSERT_EQ(seq_relative_to + seq_model[i], tcp_headers[i].seq);
    ASSERT_EQ(ack_model[i], tcp_headers[i].ack);
    ASSERT_EQ(win_model[i], tcp_headers[i].win);
    ASSERT_EQ(flags_model[i], tcp_headers[i].flags);
  }
}

}
}
