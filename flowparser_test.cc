// This file contains only one end-to-end test of the tool. In test_data/ there
// is a pcap file with 100K anonymized packets from a real-world trace. There is
// also a statistics file which lists the conversations as reported by WireShark
// In this test the file will be parsed with FlowParser and the results compared
// to the WireShark results.

#include <random>
#include <fstream>
#include <streambuf>
#include <map>

#include "gtest/gtest.h"
#include "flowparser.h"

namespace flowparser {
namespace test {

struct SummaryValue {
  SummaryValue(uint32_t pkts, uint32_t bytes)
      : pkts_total(pkts),
        bytes_total(bytes) {
  }

  uint32_t pkts_total;
  uint32_t bytes_total;
};

typedef std::map<std::pair<uint32_t, uint32_t>, SummaryValue> SummaryMap;

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

    uint32_t src = ntohl(strtoll(items[0].c_str(), nullptr, 10));
    uint32_t dst = ntohl(strtoll(items[1].c_str(), nullptr, 10));
    uint32_t pkts = strtoll(items[2].c_str(), nullptr, 10);
    uint32_t bytes = strtoll(items[3].c_str(), nullptr, 10);

    if (src > dst) {
      std::swap(src, dst);
    }

    (*map)[ {src, dst}] = {pkts, bytes};
  }
}

static void AddToSummary(const FlowKey& key, const FlowInfo& info,
                         SummaryMap* map) {
  uint32_t src = key.src();
  uint32_t dst = key.dst();

  if (src > dst) {
    std::swap(src, dst);
  }

  it = map->find({ src, dst });

  SummaryValue& sv = (*map)[ { src, dst }];
  sv.bytes_total += info.size_bytes;
  sv.pkts_total += info.size_pkts;
}

TEST(FlowParser, EndToEnd) {
  SummaryMap model_map;
  SummaryMap map;

  ParseSummary("test_data/summary.csv.new", &model_map);

  FlowParserConfig cfg;
  cfg.OfflineTrace("test_data/output_dump");

  FlowParser fp(
      cfg,
      [&map](const FlowKey& key, unique_ptr<TCPFlow> flow) {AddToSummary(key, flow->GetInfo(), &map);},
      [&map](const FlowKey& key, unique_ptr<UDPFlow> flow) {AddToSummary(key, flow->GetInfo(), &map);});
}

}
}
