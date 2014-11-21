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
  SummaryValue(uint32_t pkts, uint64_t duration)
      : pkts_total(pkts),
        duration(duration) {
  }

  uint32_t pkts_total;
  uint64_t duration;
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

    // Addresses are in host order already
    uint32_t src = strtoll(items[0].c_str(), nullptr, 10);
    uint32_t dst = strtoll(items[1].c_str(), nullptr, 10);

    uint32_t pkts = strtoll(items[2].c_str(), nullptr, 10);
    uint32_t duration = strtoll(items[4].c_str(), nullptr, 10);

    if (src > dst) {
      std::swap(src, dst);
    }

    map->insert( { { src, dst }, SummaryValue(pkts, duration) });
  }
}

static void AddToSummary(const FlowKey& key, const FlowInfo& info,
                         SummaryMap* map) {
  uint32_t src = key.src();
  uint32_t dst = key.dst();

  if (src > dst) {
    std::swap(src, dst);
  }

  std::pair<uint32_t, uint32_t> summary_key = std::make_pair(src, dst);

  SummaryValue* sv;
  auto it = map->find( { src, dst });
  if (it == map->end()) {
    sv = &map->insert( { summary_key, SummaryValue(0, 0) }).first->second;
  } else {
    sv = &it->second;
  }

  // The timestamps in WireShark's summary are only precise up to 4 decimals
  // after the second
  sv->duration = ((info.last_rx - info.first_rx) / 100) * 100;
  sv->pkts_total += info.size_pkts;
}

static void CompareSummaryMaps(const SummaryMap& one, const SummaryMap& two) {
  for (const auto& key_and_value : one) {
    ASSERT_TRUE(two.count(key_and_value.first))
        << " Missing key " << key_and_value.first.first << " -> "
        << key_and_value.first.second;

    const SummaryValue& value = key_and_value.second;
    const SummaryValue& other_value = two.find(key_and_value.first)->second;

    std::cout << IPToString(htonl(key_and_value.first.first)) << " -> " << IPToString(htonl(key_and_value.first.second)) << "duration model " << value.duration << " vs " << other_value.duration << " src " << key_and_value.first.first << "\n";
    ASSERT_EQ(value.pkts_total, other_value.pkts_total) << "Pkts mismatch";
    ASSERT_EQ(value.duration, other_value.duration) << "Duration mismatch";
  }
}

TEST(FlowParser, EndToEnd) {
  SummaryMap model_map;
  SummaryMap map;

  ParseSummary("test_data/summary.csv", &model_map);

  FlowParserConfig cfg;
  cfg.OfflineTrace("test_data/output_dump");
  cfg.TCPCallback([&map](const FlowKey& key, unique_ptr<TCPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg.UDPCallback([&map](const FlowKey& key, unique_ptr<UDPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg.ICMPCallback([&map](const FlowKey& key, unique_ptr<ICMPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});
  cfg.ESPCallback([&map](const FlowKey& key, unique_ptr<ESPFlow> flow) {
    AddToSummary(key, flow->GetInfo(), &map);});

  FlowParser fp(cfg);
  ASSERT_TRUE(fp.RunTrace().ok());

  CompareSummaryMaps(model_map, map);
}

}
}
