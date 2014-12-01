#ifndef FLOWPARSER_EXAMPLE_BINNER_H
#define FLOWPARSER_EXAMPLE_BINNER_H

#include <array>
#include <cstdint>
#include <map>
#include <unordered_set>
#include <memory>
#include <vector>

#include "../common.h"
#include "../flows.h"
#include "../flowparser.h"
#include "binner.pb.h"

namespace flowparser {
class FlowKey;
} /* namespace flowparser */

namespace flowparser {
namespace example {
namespace binner {

// A bin is a map from the bin number to the total metric within the bin. The
// metric that is binned must be additive and integral.
typedef std::map<uint64_t, uint64_t> Bin;

// The array of bins.
typedef std::array<Bin, FlowType_ARRAYSIZE> BinArray;

// Port numbers
static constexpr uint16_t kHTTPPort = 80;
static constexpr uint16_t kHTTPSPort = 443;
static constexpr uint16_t kFTPPort = 21;
static constexpr uint16_t kBTLowPort = 6881;
static constexpr uint16_t kBTHighPort = 6999;

// The state associated with a BinPack. This class stores the actual bins,
// performs binning and knows how to serialize itself to a BinPack protobuf.
class BinPackValue {
 public:
  virtual ~BinPackValue() {
  }

  // Will classify the flow and bin its packets into 'bins'
  void BinFlow(const FlowKey& key, const Flow& flow);

  // Will serialize the current state of the bins to a BinPack protobuf.
  void ToBinPack(BinPack* bin_pack);

  bool NeedToUpdateFirstBinEdge() {
    return first_bin_edge_ == 0;
  }

  void UpdateFirstBinEdge(uint64_t first_bin_edge) {
    first_bin_edge_ = first_bin_edge;
  }

 protected:
  BinPackValue(BinPack::Type type, uint64_t bin_width,
               uint64_t small_flows_threshold)
      : type_(type),
        bin_width_(bin_width),
        small_flows_threshold_(small_flows_threshold),
        first_bin_edge_(0) {
  }

  // Given a FlowKey and a Flow return the type of the flow.
  FlowType ClassifyFlow(const FlowKey& key, const Flow& flow);

  // Implementations should override to perform actual binning.
  virtual void ExtractMetricAndBin(const FlowKey& key, const Flow& flow,
                                   FlowType type) = 0;

  uint64_t GetBinNum(uint64_t timestamp) {
    if (first_bin_edge_ > timestamp) {
      std::cout << "Bad timestamp, will map to bin 0\n";
      return 0;
    }

    uint64_t offset = timestamp - first_bin_edge_;
    return offset / bin_width_;
  }

  void AddToBin(uint64_t timestamp, uint64_t metric, FlowType type);

 private:
  // Makes sure that all elements from the BinArray have the same number of bins
  // with the same edges.
  void AddEmptyBins();

  // What this BinPack's type is.
  const BinPack::Type type_;

  // The width of each bin in timestamp units.
  uint64_t bin_width_;

  // What should the threshold be for small flows. This is not part of the
  // per-BinPack config, but is defined in the more global BinnerConfig.
  const uint64_t small_flows_threshold_;

  // The edge of the first bin, in timestamp units.
  uint64_t first_bin_edge_;

  // The bins. This is just a fixed array.
  BinArray bins_;

  DISALLOW_COPY_AND_ASSIGN(BinPackValue);
};

class SizeBytesBinPack : public BinPackValue {
 public:
  SizeBytesBinPack(uint64_t bin_width, uint64_t small_flows_threshold)
      : BinPackValue(BinPack::SIZES_BYTES, bin_width, small_flows_threshold) {
  }

 protected:
  void ExtractMetricAndBin(const FlowKey& key, const Flow& flow, FlowType type)
      override {
    FlowIterator it(flow);
    IPHeader ip_header;
    while (it.Next(&ip_header)) {
      uint64_t timestamp = ip_header.timestamp;
      uint16_t pkt_size = ip_header.length;

      AddToBin(timestamp, pkt_size, type);
      AddToBin(timestamp, pkt_size, FlowType::TOTAL);
    }
  }
};

class SizePktsBinPack : public BinPackValue {
 public:
  SizePktsBinPack(uint64_t bin_width, uint64_t small_flows_threshold)
      : BinPackValue(BinPack::SIZES_PKTS, bin_width, small_flows_threshold) {
  }

 protected:
  void ExtractMetricAndBin(const FlowKey& key, const Flow& flow, FlowType type)
      override {
    FlowIterator it(flow);
    IPHeader ip_header;
    while (it.Next(&ip_header)) {
      uint64_t timestamp = ip_header.timestamp;

      AddToBin(timestamp, 1, type);
      AddToBin(timestamp, 1, FlowType::TOTAL);
    }
  }
};

class NewFlowsBinPack : public BinPackValue {
 public:
  NewFlowsBinPack(uint64_t bin_width, uint64_t small_flows_threshold)
      : BinPackValue(BinPack::NEW_FLOWS, bin_width, small_flows_threshold) {
  }

 protected:
  void ExtractMetricAndBin(const FlowKey& key, const Flow& flow, FlowType type)
      override {
    FlowIterator it(flow);
    IPHeader ip_header;
    it.Next(&ip_header);
    uint64_t timestamp = ip_header.timestamp;

    AddToBin(timestamp, 1, type);
    AddToBin(timestamp, 1, FlowType::TOTAL);
  }
};

class EndTimestampBinPack : public BinPackValue {
 public:
  EndTimestampBinPack(uint64_t bin_width, uint64_t small_flows_threshold)
      : BinPackValue(BinPack::END_TIMESTAMP, bin_width, small_flows_threshold) {
  }

 protected:
  void ExtractMetricAndBin(const FlowKey& key, const Flow& flow, FlowType type)
      override {
    FlowIterator it(flow);
    IPHeader ip_header;
    uint64_t last_timestamp;

    while (it.Next(&ip_header)) {
      last_timestamp = ip_header.timestamp;
    }

    AddToBin(last_timestamp, 1, type);
    AddToBin(last_timestamp, 1, FlowType::TOTAL);
  }
};

class ActiveFlowsBinPack : public BinPackValue {
 public:
  ActiveFlowsBinPack(uint64_t bin_width, uint64_t small_flows_threshold)
      : BinPackValue(BinPack::ACTIVE_FLOWS, bin_width, small_flows_threshold) {
  }

 protected:
  void ExtractMetricAndBin(const FlowKey& key, const Flow& flow, FlowType type)
      override {
    // We will assume the flows do not repeat and the keys passed to this
    // function are unique. If we run out of memory and evict a flow which has
    // not actually terminated this will not be the case.
    static uint32_t key_id = 0;

    FlowIterator it(flow);
    IPHeader ip_header;
    while (it.Next(&ip_header)) {
      uint64_t timestamp = ip_header.timestamp;

      uint64_t bin_num = GetBinNum(timestamp);

      auto& active_flows_set = active_bin_array_[type][bin_num];
      bool inserted = active_flows_set.insert(key_id).second;

      if (inserted) {
        AddToBin(timestamp, 1, type);
        AddToBin(timestamp, 1, FlowType::TOTAL);
      }
    }

    key_id++;
  }

 private:
  typedef std::map<uint64_t, std::set<uint32_t>> ActiveBins;
  std::array<ActiveBins, FlowType_ARRAYSIZE> active_bin_array_;
};

class Binner {
 public:
  Binner(const BinnerConfig& config)
      : config_(config) {
  }

  // Initializes bin packs from the initial config. Should be called before
  // calling RunTrace.
  Status InitBinPacks();

  // Will construct a new FlowParser, process the file in the config and create
  // and populate a new BinnedFlows instance.
  Status RunTrace();

  // Serializes this binner and all its bin packs into a BinnedFlows protobuf.
  void ToBinnedFlows(BinnedFlows* binned_flows) {
    for (const auto& bin_pack : bin_packs_) {
      BinPack* bin_pack_protobuf = binned_flows->add_bin_packs();
      bin_pack->ToBinPack(bin_pack_protobuf);
    }
  }

 private:

  void HandleFlow(const FlowKey& key, const Flow& flow,
                  const flowparser::FlowParser& flow_parser) {
    for (const auto& bin_pack : bin_packs_) {
      if (bin_pack->NeedToUpdateFirstBinEdge()) {
        bin_pack->UpdateFirstBinEdge(flow_parser.first_rx());
      }

      bin_pack->BinFlow(key, flow);
    }
  }

  // The initial config.
  const BinnerConfig config_;

  // The bin packs. All flows are handed to all bin packs in order.
  std::vector<std::unique_ptr<BinPackValue>> bin_packs_;

  DISALLOW_COPY_AND_ASSIGN(Binner);
};

}
}
}

#endif  /* FLOWPARSER_EXAMPLE_BINNER_H */
