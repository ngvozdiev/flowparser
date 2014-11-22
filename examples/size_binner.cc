#include <map>
#include <array>
#include <fstream>

#include "../flowparser.h"

namespace example {

using flowparser::FlowParserConfig;
using flowparser::FlowKey;
using flowparser::Flow;
using flowparser::IPHeader;
using flowparser::FlowIterator;

// A bin is a map from the start of the edge of th bin (in timestamp units) to
// the total size of packets within the bin.
typedef std::map<uint64_t, uint64_t> Bin;

// Indices into the bin array.
enum BinIndex {
  TOTAL = 0,
  SMALL,
  UDP,
  WWW,
  HTTPS,
  OTHER,
  BIN_COUNT
};

// The array of bins.
typedef std::array<Bin, BinIndex::BIN_COUNT> BinArray;

// The width of the bin, in timestamp timeunits (microseconds)
static constexpr uint64_t kBinWidth = 1000000;

// The limit below which a flow is considered small (bytes)
static constexpr uint64_t kSmallFlowLimit = 10000;

// Port numbers
static constexpr uint16_t kHTTPPort = 80;
static constexpr uint16_t kHTTPSPort = 443;

// Will classify the flow and bin its packets into 'bins'
static void DoBin(const FlowKey& key, uint64_t first_bin_start,
                  const Flow& flow, BinArray* bins) {
  bool small_flow = flow.GetInfo().size_bytes < kSmallFlowLimit;
  bool udp_flow = flow.type() == flowparser::UDP;
  bool www_flow = (flow.type() == flowparser::TCP)
      && (key.src_port() == kHTTPPort || key.dst_port() == kHTTPPort);
  bool wwws_flow = (flow.type() == flowparser::TCP)
      && (key.src_port() == kHTTPSPort || key.dst_port() == kHTTPSPort);

  FlowIterator it(flow);
  IPHeader ip_header;
  while (it.Next(&ip_header)) {
    uint64_t timestamp = ip_header.timestamp;
    uint16_t pkt_size = ip_header.length;

    if (timestamp < first_bin_start) {
      return;  // Should not happen.
    }

    uint64_t offset = timestamp - first_bin_start;

    uint64_t bin_num = offset / kBinWidth;
    uint64_t bin_start = kBinWidth * bin_num;

    BinArray& bin_array = *bins;

    bin_array[BinIndex::TOTAL][bin_start] += pkt_size;
    if (small_flow) {
      bin_array[BinIndex::SMALL][bin_start] += pkt_size;
    } else if (udp_flow) {
      bin_array[BinIndex::UDP][bin_start] += pkt_size;
    } else if (www_flow) {
      bin_array[BinIndex::WWW][bin_start] += pkt_size;
    } else if (wwws_flow) {
      bin_array[BinIndex::HTTPS][bin_start] += pkt_size;
    } else {
      bin_array[BinIndex::OTHER][bin_start] += pkt_size;
    }
  }
}

// Makes sure that all elements from the BinArray have the same number of bins
// with the same edges.
static void AddEmptyBins(BinArray* bins, uint64_t first_bin_start) {
  size_t max_num_bins = 0;
  for (size_t i = 0; i < BinIndex::BIN_COUNT; ++i) {
    size_t bin_count = (*bins)[i].size();
    if (bin_count > max_num_bins) {
      max_num_bins = bin_count;
    }
  }

  for (size_t i = 0; i < BinIndex::BIN_COUNT; ++i) {
    for (size_t bin_num = 0; bin_num < max_num_bins; ++bin_num) {
      uint64_t bin_start = kBinWidth * bin_num;
      (*bins)[i][bin_start];
    }
  }
}

// Writes out the bins to a CSV file, each bin type will have its own row and
// the resulting matrix will have as many columns as buckets.
static void DumpToFile(const BinArray& bins, const std::string& filename) {
  std::ofstream out(filename);

  for (size_t i = 0; i < BinIndex::BIN_COUNT; ++i) {
    size_t num_bins = bins[i].size();
    for (size_t bin_num = 0; bin_num < num_bins; ++bin_num) {
      uint64_t bin_start = kBinWidth * bin_num;
      out << bins[i].find(bin_start)->second;

      if (bin_num != num_bins - 1) {
        out << ",";
      }
    }

    out << "\n";
  }

  out.close();
}

static Status RunTrace(const std::string& filename, BinArray* bins) {
  FlowParserConfig cfg;
  flowparser::FlowParser* fp_ptr = nullptr;

  cfg.OfflineTrace(filename);

  cfg.TCPCallback([&bins, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::TCPFlow> flow) {
    DoBin(key, fp_ptr->first_rx(), *flow, bins);
  });

  cfg.UDPCallback([&bins, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::UDPFlow> flow) {
    DoBin(key, fp_ptr->first_rx(), *flow, bins);
  });

  cfg.ICMPCallback([&bins, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::ICMPFlow> flow) {
    DoBin(key, fp_ptr->first_rx(), *flow, bins);
  });

  cfg.UnknownCallback([&bins, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::UnknownFlow> flow) {
    DoBin(key, fp_ptr->first_rx(), *flow, bins);
  });

  flowparser::FlowParser fp(cfg);
  fp_ptr = &fp;

  auto status = fp.RunTrace();
  if (!status.ok()) {
    return status;
  }

  AddEmptyBins(bins, fp.first_rx());
  return Status::kStatusOK;
}

}  // namespace example

int main(int argc, char *argv[]) {
  example::BinArray bins;

  if (argc != 2) {
    std::cout << "Supply exactly one argument.\n";

    return -1;
  }

  std::string filename(argv[1]);
  Status status = example::RunTrace(filename, &bins);
  if (!status.ok()) {
    std::cout << "Non-ok status from trace: " << status.ToString() << "\n";

    return -1;
  }

  example::DumpToFile(bins, filename + ".out");
  return 0;
}
