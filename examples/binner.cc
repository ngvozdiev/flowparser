#include "binner.h"

#include <cstdbool>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <type_traits>
#include <utility>

#include "../flowparser.h"
#include "../parser.h"

namespace flowparser {
namespace example {
namespace binner {

FlowType BinPackValue::ClassifyFlow(const FlowKey& key, const Flow& flow) {
  bool small_flow = flow.GetInfo().size_bytes < small_flows_threshold_;
  bool udp_flow = flow.type() == flowparser::UDP;
  bool tcp_flow = flow.type() == flowparser::TCP;
  bool http_flow = (flow.type() == flowparser::TCP)
      && (key.src_port() == kHTTPPort || key.dst_port() == kHTTPPort);
  bool ftp_flow = (flow.type() == flowparser::TCP)
      && (key.src_port() == kFTPPort || key.dst_port() == kFTPPort);
  bool https_flow = (flow.type() == flowparser::TCP)
      && (key.src_port() == kHTTPSPort || key.dst_port() == kHTTPSPort);
  bool bt_flow = (key.src_port() >= kBTLowPort && key.src_port() <= kBTHighPort)
      || (key.dst_port() >= kBTLowPort && key.dst_port() <= kBTHighPort);

  if (small_flow) {
    if (udp_flow) {
      return FlowType::SMALL_UDP;
    }

    if (tcp_flow) {
      return FlowType::SMALL_TCP;
    }

    return FlowType::SMALL_NO_TCP_UDP;
  }

  if (bt_flow) {
    return FlowType::LARGE_TORRENT;
  }

  if (http_flow) {
    return FlowType::LARGE_HTTP;
  }

  if (https_flow) {
    return FlowType::LARGE_HTTPS;
  }

  if (ftp_flow) {
    return FlowType::LARGE_FTP;
  }

  if (udp_flow) {
    return FlowType::LARGE_OTHER_UDP;
  }

  if (tcp_flow) {
    return FlowType::LARGE_OTHER_TCP;
  }

  return FlowType::LARGE_NO_TCP_UDP;
}

void BinPackValue::AddToBin(uint64_t timestamp, uint64_t metric,
                            FlowType type) {
  bins_[type][GetBinNum(timestamp)] += metric;
}

void BinPackValue::BinFlow(const FlowKey& key, const Flow& flow) {
  FlowType type = ClassifyFlow(key, flow);

  ExtractMetricAndBin(key, flow, type);
}

void BinPackValue::AddEmptyBins() {
  size_t max_num_bins = 0;
  for (size_t i = 0; i < FlowType_ARRAYSIZE; ++i) {
    size_t bin_count = bins_[i].size();
    if (bin_count > max_num_bins) {
      max_num_bins = bin_count;
    }
  }

  for (size_t i = 0; i < FlowType_ARRAYSIZE; ++i) {
    for (size_t bin_num = 0; bin_num < max_num_bins; ++bin_num) {
      bins_[i][bin_num];
    }
  }
}

void BinPackValue::ToBinPack(BinPack* bin_pack) {
  AddEmptyBins();

  bin_pack->set_bin_width(bin_width_);
  bin_pack->set_num_bins(bins_[0].size());
  bin_pack->set_bins_start(first_bin_edge_);
  bin_pack->set_type(type_);
  for (size_t i = 0; i < FlowType_ARRAYSIZE; ++i) {
    BinnedValues* values = bin_pack->add_values();

    values->set_type(static_cast<FlowType>(i));
    for (const auto& bin_num_and_value : bins_[i]) {
      values->add_bins(bin_num_and_value.second);
    }
  }
}

Status Binner::InitBinPacks() {
  const uint64_t small_flows_threshold = config_.small_flow_threshold();

  for (const auto& bin_pack_config : config_.bin_pack_configs()) {
    std::unique_ptr<BinPackValue> new_bin_pack;
    if (bin_pack_config.type() == BinPack::SIZES_BYTES) {
      new_bin_pack = std::unique_ptr<BinPackValue>(
          new SizeBytesBinPack(bin_pack_config.bin_width(),
                               small_flows_threshold));
    } else if (bin_pack_config.type() == BinPack::SIZES_PKTS) {
      new_bin_pack = std::unique_ptr<BinPackValue>(
          new SizePktsBinPack(bin_pack_config.bin_width(),
                              small_flows_threshold));
    } else if (bin_pack_config.type() == BinPack::NEW_FLOWS) {
      new_bin_pack = std::unique_ptr<BinPackValue>(
          new NewFlowsBinPack(bin_pack_config.bin_width(),
                              small_flows_threshold));
    } else if (bin_pack_config.type() == BinPack::ACTIVE_FLOWS) {
      new_bin_pack = std::unique_ptr<BinPackValue>(
          new ActiveFlowsBinPack(bin_pack_config.bin_width(),
                                 small_flows_threshold));
    } else if (bin_pack_config.type() == BinPack::END_TIMESTAMP) {
      new_bin_pack = std::unique_ptr<BinPackValue>(
          new EndTimestampBinPack(bin_pack_config.bin_width(),
                                  small_flows_threshold));
    } else {
      return "Unknown bin pack type";
    }

    bin_packs_.push_back(std::move(new_bin_pack));
  }

  return Status::kStatusOK;
}

Status Binner::RunTrace() {
  FlowParserConfig fp_cfg;
  flowparser::FlowParser* fp_ptr = nullptr;

  const std::string& filename = config_.pcap_filename();

  fp_cfg.OfflineTrace(filename);

  fp_cfg.TCPCallback([this, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::TCPFlow> flow) {
    HandleFlow(key, *flow, *fp_ptr);
  });

  fp_cfg.UDPCallback([this, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::UDPFlow> flow) {
    HandleFlow(key, *flow, *fp_ptr);
  });

  fp_cfg.ICMPCallback([this, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::ICMPFlow> flow) {
    HandleFlow(key, *flow, *fp_ptr);
  });

  fp_cfg.UnknownCallback([this, &fp_ptr]
  (const FlowKey& key, std::unique_ptr<flowparser::UnknownFlow> flow) {
    HandleFlow(key, *flow, *fp_ptr);
  });

  flowparser::FlowParser fp(fp_cfg);
  fp_ptr = &fp;

  auto status = fp.RunTrace();
  if (!status.ok()) {
    return status;
  }

  return Status::kStatusOK;
}

}  // namespace binner
}  // namespace example
}  // namespace flowparser

using flowparser::example::binner::BinnerConfig;
using flowparser::example::binner::Binner;
using flowparser::example::binner::BinnedFlows;

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cout << "Supply exactly one argument.\n";

    return -1;
  }

  std::string filename(argv[1]);
  std::ifstream in_stream(filename);
  std::string serialized_protobuf((std::istreambuf_iterator<char>(in_stream)),
                                  std::istreambuf_iterator<char>());

  BinnerConfig binner_config;
  if (!binner_config.ParseFromString(serialized_protobuf)) {
    std::cout << "Bad binner config protobuf\n";

    return -1;
  }

  Binner binner(binner_config);

  Status init_bin_packs_status = binner.InitBinPacks();
  if (!init_bin_packs_status.ok()) {
    std::cout << "Unable to init bin packs: "
              << init_bin_packs_status.ToString() << "\n";

    return -1;
  }

  Status status = binner.RunTrace();
  if (!status.ok()) {
    std::cout << "Non-ok status from trace: " << status.ToString() << "\n";

    return -1;
  }

  BinnedFlows output_protobuf;
  binner.ToBinnedFlows(&output_protobuf);

  std::ofstream out_stream(binner_config.pcap_filename() + ".binned.proto");
  out_stream << output_protobuf.SerializeAsString();
  out_stream.close();

  return 0;
}
