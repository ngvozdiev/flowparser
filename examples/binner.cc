#include "binner.h"

#include <cstdbool>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <type_traits>
#include <utility>
#include <thread>

#include "../flowparser.h"
#include "../parser.h"

namespace flowparser {
namespace example {
namespace binner {

FlowType BinPackValue::ClassifyFlow(const Flow& flow) {
  bool small_flow = flow.GetInfo().total_ip_len_seen < small_flows_threshold_;
  const FlowKey& key = flow.key();

  bool udp_flow = key.protocol() == IPPROTO_UDP;
  bool tcp_flow = key.protocol() == IPPROTO_TCP;
  bool http_flow = tcp_flow
      && (key.src_port() == kHTTPPort || key.dst_port() == kHTTPPort);
  bool ftp_flow = tcp_flow
      && (key.src_port() == kFTPPort || key.dst_port() == kFTPPort);
  bool https_flow = tcp_flow
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

void BinPackValue::BinFlow(const Flow& flow) {
  FlowType type = ClassifyFlow(flow);

  ExtractMetricAndBin(flow, type);
}

void BinPackValue::AddEmptyBins() {
  size_t max_num_bins = 0;
  for (size_t i = 0; i < FlowType_ARRAYSIZE; ++i) {
    for (const auto& bin_num_and_value : bins_[i]) {
      size_t bin_num = bin_num_and_value.first;
      if (bin_num > max_num_bins) {
        max_num_bins = bin_num;
      }
    }
  }

  for (size_t i = 0; i < FlowType_ARRAYSIZE; ++i) {
    for (size_t bin_num = 0; bin_num <= max_num_bins; ++bin_num) {
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

void Binner::InitBinPacks() {
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
      throw std::logic_error("Unknown bin pack type");
    }

    bin_packs_.push_back(std::move(new_bin_pack));
  }
}

void Binner::RunTrace() {
  FlowParserConfig fp_cfg;

  const std::string& filename = config_.pcap_filename();
  fp_cfg.OfflineTrace(filename);

  auto queue_ptr = std::make_shared<Parser::FlowQueue>();
  fp_cfg.FlowQueue(queue_ptr);
  FlowConfig* flow_config = fp_cfg.MutableParserConfig()->mutable_flow_config();
  flow_config->SetField(FlowConfig::HF_IP_ID);
  flow_config->SetField(FlowConfig::HF_IP_TTL);
  flow_config->SetField(FlowConfig::HF_IP_LEN);
  flow_config->SetField(FlowConfig::HF_TCP_SEQ);
  flow_config->SetField(FlowConfig::HF_TCP_ACK);
  flow_config->SetField(FlowConfig::HF_TCP_WIN);
  flow_config->SetField(FlowConfig::HF_TCP_FLAGS);

  FlowParser fp(fp_cfg);

  std::thread th([this, &queue_ptr, &fp] {
    while (true) {
      std::unique_ptr<Flow> flow_ptr = queue_ptr->ConsumeOrBlock();
      if (!flow_ptr) {
        break;
      }

      uint64_t first_rx = fp.parser().GetInfoNoLock().first_rx;
      HandleFlow(*flow_ptr, first_rx);
    }
  });

  fp.RunTrace();
  th.join();
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
  binner.InitBinPacks();
  binner.RunTrace();

  BinnedFlows output_protobuf;
  binner.ToBinnedFlows(&output_protobuf);

  std::ofstream out_stream(binner_config.pcap_filename() + ".binned.pb");
  out_stream << output_protobuf.SerializeAsString();
  out_stream.close();

  return 0;
}
