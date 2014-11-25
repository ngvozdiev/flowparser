#include "parser.h"

namespace flowparser {

template<typename T, typename P>
std::pair<uint64_t, uint64_t> Parser<T, P>::TotalMemAndDeltaRx() {
  std::unique_lock<std::mutex> lock(flows_table_mutex_);

  uint64_t mem_usage = 0;
  uint64_t min_rx_time = last_rx_;

  for (auto& key_and_flow : flows_table_) {
    const auto& flow = key_and_flow.second;
    mem_usage += flow->SizeBytes();
    uint64_t last_rx = flow->last_rx();
    if (last_rx < min_rx_time) {
      min_rx_time = last_rx;
    }
  }

  return {mem_usage, last_rx_ - min_rx_time};
}

template<typename T, typename P>
Status Parser<T, P>::HandlePkt(const pcap::SniffIp& ip_header,
                               const P& transport_header, uint64_t timestamp) {
  FlowKey key(ip_header, transport_header);

  // Lock the table mutex since we will be potentially modifying the table.
  {
    std::unique_lock<std::mutex> lock(flows_table_mutex_);
    auto& flow = flows_table_[key];

    if (flow.get() == nullptr) {
      flow = std::make_unique<T>(timestamp, flow_timeout_);
    }

    // Update the parser's last RX time. This is slightly odd - we should only
    // update it once we know we will be able to add the packet to the flow,
    // but this requires locking the mutex again later.
    if (timestamp < last_rx_) {
      return "Timestamp in the past";
    }

    last_rx_ = timestamp;
    auto result = flow->PacketRx(ip_header, transport_header, timestamp);
    if (!result.ok()) {
      return result;
    }
  }

  return Status::kStatusOK;
}

template<typename T, typename P>
void Parser<T, P>::PrivateCollectFlows(
    std::function<bool(const T&)> eval_for_collection) {
  std::vector<std::pair<FlowKey, std::unique_ptr<T>>>flows_to_collect;

  // Lock the table mutex
  {
    std::unique_lock<std::mutex> table_lock(flows_table_mutex_);

    auto it = flows_table_.begin();
    while (it != flows_table_.end()) {
      const FlowKey& key = it->first;
      auto& flow = it->second;

      bool to_delete = false;
      flow->UpdateAverages();

      if (eval_for_collection(*flow)) {
        flow->Deactivate();
        flows_to_collect.push_back( {key, std::move(flow)});

        to_delete = true;
      }

      if (to_delete) {
        flows_table_.erase(it++);
      } else {
        ++it;
      }
    }
  }

  if (!flows_to_collect.empty()) {
    for (auto& key_and_flow : flows_to_collect) {
      callback_(key_and_flow.first, std::move(key_and_flow.second));
    }
  }
}

template class Parser<TCPFlow, pcap::SniffTcp> ;
template class Parser<UDPFlow, pcap::SniffUdp> ;
template class Parser<ICMPFlow, pcap::SniffIcmp> ;
template class Parser<UnknownFlow, pcap::SniffUnknown> ;

}
