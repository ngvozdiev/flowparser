#include "parser.h"

namespace flowparser {

Status FlowParser::HandlePkt(const pcap::SniffIp& ip_header,
                             const pcap::SniffTcp& transport_header,
                             uint64_t timestamp) {
  FlowKey key(ip_header, transport_header);

  std::mutex* flow_mutex = nullptr;
  TCPFlow* flow_ptr = nullptr;

  // Lock the table mutex since we will be potentially modifying the table.
  {
    std::unique_lock<std::mutex> lock(flows_table_mutex_);
    FlowValue& value = flows_table_[key];

    if (value.second.get() == nullptr) {
      value.second = std::make_unique<TCPFlow>(timestamp, flow_timeout_);
    }

    flow_mutex = &value.first;
    flow_ptr = value.second.get();
  }

  // Lock the flow mutex since we are going to be adding packets to it.
  {
    std::unique_lock<std::mutex> lock(*flow_mutex);

    auto result = flow_ptr->PacketRx(ip_header, transport_header, timestamp);
    if (!result.ok()) {
      return result;
    }
  }

  return Status::kStatusOK;
}

void FlowParser::PrivateCollectFlows(
    std::function<bool(int64_t)> eval_for_collection) {
  std::vector<std::unique_ptr<TCPFlow>> flows_to_collect;

  // Lock the table mutex
  {
    std::unique_lock<std::mutex> table_lock(flows_table_mutex_);

    auto it = flows_table_.begin();
    while (it != flows_table_.end()) {
      FlowValue& flow_mutex_and_flow = it->second;
      std::mutex& flow_mutex = flow_mutex_and_flow.first;
      auto& flow = flow_mutex_and_flow.second;

      bool to_delete = false;
      {
        std::unique_lock<std::mutex> flow_lock(flow_mutex);
        flow->UpdateAverages();

        int64_t time_left = flow->TimeLeft(last_rx_);
        if (eval_for_collection(time_left)) {
          flow->Deactivate();
          flows_to_collect.push_back(std::move(flow));

          to_delete = true;
        }
      }

      if (to_delete) {
        flows_table_.erase(it++);
      } else {
        ++it;
      }
    }
  }

  if (!flows_to_collect.empty()) {
    for (auto& flow : flows_to_collect) {
      callback_(std::move(flow));
    }
  }
}

}
