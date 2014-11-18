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
    std::unique_lock<std::mutex> lock(mu_);
    TCPValue& value = flows_[key];

    if (value.flow_.get() == nullptr) {
      value.flow_ = std::make_unique<TCPFlow>(timestamp, flow_timeout_);
    }

    flow_mutex = &value.first;
    flow_ptr = &value.second;
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

}
