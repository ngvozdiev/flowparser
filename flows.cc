#include "flows.h"

namespace flowparser {

FlowInfo Flow::GetInfo() const {
  FlowInfo info;

  info.avg_bytes_per_period = (static_cast<double>(avg_bytes_per_period_)
      / kFixedOne);
  info.avg_pkts_per_period = (static_cast<double>(avg_pkts_per_period_)
      / kFixedOne);

  info.size_pkts = size_pkts_;
  info.size_bytes = size_bytes_;
  info.first_rx = first_rx_time_;
  info.last_rx = last_rx_time_;

  return info;
}

void Flow::UpdateAverages() {
  avg_bytes_per_period_ = kFixedAlpha * (bytes_last_period_ << kFixedShift)
      + kFixedOneMinAlpha * avg_bytes_per_period_;
  avg_bytes_per_period_ >>= kFixedShift;

  avg_pkts_per_period_ = kFixedAlpha * (pkts_last_period_ << kFixedShift)
      + kFixedOneMinAlpha * avg_pkts_per_period_;
  avg_pkts_per_period_ >>= kFixedShift;

  bytes_last_period_ = bytes_this_period_;
  bytes_this_period_ = 0;

  pkts_last_period_ = pkts_this_period_;
  pkts_this_period_ = 0;
}

size_t Flow::BaseSizeBytes() const {
  size_t return_size = 0;

  return_size += timestamps_.SizeBytes();
  return_size += header_id_.SizeBytes();
  return_size += header_len_.SizeBytes();
  return_size += header_ttl_.SizeBytes();

  return return_size;
}

Status Flow::BasePacketRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
  if (state_ != FlowState::ACTIVE) {
    return "Tried to modify passive flow";
  }

  auto result = timestamps_.Append(timestamp);
  if (!result.ok()) {
    return result;
  }

  const u_short pkt_size = ntohs(ip_header.ip_len);

  last_rx_time_ = timestamp;
  pkts_this_period_++;
  bytes_this_period_ += pkt_size;

  header_len_.Append(pkt_size);
  header_id_.Append(ntohs(ip_header.ip_id));
  header_ttl_.Append(ip_header.ip_ttl);

  size_pkts_++;
  size_bytes_ += pkt_size;

  return Status::kStatusOK;
}

}
