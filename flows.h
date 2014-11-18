#ifndef FPARSER_FLOWS_H
#define FPARSER_FLOWS_H

#include <atomic>
#include <mutex>

#include "packer.h"
#include "sniff.h"

namespace flowparser {

enum FlowState {
  ACTIVE,
  PASSIVE
};

// Information about a flow.
struct FlowInfo {
  double avg_pkts_per_period = 0.0;
  double avg_bytes_per_period = 0.0;
  uint64_t size_pkts = 0;
  uint64_t size_bytes = 0;
  uint64_t first_rx = 0;
  uint64_t last_rx = 0;
};

// Generic state that every flow has. This class does not expose any public
// constructors. Use the more specific TCPFlow or UDPFlow instead. This class is
// thread-compatible.
class Flow {
 public:
  static constexpr size_t kFixedShift = 11;  // fixed-point precision
  static constexpr size_t kFixedOne = (1 << kFixedShift);  // 1 in fixed-point

  // 0.35 in fixed-point
  static constexpr size_t kFixedAlpha = (0.35 * kFixedOne);

  // 1 - 0.35 in fixed-point
  static constexpr size_t kFixedOneMinAlpha = (0.65 * kFixedOne);

  // Returns generic information about the flow.
  FlowInfo GetInfo() const {
    FlowInfo info;

    info.avg_bytes_per_period = ((double) avg_bytes_per_period_ / kFixedOne);
    info.avg_pkts_per_period = ((double) avg_pkts_per_period_ / kFixedOne);
    info.size_pkts = size_pkts_;
    info.size_bytes = size_bytes_;
    info.first_rx = first_rx_time_;
    info.last_rx = last_rx_time_;

    return info;
  }

  // Updates the average packet and byte counters. If called periodically this
  // function will produce per-period averages. This function is thread-safe.
  void UpdateAverages() {
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

  // Returns the time remaining until this flow expires (if the returned value
  // is negative this flow has expired).
  int64_t TimeLeft(uint64_t time_now) const {
    return (last_rx_time_ + timeout_) - time_now;
  }

 protected:
  Flow(uint64_t timestamp, uint64_t timeout)
      : first_rx_time_(timestamp),
        timeout_(timeout),
        state_(FlowState::ACTIVE),
        last_rx_time_(timestamp) {
  }

  // Returns the sum of sizes of headers and timestamps stored. Does not include
  // the size of the flow class itself. This function is NOT thread-safe.
  size_t BaseSizeBytes() const {
    size_t return_size = 0;

    return_size += timestamps_.SizeBytes();
    return_size += header_id_.SizeBytes();
    return_size += header_len_.SizeBytes();
    return_size += header_ttl_.SizeBytes();

    return return_size;
  }

  // Called when a new packet is received.
  Status BasePacketRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
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
    header_ttl_.Append(ntohs(ip_header.ip_ttl));

    size_pkts_++;
    size_bytes_ += pkt_size;

    return Status::kStatusOK;
  }

 private:
  // Timestamp of the first packet reception.
  const uint64_t first_rx_time_;

  // How long after the last rx packet the flow should be considered timed out.
  const uint64_t timeout_;

  // The current state of this flow. This variable should be updated atomically.
  FlowState state_;

  // Timestamps of when packets were received.
  PackedUintSeq timestamps_;

  // IP id header fields of seen packets.
  RLEField<u_short> header_id_;

  // IP length header fields of seen packets.
  RLEField<u_short> header_len_;

  // IP TTL header fields of seen packets.
  RLEField<uint8_t> header_ttl_;

  // Timestamp of the most recent packet reception.
  uint64_t last_rx_time_;

  // Number of packets seen during the current period.
  uint32_t bytes_this_period_ = 0;

  // Number of packets seen during the last period.
  uint32_t bytes_last_period_ = 0;

  // A fixed-point average of the number of packets seen per period.
  uint64_t avg_bytes_per_period_ = 0;

  // Number of packets seen during the current period.
  uint32_t pkts_this_period_ = 0;

  // Number of packets seen during the last period.
  uint32_t pkts_last_period_ = 0;

  // A fixed-point average of the number of packets seen per period.
  uint64_t avg_pkts_per_period_ = 0;

  // Number of packets this flow has seen.
  uint64_t size_pkts_ = 0;

  // Total size in terms of bytes seen. This is not the amount of memory the
  // flow occupies, but the sum of the size field of all packets seen in this
  // flow.
  uint64_t size_bytes_ = 0;

  DISALLOW_COPY_AND_ASSIGN(Flow);
};

class UDPFlow : public Flow {
 public:
  using Flow::Flow;

  size_t SizeBytes() {
    return sizeof(UDPFlow) + BaseSizeBytes();
  }

  Status PacketRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
    return BasePacketRx(ip_header, timestamp);
  }
};

class TCPFlow : public Flow {
 public:
  using Flow::Flow;

  size_t SizeBytes() {
    size_t return_size = sizeof(TCPFlow) + BaseSizeBytes();

    return_size += header_flags_.SizeBytes();
    return_size += header_ack_.SizeBytes();
    return_size += header_seq_.SizeBytes();
    return_size += header_win_.SizeBytes();

    return return_size;
  }

  Status PacketRx(const pcap::SniffIp& ip_header,
                  const pcap::SniffTcp& tcp_header, uint64_t timestamp) {
    auto status = Flow::BasePacketRx(ip_header, timestamp);
    if (!status.ok()) {
      return status;
    }

    header_flags_.Append(tcp_header.th_flags);
    header_seq_.Append(ntohl(tcp_header.th_seq));
    header_ack_.Append(ntohl(tcp_header.th_ack));
    header_win_.Append(ntohs(tcp_header.th_win));

    return Status::kStatusOK;
  }

 protected:
  // TCP flag fields of seen packets.
  RLEField<uint8_t> header_flags_;

  // TCP sequence fields of seen packets.
  RLEField<u_int> header_seq_;

  // TCP ACK fields of seen packets.
  RLEField<u_int> header_ack_;

  // TCP window fields of seen packets.
  RLEField<u_short> header_win_;
};

}

#endif  /* FPARSER_FLOWS_H */
