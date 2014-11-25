#ifndef FPARSER_FLOWS_H
#define FPARSER_FLOWS_H

#include <atomic>
#include <mutex>

#include "packer.h"
#include "sniff.h"

namespace flowparser {

// The flow types supported.
enum FlowType {
  TCP,
  UDP,
  ICMP,
  UNKNONW
};

// A flow can be in one of two states - passive means that the flow has timed
// out.
enum FlowState {
  ACTIVE,
  PASSIVE
};

// An IP header. This header only contains fields that can be tracked. All
// fields are in host byte order.
struct IPHeader {
  uint64_t timestamp = 0;
  uint16_t length = 0;
  uint16_t id = 0;
  uint8_t ttl = 0;
};

// Similar to IPHeader, but for TCP-specific fields.
struct TCPHeader {
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint16_t win = 0;
  uint8_t flags = 0;
};

// ICMP header.
struct ICMPHeader {
  uint8_t type;
  uint8_t code;
};

// ESP header.
struct ESPHeader {
  uint32_t spi;
  uint32_t seq;
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
  FlowInfo GetInfo() const;

  // Updates the average packet and byte counters. If called periodically this
  // function will produce per-period averages. This function is thread-safe.
  void UpdateAverages();

  void Deactivate() {
    state_ = FlowState::PASSIVE;
  }

  // Returns the time remaining until this flow expires (if the returned value
  // is negative this flow has expired).
  int64_t TimeLeft(uint64_t time_now) const {
    return (last_rx_time_ + timeout_) - time_now;
  }

  uint64_t last_rx() const {
    return last_rx_time_;
  }

  FlowType type() const {
    return type_;
  }

 protected:
  Flow(uint64_t timestamp, uint64_t timeout, FlowType type)
      : first_rx_time_(timestamp),
        timeout_(timeout),
        type_(type),
        state_(FlowState::ACTIVE) {
  }

  // Returns the sum of sizes of headers and timestamps stored. Does not include
  // the size of the flow class itself. This function is NOT thread-safe.
  size_t BaseSizeBytes() const;

  // Called when a new packet is received.
  Status BasePacketRx(const pcap::SniffIp& ip_header, uint64_t timestamp);

 private:
  // Timestamp of the first packet reception.
  const uint64_t first_rx_time_;

  // How long after the last rx packet the flow should be considered timed out.
  const uint64_t timeout_;

  // Even though all flow classes inherit from this one it is still convenient
  // to keep track of the flow type in the base class in case a more specific
  // class is sliced to the base one and the user still needs to know what the
  // original flow type was.
  const FlowType type_;

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
  uint64_t last_rx_time_ = std::numeric_limits<uint64_t>::max();

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

  friend class FlowIterator;

  DISALLOW_COPY_AND_ASSIGN(Flow);
};

// An iterator over a flow instance that can be used to recover the packets from
// a flow. The parent Flow instance should outlive this object and it should not
// be defined while this object is active.
class FlowIterator {
 public:
  FlowIterator(const Flow& parent)
      : timestamp_it_(parent.timestamps_),
        id_it_(parent.header_id_),
        len_it_(parent.header_len_),
        ttl_it_(parent.header_ttl_) {
  }

  // Populates the given struct with the next header from the flow. If there are
  // no more headers false is returned.
  bool Next(IPHeader* header) {
    if (!timestamp_it_.Next(&header->timestamp)) {
      return false;
    }

    // These should all return true
    id_it_.Next(&header->id);
    len_it_.Next(&header->length);
    ttl_it_.Next(&header->ttl);

    return true;
  }

 private:
  PackedUintSeqIterator timestamp_it_;
  RLEFieldIterator<u_short> id_it_;
  RLEFieldIterator<u_short> len_it_;
  RLEFieldIterator<uint8_t> ttl_it_;

  DISALLOW_COPY_AND_ASSIGN(FlowIterator);
};

// An unknown protocol. This is essentially just an IP header.
class UnknownFlow : public Flow {
 public:
  UnknownFlow(uint64_t init_timestamp, uint64_t timeout)
      : Flow::Flow(init_timestamp, timeout, FlowType::UNKNONW) {
  }

  size_t SizeBytes() {
    return sizeof(UnknownFlow) + BaseSizeBytes();
  }

  Status PacketRx(const pcap::SniffIp& ip_header,
                  const pcap::SniffUnknown& unknown_header,
                  uint64_t timestamp) {
    ignore(unknown_header);

    return BasePacketRx(ip_header, timestamp);
  }
};

// A UDP flow is just an IP header. The src/dst port information is stored as
// part of FlowKey.
class UDPFlow : public Flow {
 public:
  UDPFlow(uint64_t init_timestamp, uint64_t timeout)
      : Flow::Flow(init_timestamp, timeout, FlowType::UDP) {
  }

  size_t SizeBytes() {
    return sizeof(UDPFlow) + BaseSizeBytes();
  }

  Status PacketRx(const pcap::SniffIp& ip_header,
                  const pcap::SniffUdp& udp_header, uint64_t timestamp) {
    ignore(udp_header);

    return BasePacketRx(ip_header, timestamp);
  }
};

// Four fields are tracked for TCP headers - flags, sequence numbers, ack
// numbers and window sizes.
class TCPFlow : public Flow {
 public:
  TCPFlow(uint64_t init_timestamp, uint64_t timeout)
      : Flow::Flow(init_timestamp, timeout, FlowType::TCP) {
  }

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

 private:
  // TCP flag fields of seen packets.
  RLEField<uint8_t> header_flags_;

  // TCP sequence fields of seen packets.
  RLEField<u_int> header_seq_;

  // TCP ACK fields of seen packets.
  RLEField<u_int> header_ack_;

  // TCP window fields of seen packets.
  RLEField<u_short> header_win_;

  friend class TCPFlowIterator;
};

// An iterator over both the IP and the TCP fields of a flow. Same restrictions
// as FlowIterator apply.
class TCPFlowIterator {
 public:
  TCPFlowIterator(const TCPFlow& parent)
      : flow_it_(parent),  // Intentional slicing
        ack_it_(parent.header_ack_),
        seq_it_(parent.header_seq_),
        flags_it_(parent.header_flags_),
        win_it_(parent.header_win_) {
  }

  bool Next(IPHeader* ip_header, TCPHeader* tcp_header) {
    if (!flow_it_.Next(ip_header)) {
      return false;
    }

    ack_it_.Next(&tcp_header->ack);
    seq_it_.Next(&tcp_header->seq);
    flags_it_.Next(&tcp_header->flags);
    win_it_.Next(&tcp_header->win);

    return true;
  }

 private:
  FlowIterator flow_it_;
  RLEFieldIterator<uint32_t> ack_it_;
  RLEFieldIterator<uint32_t> seq_it_;
  RLEFieldIterator<uint8_t> flags_it_;
  RLEFieldIterator<uint16_t> win_it_;

  DISALLOW_COPY_AND_ASSIGN(TCPFlowIterator);
};

// For ICMP two fields are tracked - type and code.
class ICMPFlow : public Flow {
 public:
  ICMPFlow(uint64_t init_timestamp, uint64_t timeout)
      : Flow::Flow(init_timestamp, timeout, FlowType::ICMP) {
  }

  size_t SizeBytes() {
    size_t return_size = sizeof(TCPFlow) + BaseSizeBytes();

    return_size += header_type_.SizeBytes();
    return_size += header_code_.SizeBytes();

    return return_size;
  }

  Status PacketRx(const pcap::SniffIp& ip_header,
                  const pcap::SniffIcmp& icmp_header, uint64_t timestamp) {
    auto status = Flow::BasePacketRx(ip_header, timestamp);
    if (!status.ok()) {
      return status;
    }

    header_type_.Append(icmp_header.icmp_type);
    header_code_.Append(icmp_header.icmp_code);

    return Status::kStatusOK;
  }

 private:
  // TCP flag fields of seen packets.
  RLEField<uint8_t> header_type_;

  // TCP flag fields of seen packets.
  RLEField<uint8_t> header_code_;

  friend class ICMPFlowIterator;
};

class ICMPFlowIterator {
 public:
  ICMPFlowIterator(const ICMPFlow& parent)
      : flow_it_(parent),  // Intentional slicing
        type_it_(parent.header_type_),
        code_it_(parent.header_code_) {
  }

  bool Next(IPHeader* ip_header, ICMPHeader* icmp_header) {
    if (!flow_it_.Next(ip_header)) {
      return false;
    }

    type_it_.Next(&icmp_header->type);
    code_it_.Next(&icmp_header->code);

    return true;
  }

 private:
  FlowIterator flow_it_;
  RLEFieldIterator<uint8_t> type_it_;
  RLEFieldIterator<uint8_t> code_it_;

  DISALLOW_COPY_AND_ASSIGN(ICMPFlowIterator);
};

}

#endif  /* FPARSER_FLOWS_H */
