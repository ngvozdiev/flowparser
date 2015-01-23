#ifndef FPARSER_FLOWS_H
#define FPARSER_FLOWS_H

#include <atomic>
#include <mutex>

#include "packer.h"
#include "sniff.h"

namespace flowparser {

// A flow can be in one of two states - passive means that the flow has timed
// out.
enum FlowState {
  ACTIVE,
  PASSIVE
};

// Each flow is indexed by this value. Note that it does not contain a flow
// type.
class FlowKey {
 public:
  FlowKey(const FlowKey& other)
      : ip_proto_(other.ip_proto_),
        src_(other.src_),
        dst_(other.dst_),
        sport_(other.sport_),
        dport_(other.dport_) {
  }

  FlowKey(const pcap::SniffIp& ip_header, uint16_t sport, uint16_t dport)
      : ip_proto_(ip_header.ip_p),
        src_(ip_header.ip_src.s_addr),
        dst_(ip_header.ip_dst.s_addr),
        sport_(sport),
        dport_(dport) {
  }

  bool operator==(const FlowKey &other) const {
    return (src_ == other.src_ && dst_ == other.dst_ && sport_ == other.sport_
        && dport_ == other.dport_ && ip_proto_ == other.ip_proto_);
  }

  bool operator!=(const FlowKey& other) const {
    return !(*this == other);
  }

  std::string ToString() const {
    return "(src='" + IPToString(src_) + "', dst='" + IPToString(dst_)
        + "', src_port=" + std::to_string(src_port()) + ", dst_port="
        + std::to_string(dst_port()) + ")";
  }

  // The source IP address of the flow (in host byte order)
  uint32_t src() const {
    return ntohl(src_);
  }

  // The destination IP address of the flow (in host byte order)
  uint32_t dst() const {
    return ntohl(dst_);
  }

  // The IP protocol
  uint8_t protocol() const {
    return ip_proto_;
  }

  // A string representation of the source address.
  std::string SrcToString() const {
    return IPToString(src_);
  }

  // A string representation of the destination address.
  std::string DstToString() const {
    return IPToString(dst_);
  }

  // The source port of the flow (in host byte order)
  uint16_t src_port() const {
    return ntohs(sport_);
  }

  // The destination port of the flow (in host byte order)
  uint16_t dst_port() const {
    return ntohs(dport_);
  }

  size_t hash() const {
    size_t result = 17;
    result = 37 * result + ip_proto_;
    result = 37 * result + src_;
    result = 37 * result + dst_;
    result = 37 * result + sport_;
    result = 37 * result + dport_;
    return result;
  }

 private:
  const uint8_t ip_proto_;
  const uint32_t src_;
  const uint32_t dst_;
  const uint16_t sport_;
  const uint16_t dport_;

  friend class FlowIterator;
};

struct KeyHasher {
  size_t operator()(const FlowKey& k) const {
    return k.hash();
  }
};

// Configuration for a flow. Also holds an enum with possible field types.
class FlowConfig {
 public:
  enum HeaderField {
    HF_TIMESTAMP = 1 << 0,
    HF_IP_LEN = 1 << 1,
    HF_IP_ID = 1 << 2,
    HF_IP_TTL = 1 << 3,
    HF_TCP_SEQ = 1 << 4,
    HF_TCP_ACK = 1 << 5,
    HF_TCP_WIN = 1 << 6,
    HF_TCP_FLAGS = 1 << 7,
    HF_ICMP_TYPE = 1 << 8,
    HF_ICMP_CODE = 1 << 9,
    HF_PAYLOAD_SIZE = 1 << 10
  };

  FlowConfig()
      : fields_to_track_(0x1) {
  }

  void SetField(HeaderField header_field) {
    fields_to_track_ |= header_field;
  }

  void ClearField(HeaderField header_field) {
    fields_to_track_ &= ~(header_field);
  }

  uint32_t fields_to_track() const {
    return fields_to_track_;
  }

 private:
  uint32_t fields_to_track_;

  friend class Flow;
};

// This header contains all fields that can be tracked. All fields are in host
// byte order. If a field is not tracked, or is invalid for the packet type,
// its value will be 0.
class TrackedFields {
 public:
  TrackedFields(const TrackedFields& other)
      : fields_present_bitmap_(other.fields_present_bitmap_),
        timestamp_(other.timestamp_),
        payload_size_(other.payload_size_),
        ip_len_(other.ip_len_),
        ip_id_(other.ip_id_),
        ip_ttl_(other.ip_ttl_),
        tcp_seq_(other.tcp_seq_),
        tcp_ack_(other.tcp_ack_),
        tcp_win_(other.tcp_win_),
        tcp_flags_(other.tcp_flags_),
        icmp_code_(other.icmp_code_),
        icmp_type_(other.icmp_type_) {
  }

  uint64_t timestamp() const;
  uint16_t ip_len() const;
  uint16_t ip_id() const;
  uint8_t ip_ttl() const;
  uint32_t tcp_seq() const;
  uint32_t tcp_ack() const;
  uint16_t tcp_win() const;
  uint8_t tcp_flags() const;
  uint16_t payload_size() const;
  uint8_t icmp_code() const;
  uint8_t icmp_type() const;

 private:
  TrackedFields(uint32_t fields_present_bitmap)
      : fields_present_bitmap_(fields_present_bitmap) {
  }

  const uint32_t fields_present_bitmap_;

  uint64_t timestamp_ = 0;
  uint16_t payload_size_ = 0;
  uint16_t ip_len_ = 0;
  uint16_t ip_id_ = 0;
  uint8_t ip_ttl_ = 0;
  uint32_t tcp_seq_ = 0;
  uint32_t tcp_ack_ = 0;
  uint16_t tcp_win_ = 0;
  uint8_t tcp_flags_ = 0;
  uint8_t icmp_code_ = 0;
  uint8_t icmp_type_ = 0;

  friend class FlowIterator;
};

// Information about a flow.
struct FlowInfo {
  uint64_t pkts_seen = 0;
  uint64_t total_ip_len_seen = 0;
  uint64_t total_payload_seen = 0;
  uint64_t first_rx = 0;
  uint64_t last_rx = 0;
  uint64_t inmem_size_bytes = 0;
};

// The main (and only) flow class.
class Flow {
 public:
  Flow(uint64_t timestamp, const FlowKey& key, const FlowConfig& flow_config)
      : flow_config_(flow_config),
        first_rx_time_(timestamp),
        key_(key),
        curr_size_bytes_(0),
        state_(FlowState::ACTIVE),
        pkts_seen_(0),
        total_ip_len_seen_(0),
        total_payload_seen_(0) {
  }

  void Deactivate() {
    state_ = FlowState::PASSIVE;
  }

  uint64_t last_rx() const {
    return last_rx_time_;
  }

  const FlowKey& key() const {
    return key_;
  }

  FlowInfo GetInfo() const {
    FlowInfo info;

    info.pkts_seen = pkts_seen_;
    info.total_ip_len_seen = total_ip_len_seen_;
    info.total_payload_seen = total_payload_seen_;
    info.first_rx = first_rx_time_;
    info.last_rx = last_rx_time_;
    info.inmem_size_bytes = curr_size_bytes_;

    return info;
  }

  size_t SizeBytes() const {
    return curr_size_bytes_;
  }

  void TCPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffTcp& tcp_header,
               uint64_t timestamp, size_t* bytes);

  void UDPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffUdp& udp_header,
               uint64_t timestamp, size_t* bytes);

  void ICMPIpRx(const pcap::SniffIp& ip_header,
                const pcap::SniffIcmp& icmp_header, uint64_t timestamp,
                size_t* bytes);

  void UnknownIpRx(const pcap::SniffIp& ip_header, uint64_t timestamp,
                   size_t* bytes);

 private:
  void IpRx(const pcap::SniffIp& ip_header, uint64_t timestamp);

  // Whether or not to track header fields.
  const FlowConfig& flow_config_;

  // Timestamp of the first packet reception.
  const uint64_t first_rx_time_;

  // The flow key.
  const FlowKey key_;

  // The current size of this flow.
  size_t curr_size_bytes_;

  // The current state of this flow.
  FlowState state_;

  // Timestamps of when packets were received.
  PackedUintSeq timestamps_;

  // IP id header fields of seen packets.
  RLEField<u_short> ip_id_;

  // IP length header fields of seen packets.
  RLEField<u_short> ip_len_;

  // Payload of the packet -- ip_len minus ip/tcp headers.
  RLEField<u_short> payload_size_;

  // IP TTL header fields of seen packets.
  RLEField<uint8_t> ip_ttl_;

  // TCP flag fields of seen packets.
  RLEField<uint8_t> tcp_flags_;

  // TCP sequence fields of seen packets.
  RLEField<u_int> tcp_seq_;

  // TCP ACK fields of seen packets.
  RLEField<u_int> tcp_ack_;

  // TCP window fields of seen packets.
  RLEField<u_short> tcp_win_;

  // TCP flag fields of seen packets.
  RLEField<uint8_t> icmp_type_;

  // TCP flag fields of seen packets.
  RLEField<uint8_t> icmp_code_;

  // Timestamp of the most recent packet reception.
  uint64_t last_rx_time_ = std::numeric_limits<uint64_t>::max();

  // Total number of packets seen by this flow.
  uint64_t pkts_seen_;

  // Sum of ip_len fields of all packets seen by this flow.
  uint64_t total_ip_len_seen_;

  // Sum of payload (ip_len - headers) of all packets seen by this flow.
  uint64_t total_payload_seen_;

  friend class FlowIterator;

  DISALLOW_COPY_AND_ASSIGN(Flow);
};

// An iterator over a flow instance that can be used to recover the packets from
// a flow. The parent Flow instance should outlive this object.
class FlowIterator {
 public:
  FlowIterator(const Flow& parent)
      : max_(parent.pkts_seen_),
        fields_(parent.flow_config_.fields_to_track()),
        i_(0),
        timestamp_it_(parent.timestamps_),
        payload_size_it_(parent.payload_size_),
        ip_id_it_(parent.ip_id_),
        ip_len_it_(parent.ip_len_),
        ip_ttl_it_(parent.ip_ttl_),
        tcp_ack_it_(parent.tcp_ack_),
        tcp_seq_it_(parent.tcp_seq_),
        tcp_flags_it_(parent.tcp_flags_),
        tcp_win_it_(parent.tcp_win_),
        icmp_type_it_(parent.icmp_type_),
        icmp_code_it_(parent.icmp_code_) {
  }

  // Populates the given struct with the next header from the flow. If there are
  // no more headers false is returned.
  const TrackedFields* NextOrNull() {
    if (i_++ == max_) {
      return nullptr;
    }

    timestamp_it_.Next(&fields_.timestamp_);
    payload_size_it_.Next(&fields_.payload_size_);
    ip_id_it_.Next(&fields_.ip_id_);
    ip_len_it_.Next(&fields_.ip_len_);
    ip_ttl_it_.Next(&fields_.ip_ttl_);
    tcp_ack_it_.Next(&fields_.tcp_ack_);
    tcp_seq_it_.Next(&fields_.tcp_seq_);
    tcp_win_it_.Next(&fields_.tcp_win_);
    tcp_flags_it_.Next(&fields_.tcp_flags_);
    icmp_type_it_.Next(&fields_.icmp_type_);
    icmp_code_it_.Next(&fields_.icmp_code_);

    return &fields_;
  }

 private:
  const size_t max_;
  TrackedFields fields_;
  size_t i_;

  PackedUintSeqIterator timestamp_it_;
  RLEFieldIterator<uint16_t> payload_size_it_;
  RLEFieldIterator<uint16_t> ip_id_it_;
  RLEFieldIterator<uint16_t> ip_len_it_;
  RLEFieldIterator<uint8_t> ip_ttl_it_;
  RLEFieldIterator<uint32_t> tcp_ack_it_;
  RLEFieldIterator<uint32_t> tcp_seq_it_;
  RLEFieldIterator<uint8_t> tcp_flags_it_;
  RLEFieldIterator<uint16_t> tcp_win_it_;
  RLEFieldIterator<uint8_t> icmp_type_it_;
  RLEFieldIterator<uint8_t> icmp_code_it_;

  DISALLOW_COPY_AND_ASSIGN(FlowIterator);
};

}

#endif  /* FPARSER_FLOWS_H */
