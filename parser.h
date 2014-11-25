// Defines the main parser class.

#ifndef FLOWPARSER_PARSER_H
#define FLOWPARSER_PARSER_H

#include <functional>
#include <memory>
#include <unordered_map>

#include "common.h"
#include "sniff.h"
#include "flows.h"

namespace flowparser {

static std::string IPToString(uint32_t ip) {
  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN);
  return std::string(str);
}

// Each flow is indexed by this value. Note that it does not contain a flow
// type. Only two flow types are supported - TCP and UDP and each has a
// separate map.
class FlowKey {
 public:
  FlowKey(const FlowKey& other)
      : src_(other.src_),
        dst_(other.dst_),
        sport_(other.sport_),
        dport_(other.dport_) {
  }

  FlowKey(const pcap::SniffIp& ip_header, const pcap::SniffTcp& tcp_header)
      : src_(ip_header.ip_src.s_addr),
        dst_(ip_header.ip_dst.s_addr),
        sport_(tcp_header.th_sport),
        dport_(tcp_header.th_dport) {
  }

  FlowKey(const pcap::SniffIp& ip_header, const pcap::SniffUdp& udp_header)
      : src_(ip_header.ip_src.s_addr),
        dst_(ip_header.ip_dst.s_addr),
        sport_(udp_header.uh_sport),
        dport_(udp_header.uh_dport) {
  }

  // In the case of ICMP a flow is considered to be all packets between the same
  // pair of endpoints (since there are no port numbers in ICMP)
  FlowKey(const pcap::SniffIp& ip_header, const pcap::SniffIcmp& icmp_header)
      : src_(ip_header.ip_src.s_addr),
        dst_(ip_header.ip_dst.s_addr),
        sport_(0),
        dport_(0) {
    ignore(icmp_header);
  }

  // Unknown transport traffic session is between the same pair of endpoints.
  FlowKey(const pcap::SniffIp& ip_header,
          const pcap::SniffUnknown& unknown_header)
      : src_(ip_header.ip_src.s_addr),
        dst_(ip_header.ip_dst.s_addr),
        sport_(0),
        dport_(0) {
    ignore(unknown_header);
  }

  bool operator==(const FlowKey &other) const {
    return (src_ == other.src_ && dst_ == other.dst_ && sport_ == other.sport_
        && dport_ == other.dport_);
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
    result = 37 * result + src_;
    result = 37 * result + dst_;
    result = 37 * result + sport_;
    result = 37 * result + dport_;
    return result;
  }

 private:
  const uint32_t src_;
  const uint32_t dst_;
  const uint16_t sport_;
  const uint16_t dport_;
};

struct KeyHasher {
  size_t operator()(const FlowKey& k) const {
    return k.hash();
  }
};

using std::function;
using std::pair;
using std::unique_ptr;

// The main parser class. This class stores tables with flow data and owns all
// flow instances. The first type is the flow class that will be stored, the
// second is the transport header from pcap.
template<typename T, typename P>
class Parser {
 public:
  typedef function<void(const FlowKey&, unique_ptr<T>)> FlowCallback;

  Parser(FlowCallback callback, uint64_t timeout, uint64_t soft_mem_limit,
         uint64_t hard_mem_limit)
      : flow_timeout_(timeout),
        soft_mem_limit_(soft_mem_limit),
        hard_mem_limit_(hard_mem_limit),
        last_rx_(0),
        callback_(callback) {
  }

  // Called when a new TCP packet arrives.
  Status HandlePkt(const pcap::SniffIp& ip_header, const P& transport_header,
                   uint64_t timestamp);

  // Times out flows that have expired.
  void CollectFlows() {
    auto mem_and_min_rx_time = TotalMemAndDeltaRx();
    uint64_t total_mem = mem_and_min_rx_time.first;
    uint64_t time_delta = mem_and_min_rx_time.second;

    if (total_mem < soft_mem_limit_) {
      PrivateCollectFlows(
          [this](const T& flow) {return flow.TimeLeft(last_rx_) <= 0;});
    } else {
      uint64_t hm = hard_mem_limit_;
      if (total_mem > hard_mem_limit_) {
        hm = total_mem;
      }

      double limit = (total_mem - soft_mem_limit_)
          / static_cast<double>(hm - soft_mem_limit_);

      PrivateCollectFlows([this, limit, time_delta](const T& flow)
      {
        // The idea is to time out a fraction of the flows that is proportional
        // to how much out of memory we are, starting with the ones that have
        // not seen traffic recently.
          double timeout_fraction =
          1 - (last_rx_ - flow.last_rx()) / static_cast<double>(time_delta);
          if (time_delta == 0) {
            timeout_fraction = 1;
          }

          return timeout_fraction <= limit;
        });
    }
  }

  // Times out all flow regardless of how close they are to expiring.
  void CollectAllFlows() {
    PrivateCollectFlows([](const T&) {return true;});
  }

 private:
  typedef std::pair<std::mutex, std::unique_ptr<T>> FlowValue;

  // Returns a tuple, the first element is the total amount of memory used by
  // the parser and the second one is the maximum difference between the minimum
  // last_rx_time among all flows and the parser's last_rx_time.
  std::pair<uint64_t, uint64_t> TotalMemAndDeltaRx();

  // Performs a collection. Each flow is considered for collection based on an
  // evaluation function that is given the remaining amount of time that the
  // flow has until it expires.
  void PrivateCollectFlows(std::function<bool(const T&)> eval_for_collection);

  // How long to wait before collecting flows. This is not in real time, but in
  // time measured as per pcap timestamps. This means that "time" has whatever
  // precision the pcap timestamps give (usually microseconds) and only advances
  // when packets are received.
  const uint64_t flow_timeout_;

  // Below this threshold no flows are forcibly evicted - they are kept in
  // memory until they time out.
  const uint64_t soft_mem_limit_;

  // Above the soft limit and up to the hard limit flows are progressively more
  // likely to get forcibly evicted when a collection happens.
  const uint64_t hard_mem_limit_;

  // Last time a packet was received.
  uint64_t last_rx_;

  // A map to store flows.
  std::unordered_map<FlowKey, FlowValue, KeyHasher> flows_table_;

  // A mutex for the flows table.
  std::mutex flows_table_mutex_;

  // When a TCP flow is complete it gets handed to this callback.
  const FlowCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(Parser);
};

typedef Parser<TCPFlow, pcap::SniffTcp> TCPFlowParser;
typedef Parser<UDPFlow, pcap::SniffUdp> UDPFlowParser;
typedef Parser<ICMPFlow, pcap::SniffIcmp> ICMPFlowParser;
typedef Parser<UnknownFlow, pcap::SniffUnknown> UnknownFlowParser;

}

#endif  /* FLOWPARSER_PARSER_H */
