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
  }

  // For ESP the endpoints and the SPI is considered.
  FlowKey(const pcap::SniffIp& ip_header, const pcap::SniffEsp& esp_header)
        : src_(ip_header.ip_src.s_addr),
          dst_(ip_header.ip_dst.s_addr),
          sport_(esp_header.spi & 0x0000ffff),
          dport_(esp_header.spi >> 16) {
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

  Parser(FlowCallback callback, uint64_t timeout)
      : flow_timeout_(timeout),
        last_rx_(0),
        callback_(callback) {
  }

  // Called when a new TCP packet arrives.
  Status HandlePkt(const pcap::SniffIp& ip_header, const P& transport_header,
                   uint64_t timestamp);

  // Times out flows that have expired.
  void CollectFlows() {
    PrivateCollectFlows([](int64_t time_left) {return time_left <= 0;});
  }

  // Times out all flow regardless of how close they are to expiring.
  void CollectAllFlows() {
    PrivateCollectFlows([](int64_t time_left) {return true;});
  }

 private:
  typedef std::pair<std::mutex, std::unique_ptr<T>> FlowValue;

  // Performs a collection. Each flow is considered for collection based on an
  // evaluation function that is given the remaining amount of time that the
  // flow has until it expires.
  void PrivateCollectFlows(std::function<bool(int64_t)> eval_for_collection);

  // How long to wait before collecting flows. This is not in real time, but in
  // time measured as per pcap timestamps. This means that "time" has whatever
  // precision the pcap timestamps give (usually microseconds) and only advances
  // when packets are received.
  const uint64_t flow_timeout_;

  // Last time a packet was received.
  uint64_t last_rx_;

  // A map to store TCP flows.
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
typedef Parser<ESPFlow, pcap::SniffEsp> ESPFlowParser;

}

#endif  /* FLOWPARSER_PARSER_H */
