#ifndef FLOWPARSER_FLOWPARSER_H
#define FLOWPARSER_FLOWPARSER_H

#include "sniff.h"
#include "parser.h"
#include "periodic_runner.h"

namespace flowparser {

static constexpr uint64_t kMillion = 1000000;

class FlowParserConfig {
 public:
  FlowParserConfig()
      : offline_(false),
        snapshot_len_(100),
        bpf_filter_("ip"),
        bad_status_callback_([](Status status) {
          std::cout << "ERROR: " << status.ToString() << "\n";}),
        info_callback_([](const std::string& info) {
          std::cout << "INFO: " << info << "\n";
        }),
        flow_timeout_(2 * 60 * kMillion) {
  }

  void OfflineTrace(const std::string& filename) {
    source_ = filename;
    offline_ = true;
  }

  void OnlineTrace(const std::string& iface) {
    source_ = iface;
    offline_ = false;
  }

 private:
  // The source that packets will be read from. Can be either a filename or a
  // device name.
  std::string source_;

  // If the source is a filename offline_ should be set to true.
  bool offline_;

  // Snapshot length passed to pcap. Only used if capturing from a live device.
  size_t snapshot_len_;

  // The BPF filter to use when capturing.
  std::string bpf_filter_;

  // A function that will be called when a failure during packet capture occurs.
  // By default will print the error to stdout.
  std::function<void(Status status)> bad_status_callback_;

  // A function that will be called if the parser wants to send a text info
  // message. By default will print to stdout.
  std::function<void(const std::string&)> info_callback_;

  // How long to wait before a flow with no traffic is considered timed out.
  // This is in whatever precision pcap provides (microseconds by default).
  // The default value is 2min.
  uint64_t flow_timeout_;

  friend class FlowParser;
};

class FlowParser {
 public:
  FlowParser(const FlowParserConfig& config,
             TCPFlowParser::FlowCallback tcp_callback,
             UDPFlowParser::FlowCallback udp_callback)
      : config_(config),
        pcap_handle_(nullptr),
        datalink_offset_(0),
        tcp_parser_(tcp_callback, config_.flow_timeout_),
        udp_parser_(udp_callback, config_.flow_timeout_),
        collector_([this] {CollectAll();}, std::chrono::milliseconds(1000)) {
  }

  // Handles a single TCP packet. This function will do the appropriate casting
  // and send the packet to the TCPFlowParser.
  Status HandleTcp(uint64_t timestamp, size_t size_ip,
                   const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single UDP packet.
  Status HandleUdp(const uint64_t timestamp, size_t size_ip,
                   const pcap::SniffIp& ip_header, const uint8_t* pkt);

  size_t datalink_offset() const {
    return datalink_offset_;
  }

  // Called to handle a bad Status that needs to be forwarded to the client of
  // FlowParser.
  void HandleBadStatus(Status status) const {
    config_.bad_status_callback_(status);
  }

 private:
  // The configuration to be used.
  const FlowParserConfig config_;

  // Opens the source, compiles the filter provided (if any) and checks that the
  // datalink is supported.
  Status PcapOpen();

  void PcapLoop();

  void CollectAll() {
    tcp_parser_.CollectFlows();
    udp_parser_.CollectFlows();
  }

  // A raw pointer to pcap. Will be cleaned up in destructor.
  pcap_t* pcap_handle_;

  // Depending on the data link the ip+tcp/udp headers may be at different
  // offsets. This is set in PcapOpen.
  size_t datalink_offset_;

  TCPFlowParser tcp_parser_;
  UDPFlowParser udp_parser_;

  // A periodic task to perform collection of flows.
  PeriodicTask collector_;
};

}

#endif  /* FLOWPARSER_FLOWPARSER_H */
