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

  void TCPCallback(TCPFlowParser::FlowCallback tcp_callback) {
    tcp_callback_ = tcp_callback;
  }

  void UDPCallback(UDPFlowParser::FlowCallback udp_callback) {
    udp_callback_ = udp_callback;
  }

  void ICMPCallback(ICMPFlowParser::FlowCallback icmp_callback) {
    icmp_callback_ = icmp_callback;
  }

  void ESPCallback(ESPFlowParser::FlowCallback esp_callback) {
    esp_callback_ = esp_callback;
  }

  void BadStatusCallback(std::function<void(Status status)> status_callback) {
    bad_status_callback_ = status_callback;
  }

  void InfoCallback(std::function<void(const std::string&)> info_callback) {
    info_callback_ = info_callback;
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

  // How long to wait before a flow with no traffic is considered timed out.
  // This is in whatever precision pcap provides (microseconds by default).
  // The default value is 2min.
  uint64_t flow_timeout_;

  // A function that will be called when a failure during packet capture occurs.
  // By default will print the error to stdout.
  std::function<void(Status status)> bad_status_callback_ =
      [](Status status) {std::cout << "ERROR: " << status.ToString() << "\n";};

  // A function that will be called if the parser wants to send a text info
  // message. By default will print to stdout.
  std::function<void(const std::string&)> info_callback_ =
      [](const std::string& info) {std::cout << "INFO: " << info << "\n";};

  // A callback for TCP flows.
  TCPFlowParser::FlowCallback tcp_callback_ =
      [](const FlowKey&, unique_ptr<TCPFlow>) {};

  // A callback for UDP flows.
  UDPFlowParser::FlowCallback udp_callback_ =
      [](const FlowKey&, unique_ptr<UDPFlow>) {};

  // A callback for ICMP flows.
  ICMPFlowParser::FlowCallback icmp_callback_ =
      [](const FlowKey&, unique_ptr<ICMPFlow>) {};

  // A callback for ESP flows.
  ESPFlowParser::FlowCallback esp_callback_ =
      [](const FlowKey&, unique_ptr<ESPFlow>) {};

  friend class FlowParser;
};

class FlowParser {
 public:
  FlowParser(const FlowParserConfig& config)
      : config_(config),
        pcap_handle_(nullptr),
        datalink_offset_(0),
        tcp_parser_(config.tcp_callback_, config_.flow_timeout_),
        udp_parser_(config.udp_callback_, config_.flow_timeout_),
        icmp_parser_(config.icmp_callback_, config_.flow_timeout_),
        esp_parser_(config.esp_callback_, config_.flow_timeout_),
        collector_([this] {CollectAll();}, std::chrono::milliseconds(1000)) {
  }

  // Handles a single TCP packet. This function will do the appropriate casting
  // and send the packet to the TCPFlowParser.
  Status HandleTcp(uint64_t timestamp, size_t size_ip,
                   const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single UDP packet.
  Status HandleUdp(const uint64_t timestamp, size_t size_ip,
                   const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single ICMP packet.
  Status HandleIcmp(const uint64_t timestamp, size_t size_ip,
                    const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single ESP packet.
  Status HandleEsp(const uint64_t timestamp, size_t size_ip,
                   const pcap::SniffIp& ip_header, const uint8_t* pkt);

  size_t datalink_offset() const {
    return datalink_offset_;
  }

  // Called to handle a bad Status that needs to be forwarded to the client of
  // FlowParser.
  void HandleBadStatus(Status status) const {
    config_.bad_status_callback_(status);
  }

  Status RunTrace() {
    auto status = PcapOpen();
    if (!status.ok()) {
      return status;
    }

    collector_.Start();

    PcapLoop();

    collector_.Stop();
    tcp_parser_.CollectAllFlows();
    udp_parser_.CollectAllFlows();
    icmp_parser_.CollectAllFlows();
    esp_parser_.CollectAllFlows();

    return Status::kStatusOK;
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
    icmp_parser_.CollectFlows();
    esp_parser_.CollectFlows();
  }

  // A raw pointer to pcap. Will be cleaned up in destructor.
  pcap_t* pcap_handle_;

  // Depending on the data link the ip+tcp/udp headers may be at different
  // offsets. This is set in PcapOpen.
  size_t datalink_offset_;

  TCPFlowParser tcp_parser_;
  UDPFlowParser udp_parser_;
  ICMPFlowParser icmp_parser_;
  ESPFlowParser esp_parser_;

  // A periodic task to perform collection of flows.
  PeriodicTask collector_;
};

}

#endif  /* FLOWPARSER_FLOWPARSER_H */
