#ifndef FLOWPARSER_FLOWPARSER_H
#define FLOWPARSER_FLOWPARSER_H

#include <atomic>

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
        flow_timeout_(2 * 60 * kMillion),
        soft_mem_limit_(1 << 27),
        hard_mem_limit_(1 << 28) {
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

  void UnknownCallback(UnknownFlowParser::FlowCallback unknown_callback) {
    unknown_callback_ = unknown_callback;
  }

  void BadStatusCallback(std::function<void(Status status)> status_callback) {
    bad_status_callback_ = status_callback;
  }

  void InfoCallback(std::function<void(const std::string&)> info_callback) {
    info_callback_ = info_callback;
  }

  void MemoryLimits(uint64_t soft, uint64_t hard) {
    soft_mem_limit_ = soft;
    hard_mem_limit_ = hard;
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

  // The soft memory limit. Look at comment in parser.h for description.
  uint64_t soft_mem_limit_;

  // The hard memory limit. Look at comment in parser.h for description.
  uint64_t hard_mem_limit_;

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
  UnknownFlowParser::FlowCallback unknown_callback_ =
      [](const FlowKey&, unique_ptr<UnknownFlow>) {};

  friend class FlowParser;
};

class FlowParser {
 public:
  FlowParser(const FlowParserConfig& config)
      : config_(config),
        first_rx_(0),
        last_rx_(0),
        pcap_handle_(nullptr),
        datalink_offset_(0),
        tcp_parser_(config.tcp_callback_, config_.flow_timeout_,
                    config.soft_mem_limit_, config.hard_mem_limit_),
        udp_parser_(config.udp_callback_, config_.flow_timeout_,
                    config.soft_mem_limit_, config.hard_mem_limit_),
        icmp_parser_(config.icmp_callback_, config_.flow_timeout_,
                     config.soft_mem_limit_, config.hard_mem_limit_),
        unknown_parser_(config.unknown_callback_, config_.flow_timeout_,
                        config.soft_mem_limit_, config.hard_mem_limit_),
        collector_([this] {CollectAll();}, std::chrono::milliseconds(1000)) {
  }

  ~FlowParser() {
    if (pcap_handle_ != nullptr) {
      pcap_close(pcap_handle_);
    }
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

  // Handles a single packet from an unknown transport protocol.
  Status HandleUnknown(const uint64_t timestamp, size_t size_ip,
                       const pcap::SniffIp& ip_header);

  size_t datalink_offset() const {
    return datalink_offset_;
  }

  // The timestamp of the first packet seen by the flowparser.
  uint64_t first_rx() const {
    return first_rx_.load();
  }

  // The timestamp of the last packet seen by the flowparser.
  uint64_t last_rx() const {
    return last_rx_.load();
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
    unknown_parser_.CollectAllFlows();

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
    unknown_parser_.CollectFlows();
  }

  // Updates the first and the last rx times.
  void UpdateFirstLastRx(uint64_t timestamp) {
    // Since we just want to update a couple of counters using mutexes would be
    // heavy-handed. Instead we can use a couple of CAS operations.

    uint64_t tmp = 0;
    std::atomic_compare_exchange_strong(&first_rx_, &tmp, timestamp);
    std::atomic_exchange(&last_rx_, timestamp);
  }

  // The first time a packet was received at any parser.
  std::atomic<uint64_t> first_rx_;

  // The most recent time a packet was received at any parser.
  std::atomic<uint64_t> last_rx_;

  // A raw pointer to pcap. Will be cleaned up in destructor.
  pcap_t* pcap_handle_;

  // Depending on the data link the ip+tcp/udp headers may be at different
  // offsets. This is set in PcapOpen.
  size_t datalink_offset_;

  TCPFlowParser tcp_parser_;
  UDPFlowParser udp_parser_;
  ICMPFlowParser icmp_parser_;
  UnknownFlowParser unknown_parser_;

  // A periodic task to perform collection of flows.
  PeriodicTask collector_;
};

}

#endif  /* FLOWPARSER_FLOWPARSER_H */
