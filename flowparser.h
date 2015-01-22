#ifndef FLOWPARSER_FLOWPARSER_H
#define FLOWPARSER_FLOWPARSER_H

#include <pcap/pcap.h>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

#include "parser.h"
#include "sniff.h"

namespace flowparser {

static constexpr uint64_t kMillion = 1000000;

class FlowParserConfig {
 public:
  FlowParserConfig()
      : offline_(false),
        snapshot_len_(100),
        bpf_filter_("ip") {
  }

  void OfflineTrace(const std::string& filename) {
    source_ = filename;
    offline_ = true;
  }

  void OnlineTrace(const std::string& iface) {
    source_ = iface;
    offline_ = false;
  }

  void FlowQueue(std::shared_ptr<Parser::FlowQueue> flow_queue) {
    flow_queue_ = flow_queue;
  }

  void ExceptionCallback(
      std::function<void(const std::exception& ex)> ex_callback) {
    ex_callback_ = ex_callback;
  }

  void InfoCallback(std::function<void(const std::string&)> info_callback) {
    info_callback_ = info_callback;
  }

  ParserConfig* MutableParserConfig() {
    return &parser_config_;
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

  // Each parser will be constructed with this config.
  ParserConfig parser_config_;

  // A function that will be called when a failure during packet capture occurs.
  // By default will print the error to stdout.
  std::function<void(const std::exception& ex)> ex_callback_ =
      [](const std::exception& ex) {std::cout << "ERROR: " << ex.what() << "\n";};

  // A function that will be called if the parser wants to send a text info
  // message. By default will print to stdout.
  std::function<void(const std::string&)> info_callback_ =
      [](const std::string& info) {std::cout << "INFO: " << info << "\n";};

  // A callback for flows.
  std::shared_ptr<Parser::FlowQueue> flow_queue_;

  friend class FlowParser;
};

class FlowParser {
 public:
  FlowParser(const FlowParserConfig& config)
      : config_(config),
        pcap_handle_(nullptr),
        datalink_offset_(0),
        parser_(config.parser_config_, config.flow_queue_) {
  }

  ~FlowParser() {
    if (pcap_handle_ != nullptr) {
      pcap_close(pcap_handle_);
    }
  }

  // Handles a single TCP packet. This function will do the appropriate casting
  // and send the packet to the TCPFlowParser.
  void HandleTcp(uint64_t timestamp, size_t size_ip,
                 const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single UDP packet.
  void HandleUdp(const uint64_t timestamp, size_t size_ip,
                 const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single ICMP packet.
  void HandleIcmp(const uint64_t timestamp, size_t size_ip,
                  const pcap::SniffIp& ip_header, const uint8_t* pkt);

  // Handles a single packet from an unknown transport protocol.
  void HandleUnknown(const uint64_t timestamp, const pcap::SniffIp& ip_header);

  size_t datalink_offset() const {
    return datalink_offset_;
  }

  const Parser& parser() const {
    return parser_;
  }

  // Called to handle a bad Status that needs to be forwarded to the client of
  // FlowParser.
  void HandleException(const std::exception& ex) const {
    config_.ex_callback_(ex);
  }

  void RunTrace() {
    PcapOpen();
    PcapLoop();

    parser_.CollectAllFlows();
  }

 private:
  // Opens the source, compiles the filter provided (if any) and checks that the
  // datalink is supported.
  void PcapOpen();

  void PcapLoop();

  // The configuration to be used.
  const FlowParserConfig config_;

  // A raw pointer to pcap. Will be cleaned up in destructor.
  pcap_t* pcap_handle_;

  // Depending on the data link the ip+tcp/udp headers may be at different
  // offsets. This is set in PcapOpen.
  size_t datalink_offset_;

  Parser parser_;
};

}

#endif  /* FLOWPARSER_FLOWPARSER_H */
