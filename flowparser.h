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

enum LogSeverity {
  ERROR,
  INFO
};

class FlowParserConfig {
 public:
  typedef std::function<void(LogSeverity level, std::string what)> LogCallback;

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

  void SetLogCallback(LogCallback log_callback) {
    log_callback_ = log_callback;
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
  LogCallback log_callback_ = [](LogSeverity level, std::string what)
  { std::cout << std::to_string(level) << " -- " << what << "\n";};

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

  void SendErrorToCallback(const std::string& error) const {
    config_.log_callback_(LogSeverity::ERROR, error);
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
