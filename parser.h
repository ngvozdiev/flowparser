// Defines the main parser class.

#ifndef FLOWPARSER_PARSER_H
#define FLOWPARSER_PARSER_H

#include <functional>
#include <memory>
#include <unordered_map>
#include <list>

#include "common.h"
#include "sniff.h"
#include "flows.h"
#include "ptr_queue.h"

namespace flowparser {

struct ParserConfig {
  typedef std::function<void(uint64_t curr_time)> PeriodicCallback;

  ParserConfig()
      : soft_mem_limit(1 << 27) {
  }

  // Below this threshold no flows are forcibly evicted - they are kept in
  // memory forever.
  uint64_t soft_mem_limit;

  // All new flows will get instantiated with this config.
  FlowConfig new_flow_config;
};

class PeriodicCallback {
 private:
  std::function<void(uint64_t time_now)> callback_;
  uint64_t period_;
  uint64_t
};

struct ParserInfo {
  uint64_t first_rx = 0;
  uint64_t last_rx = 0;
};

using std::function;
using std::pair;
using std::unique_ptr;

// The main parser class. This class stores tables with flow data and owns all
// flow instances.
class Parser {
 public:
  typedef PtrQueue<Flow, 1 << 10> FlowQueue;

  Parser(const ParserConfig& parser_config, std::shared_ptr<FlowQueue> queue)
      : parser_config(parser_config),
        mem_usage_(0),
        queue_(queue),
        first_rx_(0),
        last_rx_(std::numeric_limits<uint64_t>::max()) {
  }

  void TCPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffTcp& tcp_header,
               uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    Flow* flow = FindOrNewFlow(timestamp, { ip_header, tcp_header.th_sport,
                                   tcp_header.th_dport });
    flow->TCPIpRx(ip_header, tcp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
  }

  void UDPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffUdp& udp_header,
               uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    Flow* flow = FindOrNewFlow(timestamp, { ip_header, udp_header.uh_sport,
                                   udp_header.uh_dport });
    flow->UDPIpRx(ip_header, udp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
  }

  void ICMPIpRx(const pcap::SniffIp& ip_header,
                const pcap::SniffIcmp& icmp_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    flow->ICMPIpRx(ip_header, icmp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
  }

  void UnknownIpRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    flow->UnknownIpRx(ip_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
  }

  ParserInfo GetInfo() const {
    ParserInfo info;

    std::lock_guard<std::mutex> lock(mu_);
    info.first_rx = first_rx_;
    info.last_rx = last_rx_;

    return info;
  }

  // Collects all flows
  void CollectAllFlows() {
    std::lock_guard<std::mutex> lock(mu_);
    while (!flows_.empty()) {
      CollectLast();
    }

    if (queue_) {
      queue_->Close();
    }
  }

 private:
  typedef std::list<std::unique_ptr<Flow>> FlowList;
  typedef std::unordered_map<FlowKey, typename FlowList::iterator, KeyHasher> FlowMap;

  // Collects the least recently accessed flow.
  void CollectLast() {
    if (flows_.empty()) {
      return;
    }

    std::unique_ptr<Flow> flow = std::move(flows_.back());
    flows_table_.erase(flow->key());
    flows_.pop_back();

    mem_usage_ -= (flow->SizeBytes());

    if (queue_) {
      queue_->ProduceOrBlock(std::move(flow));
    }
  }

  // Collects one or more flows to make sure they obey
  void CollectIfLimitExceeded() {
    if (mem_usage_ > parser_config.soft_mem_limit) {
      CollectLast();
    }
  }

  Flow* FindOrNewFlow(uint64_t timestamp, const FlowKey& key) {
    const auto& it = flows_table_.find(key);
    if (it != flows_table_.end()) {
      // Move the flow to the front of the list
      flows_.splice(flows_.begin(), flows_, it->second);

      return it->second->get();
    }

    auto flow_ptr = std::make_unique<Flow>(timestamp, key,
                                           parser_config.new_flow_config);
    mem_usage_ += sizeof(Flow);

    flows_.push_front(std::move(flow_ptr));
    flows_table_.insert(std::make_pair(key, flows_.begin()));
    return flows_.begin()->get();
  }

  void UpdateFirsLastRx(uint64_t timestamp) {
    if (first_rx_ == 0) {
      first_rx_ = timestamp;
    }

    last_rx_ = timestamp;
  }

  // Configuration for the parser
  const ParserConfig parser_config;

  // Memory used in bytes
  size_t mem_usage_;

  // A map to store flows.
  FlowMap flows_table_;

  // A list of flows, in LRU order.
  FlowList flows_;

  // When a flow is evicted it is added to this queue.
  std::shared_ptr<FlowQueue> queue_;

  // Timestamp of first packet reception
  uint64_t first_rx_;

  // Timestamp of most recent packet reception
  uint64_t last_rx_;

  // A mutex
  mutable std::mutex mu_;

  friend class ParserIterator;

  DISALLOW_COPY_AND_ASSIGN(Parser);
};

class ParserIterator {
 public:
  ParserIterator(Parser& parser)
      : lock_guard_(parser.mu_),
        it_(parser.flows_table_.begin()),
        end_it_(parser.flows_table_.end()) {
  }

  const Flow* Next() {
    if (it_ == end_it_) {
      return nullptr;
    }

    return ((it_)++)->second->get();
  }

 private:
  // A lock to keep the mutex until the iterator object goes out of scope.
  const std::lock_guard<std::mutex> lock_guard_;

  // Iterator into the flow table.
  typename Parser::FlowMap::iterator it_;

  // The end of the flow table.
  typename Parser::FlowMap::iterator end_it_;

  DISALLOW_COPY_AND_ASSIGN(ParserIterator);
};

}

#endif  /* FLOWPARSER_PARSER_H */
