// Defines the main parser class.

#ifndef FLOWPARSER_PARSER_H
#define FLOWPARSER_PARSER_H

#include <functional>
#include <memory>
#include <unordered_map>
#include <list>
#include <random>

#include "common.h"
#include "sniff.h"
#include "flows.h"
#include "ptr_queue.h"

namespace flowparser {

class Parser;

class ParserConfig {
 public:
  typedef std::function<void(const Parser& parser)> PeriodicCallback;

  ParserConfig()
      : soft_mem_limit_(1 << 27),
        callback_period_(0),
        undersample_skip_count_(1) {
  }

  uint64_t soft_mem_limit() const {
    return soft_mem_limit_;
  }

  void set_soft_mem_limit(uint64_t soft_mem_limit) {
    soft_mem_limit_ = soft_mem_limit;
  }

  FlowConfig* mutable_flow_config() {
    return &new_flow_config_;
  }

  const FlowConfig& flow_config() const {
    return new_flow_config_;
  }

  uint64_t callback_period() const {
    return callback_period_;
  }

  inline PeriodicCallback periodic_callback() const {
    return periodic_callback_;
  }

  void set_periodic_callback(PeriodicCallback callback,
                             uint64_t callback_period) {
    periodic_callback_ = callback;
    callback_period_ = callback_period;
  }

  void set_undersample_skip_count(uint32_t undersample_skip_count) {
    undersample_skip_count_ = undersample_skip_count;
  }

  inline uint32_t undersample_skip_count() const {
    return undersample_skip_count_;
  }

 private:
  // Below this threshold no flows are forcibly evicted - they are kept in
  // memory forever.
  uint64_t soft_mem_limit_;

  // All new flows will get instantiated with this config.
  FlowConfig new_flow_config_;

  // A callback to be called.
  PeriodicCallback periodic_callback_;

  // How often the callback should be called. 0s switches it off.
  uint64_t callback_period_;

  // One packet will be sampled for every 'undersample_skip_count' number of
  // packets. Defaults to 1 (no undersamling).
  uint32_t undersample_skip_count_;
};

class Undersampler {
 public:
  Undersampler(size_t skip_count)
      : mean_(skip_count),
        undersample_token_bucket_(0),
        next_index_(0) {
    if (skip_count < 2) {
      throw std::logic_error("Undersample count too low");
    }

    PopulateSkipCounts();
  }

  bool ShouldSkip() {
    if (undersample_token_bucket_ == 0) {
      if (next_index_ == (1 << 10)) {
        next_index_ = 0;
        PopulateSkipCounts();
      }

      undersample_token_bucket_ = undersample_skip_counts_[next_index_++];
      return false;
    }

    undersample_token_bucket_--;
    return true;
  }

 private:
  static constexpr size_t kMask = (1 << 10) - 1;

  void PopulateSkipCounts() {
    size_t low_range = mean_ * 0.7;
    size_t high_range = mean_ * 1.3 + 0.5;

    std::default_random_engine generator;
    std::uniform_int_distribution<size_t> distribution(low_range, high_range);

    for (size_t i = 0; i < undersample_skip_counts_.size(); ++i) {
      undersample_skip_counts_[i] = distribution(generator);
    }
  }

  const size_t mean_;

  // A list of values to pick undersample skip counts from. Should have the skip
  // count value from the config as its mean.
  std::array<size_t, 1 << 10> undersample_skip_counts_;

  // A token bucket. When it is empty a packet is processed and the bucket is
  // refilled with the next sample from the skip_count list.
  uint64_t undersample_token_bucket_;

  uint64_t next_index_;
};

struct ParserInfo {
  uint64_t first_rx = 0;
  uint64_t last_rx = 0;
  uint64_t total_pkts_seen = 0;
  uint64_t flow_hits = 0;
  uint64_t flow_misses = 0;
  uint64_t mem_usage_bytes = 0;
  uint64_t num_flows_in_mem = 0;
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
      : parser_config_(parser_config),
        mem_usage_(0),
        queue_(queue),
        first_rx_(0),
        last_rx_(std::numeric_limits<uint64_t>::max()),
        next_period_start_(0),
        total_pkts_seen_(0),
        flow_hits_(0),
        flow_misses_(0) {
    if (parser_config_.undersample_skip_count() != 1) {
      undersampler_ = std::make_unique<Undersampler>(
          parser_config_.undersample_skip_count());
    }
  }

  void TCPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffTcp& tcp_header,
               uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, tcp_header.th_sport,
                                   tcp_header.th_dport });
    flow->TCPIpRx(ip_header, tcp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
    CallPeriodicCallbackIfNeeded();
  }

  void UDPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffUdp& udp_header,
               uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, udp_header.uh_sport,
                                   udp_header.uh_dport });
    flow->UDPIpRx(ip_header, udp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
    CallPeriodicCallbackIfNeeded();
  }

  void ICMPIpRx(const pcap::SniffIp& ip_header,
                const pcap::SniffIcmp& icmp_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    flow->ICMPIpRx(ip_header, icmp_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
    CallPeriodicCallbackIfNeeded();
  }

  void UnknownIpRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    flow->UnknownIpRx(ip_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateFirsLastRx(timestamp);
    CallPeriodicCallbackIfNeeded();
  }

  ParserInfo GetInfo() const {
    std::lock_guard<std::mutex> lock(mu_);
    return GetInfoNoLock();
  }

  ParserInfo GetInfoNoLock() const {
    ParserInfo info;

    info.first_rx = first_rx_;
    info.last_rx = last_rx_;
    info.total_pkts_seen = total_pkts_seen_;
    info.flow_hits = flow_hits_;
    info.flow_misses = flow_misses_;
    info.mem_usage_bytes = mem_usage_;
    info.num_flows_in_mem = flows_table_.size();

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
    if (mem_usage_ > parser_config_.soft_mem_limit()) {
      CollectLast();
    }
  }

  Flow* FindOrNewFlow(uint64_t timestamp, const FlowKey& key) {
    const auto& it = flows_table_.find(key);
    if (it != flows_table_.end()) {
      // Move the flow to the front of the list
      flows_.splice(flows_.begin(), flows_, it->second);
      flow_hits_++;

      return it->second->get();
    }

    auto flow_ptr = std::make_unique<Flow>(timestamp, key,
                                           parser_config_.flow_config());
    flow_misses_++;
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
    total_pkts_seen_++;
  }

  void CallPeriodicCallbackIfNeeded() {
    if (parser_config_.callback_period() == 0) {
      return;
    }

    if (next_period_start_ == 0) {
      next_period_start_ = last_rx_ + parser_config_.callback_period();
      return;
    }

    if (last_rx_ >= next_period_start_) {
      parser_config_.periodic_callback()(*this);
      next_period_start_ += parser_config_.callback_period();
    }
  }

  // Configuration for the parser
  const ParserConfig parser_config_;

  // Memory used in bytes
  size_t mem_usage_;

  // A map to store flows.
  FlowMap flows_table_;

  // A list of flows, in LRU order.
  FlowList flows_;

  // When a flow is evicted it is added to this queue.
  std::shared_ptr<FlowQueue> queue_;

  // Timestamp of first packet reception.
  uint64_t first_rx_;

  // Timestamp of most recent packet reception.
  uint64_t last_rx_;

  // The beginning of the next period the periodic callback should be executed.
  uint64_t next_period_start_;

  // The total number of packets seen by the parser.
  uint64_t total_pkts_seen_;

  // The number of times a new packet comes in and its flow is in memory.
  uint64_t flow_hits_;

  // The number of times a new packet comes in an a new flow needs to be
  // allocated for it.
  uint64_t flow_misses_;

  // Only populated if the config requires it.
  std::unique_ptr<Undersampler> undersampler_;

  // A mutex
  mutable std::mutex mu_;

  friend class ParserIterator;
  friend class ParserIteratorNoLock;

  DISALLOW_COPY_AND_ASSIGN(Parser);
};

class ParserIteratorNoLock {
 public:
  ParserIteratorNoLock(const Parser& parser)
      : it_(parser.flows_table_.begin()),
        end_it_(parser.flows_table_.end()) {
  }

  const Flow* Next() {
    if (it_ == end_it_) {
      return nullptr;
    }

    return ((it_)++)->second->get();
  }

 private:

  // Iterator into the flow table.
  typename Parser::FlowMap::const_iterator it_;

  // The end of the flow table.
  typename Parser::FlowMap::const_iterator end_it_;

  DISALLOW_COPY_AND_ASSIGN(ParserIteratorNoLock);
};

class ParserIterator {
 public:
  ParserIterator(const Parser& parser)
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
  typename Parser::FlowMap::const_iterator it_;

  // The end of the flow table.
  typename Parser::FlowMap::const_iterator end_it_;

  DISALLOW_COPY_AND_ASSIGN(ParserIterator);
};

}

#endif  /* FLOWPARSER_PARSER_H */
