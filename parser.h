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
      : soft_mem_limit_(1 << 30),
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

  const std::vector<PeriodicCallback>& periodic_callbacks() const {
    return periodic_callbacks_;
  }

  void add_periodic_callback(PeriodicCallback callback) {
    periodic_callbacks_.push_back(callback);
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
  std::vector<PeriodicCallback> periodic_callbacks_;

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
  uint64_t total_tcp_syn_or_fin_pkts_seen = 0;
  uint64_t flow_hits = 0;
  uint64_t flow_misses = 0;
  uint64_t mem_usage_bytes = 0;
  uint64_t num_flows_in_mem = 0;
  uint64_t tcp_flows_in_mem = 0;
  uint64_t udp_flows_in_mem = 0;
  uint64_t icmp_flows_in_mem = 0;
  double pkts_seen_per_sec = 0.0;
  double ip_len_seen_per_sec = 0.0;
  double payload_seen_per_sec = 0.0;
  double tcp_payload_seen_per_sec = 0.0;
};

struct RunningAverage {
  void EndSecond() {
    if (first_second) {
      average = total_this_second;
    } else {
      average = 0.1 * average + 0.9 * total_this_second;
    }

    total_this_second = 0;
    first_second = false;
  }

  bool first_second = true;
  double average = 0;
  uint64_t total_this_second = 0;
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
        last_rx_(0),
        next_second_start_(0),
        total_pkts_seen_(0),
        total_tcp_syn_or_fin_pkts_seen_(0),
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
    uint16_t payload = flow->TCPIpRx(ip_header, tcp_header, timestamp,
                                     &mem_usage_);

    if (tcp_header.th_flags & TH_SYN) {
      total_tcp_syn_or_fin_pkts_seen_++;
    } else if (!(flow->tcp_flags_or() & TH_SYN)
        && (tcp_header.th_flags & TH_FIN)) {
      total_tcp_syn_or_fin_pkts_seen_++;
    }

    CollectIfLimitExceeded();
    UpdateStats(timestamp, ntohs(ip_header.ip_len), payload, true);
    CallPeriodicCallbacks();
  }

  void UDPIpRx(const pcap::SniffIp& ip_header, const pcap::SniffUdp& udp_header,
               uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, udp_header.uh_sport,
                                   udp_header.uh_dport });
    uint16_t payload = flow->UDPIpRx(ip_header, udp_header, timestamp,
                                     &mem_usage_);
    CollectIfLimitExceeded();
    UpdateStats(timestamp, ntohs(ip_header.ip_len), payload, false);
    CallPeriodicCallbacks();
  }

  void ICMPIpRx(const pcap::SniffIp& ip_header,
                const pcap::SniffIcmp& icmp_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    uint16_t payload = flow->ICMPIpRx(ip_header, icmp_header, timestamp,
                                      &mem_usage_);
    CollectIfLimitExceeded();
    UpdateStats(timestamp, ntohs(ip_header.ip_len), payload, false);
    CallPeriodicCallbacks();
  }

  void UnknownIpRx(const pcap::SniffIp& ip_header, uint64_t timestamp) {
    std::lock_guard<std::mutex> lock(mu_);
    if (undersampler_ && undersampler_->ShouldSkip()) {
      return;
    }

    Flow* flow = FindOrNewFlow(timestamp, { ip_header, 0, 0 });
    uint16_t payload = flow->UnknownIpRx(ip_header, timestamp, &mem_usage_);
    CollectIfLimitExceeded();
    UpdateStats(timestamp, ntohs(ip_header.ip_len), payload, false);
    CallPeriodicCallbacks();
  }

  uint64_t last_rx() const {
    return last_rx_;
  }

  std::unique_lock<std::mutex> GetLock() const {
    std::unique_lock<std::mutex> lock(mu_);
    return std::move(lock);
  }

  ParserInfo GetInfoNoLock() const {
    ParserInfo info;

    info.first_rx = first_rx_;
    info.last_rx = last_rx_;
    info.total_pkts_seen = total_pkts_seen_;
    info.total_tcp_syn_or_fin_pkts_seen = total_tcp_syn_or_fin_pkts_seen_;
    info.flow_hits = flow_hits_;
    info.flow_misses = flow_misses_;
    info.mem_usage_bytes = mem_usage_;
    info.num_flows_in_mem = flows_table_.size();
    info.tcp_flows_in_mem = CountFlows(IPPROTO_TCP);
    info.udp_flows_in_mem = CountFlows(IPPROTO_UDP);
    info.icmp_flows_in_mem = CountFlows(IPPROTO_ICMP);

    info.ip_len_seen_per_sec = ip_len_seen_running_avg_.average;
    info.payload_seen_per_sec = payload_seen_running_avg_.average;
    info.pkts_seen_per_sec = pkts_seen_running_avg_.average;
    info.tcp_payload_seen_per_sec = tcp_payload_seen_running_avg_.average;

    return info;
  }

  uint64_t GetOriginalNumFlowsEstimate(uint32_t sample_skip_count) const {
    if (sample_skip_count < 2) {
      return flows_table_.size();
    }

    size_t syn_flows = 0;

    for (const auto& flow_ptr : flows_) {
      uint8_t flags = flow_ptr->tcp_flags_or();
      uint64_t pkts_seen = flow_ptr->pkts_seen();

      if ((flags & TH_SYN) && pkts_seen == 1) {
        syn_flows++;
      }
    }

    size_t other_flows = flows_.size() - syn_flows;

    return syn_flows * sample_skip_count + other_flows;
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

  uint64_t CountFlows(uint8_t ip_proto) const {
    uint64_t count = 0;
    for (const auto& flow_ptr : flows_) {
      if (flow_ptr->key().protocol() == ip_proto) {
        ++count;
      }
    }

    return count;
  }

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

  void UpdateStats(uint64_t timestamp, uint16_t ip_len, uint16_t payload,
                   bool tcp) {
    if (first_rx_ == 0) {
      first_rx_ = timestamp;
    }

    if (timestamp < last_rx_) {
      throw std::logic_error("Non-incrementing timestamps");
    }

    last_rx_ = timestamp;
    total_pkts_seen_++;

    pkts_seen_running_avg_.total_this_second++;
    ip_len_seen_running_avg_.total_this_second += ip_len;
    payload_seen_running_avg_.total_this_second += payload;

    if (tcp) {
      tcp_payload_seen_running_avg_.total_this_second += payload;
    }
  }

  void UpdateAverages() {
    ip_len_seen_running_avg_.EndSecond();
    payload_seen_running_avg_.EndSecond();
    tcp_payload_seen_running_avg_.EndSecond();
    pkts_seen_running_avg_.EndSecond();
  }

  void CallPeriodicCallbacks() {
    if (next_second_start_ == 0) {
      next_second_start_ = last_rx_ + kMillion;
      return;
    }

    if (last_rx_ >= next_second_start_) {
      UpdateAverages();
      for (const auto& callback : parser_config_.periodic_callbacks()) {
        callback(*this);
      }

      next_second_start_ += kMillion;
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
  uint64_t next_second_start_;

  // Running average of the ip len seen.
  RunningAverage ip_len_seen_running_avg_;

  // Running average of the payloads (ip_len - headers) seen.
  RunningAverage payload_seen_running_avg_;

  // Running average of the TCP payloads seen.
  RunningAverage tcp_payload_seen_running_avg_;

  // Running average of the packets seen.
  RunningAverage pkts_seen_running_avg_;

  // The total number of packets seen by the parser.
  uint64_t total_pkts_seen_;

  // Total number of packets seen that have the SYN bit set.
  uint64_t total_tcp_syn_or_fin_pkts_seen_;

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

class ParserIterator {
 public:
  ParserIterator(const Parser& parser)
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

  DISALLOW_COPY_AND_ASSIGN(ParserIterator);
};

}

#endif  /* FLOWPARSER_PARSER_H */
