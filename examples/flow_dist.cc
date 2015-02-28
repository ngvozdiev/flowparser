#include "flow_dist.h"

#include <cstdint>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <thread>
//#include <armadillo>

#include "../common.h"
#include "../flowparser.h"
#include "../flows.h"
#include "../parser.h"

namespace flowparser {
namespace example {
namespace flow_dist {

//static unsigned long GcdUi(unsigned long x, unsigned long y) {
//  unsigned long t;
//  if (y < x) {
//    t = x;
//    x = y;
//    y = t;
//  }
//  while (y > 0) {
//    t = y;
//    y = x % y;
//    x = t; /* y1 <- x0 % y0 ; x1 <- y0 */
//  }
//  return x;
//}
//
//unsigned long Binomial(unsigned long n, unsigned long k) {
//  unsigned long d, g, r = 1;
//  if (k == 0)
//    return 1;
//  if (k == 1)
//    return n;
//  if (k >= n)
//    return (k == n);
//  if (k > n / 2)
//    k = n - k;
//  for (d = 1; d <= k; d++) {
//    if (r >= ULONG_MAX / n) { /* Possible overflow */
//      unsigned long nr, dr; /* reduced numerator / denominator */
//      g = GcdUi(n, d);
//      nr = n / g;
//      dr = d / g;
//      g = GcdUi(r, dr);
//      r = r / g;
//      dr = dr / g;
//      if (r >= ULONG_MAX / nr)
//        return 0; /* Unavoidable overflow */
//      r *= nr;
//      r /= dr;
//      n--;
//    } else {
//      r *= n--;
//      r /= d;
//    }
//  }
//  return r;
//}
//
//double ProbSeeXPkts(double sample_prob, size_t flow_size, size_t x) {
//  return pow(sample_prob, x) * pow(1 - sample_prob, flow_size - x)
//      * Binomial(flow_size, x);
//}

//double ProbSeeAtLeastXPkts(double loss_prob, size_t flow_size, size_t x) {
//  if (flow_size > 1000 || loss_prob == 0) {
//    return 1;
//  }
//
//  double total_sum = 0;
//  for (size_t i = x; i < flow_size + 1; ++i) {
//    total_sum += ProbSeeXPkts(loss_prob, flow_size, i);
//  }
//
//  return total_sum;
//}

// Creates a NxN matrix where the i,j member is ProbSeeXPkts(sample_prob, j, i)
//std::unique_ptr<arma::mat> GetBinomialMatrix(size_t n, double sample_prob) {
//  auto matrix_ptr = std::make_unique<arma::mat>(n, n);
//
//  for (size_t i = 1; i < n + 1; ++i) {
//    for (size_t j = 1; j < n + 1; ++j) {
//      if (i > j) {
//        (*matrix_ptr)(i - 1, j - 1) = 0;
//      } else {
//        (*matrix_ptr)(i - 1, j - 1) = ProbSeeXPkts(sample_prob, j, i);
//      }
//    }
//  }
//
//  return matrix_ptr;
//}

typedef std::vector<std::pair<double, uint64_t>> ClusterVector;

// Given a vector of sampled flow frequency sizes, will reconstruct the original
// flow frequencies vector.
//std::unique_ptr<arma::colvec> GetOriginalFlowFrequencies(
//    const arma::colvec& sample_frequencies, double sample_prob) {
//  size_t max_flow_size = sample_frequencies.n_rows;
//  auto return_ptr = std::make_unique<arma::colvec>(max_flow_size);
//  return_ptr->zeros();
//
//  auto bin_matrix = GetBinomialMatrix(max_flow_size, sample_prob);
//  bin_matrix->print("Bin matrix:");
//
//  arma::solve(sample_frequencies, *bin_matrix).print("Res:");
//
//  if (!arma::solve(*return_ptr, *bin_matrix, sample_frequencies)) {
//    throw std::logic_error("Could not solve");
//  }
//
//  return return_ptr;
//}

uint64_t GetFlowPktCountNoSeq(const Flow& flow, uint64_t time_threshold) {
  FlowIterator it(flow);
  const TrackedFields* fields_ptr = nullptr;

  if (flow.last_rx() < time_threshold) {
    return 0;
  }

  uint64_t count = 0;
  while ((fields_ptr = it.NextOrNull()) != nullptr) {
    if (fields_ptr->timestamp() < time_threshold) {
      continue;
    }

    count++;
  }

  return count;
}

std::pair<uint64_t, uint64_t> GetFlowActiveInterval(const Flow& flow,
bool filter_no_payload) {
  FlowIterator it(flow);
  const TrackedFields* fields_ptr = nullptr;

  uint64_t start = 0;
  uint64_t end = 0;
  while ((fields_ptr = it.NextOrNull()) != nullptr) {
    if (filter_no_payload && fields_ptr->payload_size() == 0) {
      continue;
    }

    if (fields_ptr->tcp_flags() & TH_FIN) {
      continue;
    }

    if (start == 0) {
      start = fields_ptr->timestamp();
    }

    end = fields_ptr->timestamp();
  }

  return {start, end};
}

//void BinFlowInActiveFlows(const Flow& flow,
//                          std::map<uint64_t, uint32_t>* active_flows) {
//  auto flow_start_end = GetFlowActiveInterval(flow, true);
//  uint64_t start_sec = (flow_start_end.first / kMillion) * kMillion;
//  for (uint64_t t = start_sec; t < flow_start_end.second; t += kMillion) {
//    (*active_flows)[t] += 1;
//  }
//}

//uint64_t GetFlowPktCountSeq(const Flow& flow, uint64_t time_threshold) {
//  uint8_t proto = flow.key().protocol();
//  FlowIterator it(flow);
//  const TrackedFields* fields_ptr = nullptr;
//
//  if (flow.last_rx() < time_threshold) {
//    return 0;
//  }
//
//  if (proto != IPPROTO_TCP) {
//    uint64_t count = 0;
//    while ((fields_ptr = it.NextOrNull()) != nullptr) {
//      if (fields_ptr->timestamp() < time_threshold) {
//        continue;
//      }
//
//      count++;
//    }
//
//    return count;
//  }
//
//  uint64_t start_seq = 0;
//  uint64_t end_seq = 0;
//  uint32_t overflow_count = 0;
//  double total_payload = 0;
//  uint32_t samples = 0;
//
//  while ((fields_ptr = it.NextOrNull()) != nullptr) {
//    if (fields_ptr->timestamp() < time_threshold) {
//      continue;
//    }
//
//    uint32_t seq = fields_ptr->tcp_seq();
//    total_payload += fields_ptr->payload_size();
//    samples++;
//
//    if (start_seq == 0) {
//      start_seq = seq;
//    }
//
//    if (end_seq > seq) {
//      if (end_seq - seq > std::numeric_limits<uint16_t>::max()) {
//        overflow_count++;
//      } else {
//        continue;
//      }
//    }
//
//    end_seq = seq;
//  }
//
//  if (end_seq == 0) {
//    // Either there was only one packet, or all packets after the first one were
//    // reordered.
//    return 1;
//  }
//
//  if (total_payload == 0 || start_seq == end_seq) {
//    // A 0-payload flow. Maybe an ACK flow.
//    return samples;
//  }
//
//  uint64_t bytes = end_seq
//      + overflow_count * std::numeric_limits<uint32_t>::max() - start_seq;
//
//  if (total_payload > bytes) {
//    // Can happen if enough packets are skipped (e.g. see only SYN and  packet)
//    return samples;
//  }
//
//  double mean_pkt_payload = total_payload / samples;
////  std::cout << "Will return " << static_cast<uint64_t>(bytes / mean_pkt_payload)
////            << " mean payload: " << mean_pkt_payload << ", bytes: " << bytes
////            << ", total payload: " << total_payload << ", samples: " << samples
////            << ", key: " << flow.key().ToString() << "\n";
//  return static_cast<uint64_t>(bytes / mean_pkt_payload);
//}

//double GetMean(const std::vector<uint64_t>& values, size_t start_index,
//               size_t end_index) {
//  double total = 0;
//  for (size_t i = start_index; i < end_index; ++i) {
//    total += values[i];
//  }
//
//  return total / (end_index - start_index);
//}
//
//void NestedMeansRecursive(const std::vector<uint64_t>& values,
//                          const size_t max_levels, size_t start_index,
//                          size_t end_index, size_t level,
//                          ClusterVector* cluster_means_and_cluster_sizes) {
//  double mean = GetMean(values, start_index, end_index);
//
//  if (level == max_levels) {
//    if (end_index < start_index) {
//      throw std::logic_error("Bad indices");
//    }
//
//    if (end_index == start_index) {
//      return;
//    }
//
//    cluster_means_and_cluster_sizes->push_back(
//        std::make_pair(mean, end_index - start_index));
//    return;
//  }
//
//  size_t pivot;
//  for (pivot = start_index; pivot < end_index; ++pivot) {
//    if (values[pivot] > mean) {
//      break;
//    }
//  }
//
//  NestedMeansRecursive(values, max_levels, start_index, pivot, level + 1,
//                       cluster_means_and_cluster_sizes);
//  NestedMeansRecursive(values, max_levels, pivot, end_index, level + 1,
//                       cluster_means_and_cluster_sizes);
//}
//
//void NestedMeans(std::vector<uint64_t>* values, size_t max_levels,
//                 ClusterVector* cluster_means_and_cluster_sizes) {
//  std::sort(values->begin(), values->end());
//
//  NestedMeansRecursive(*values, max_levels, 0, values->size(), 0,
//                       cluster_means_and_cluster_sizes);
//}

//void GetFlowSizes(const Parser& parser, uint64_t time_threshold,
//                  double sample_prob) {
//  auto measurement_frequencies_ptr = std::make_unique<arma::colvec>(2);
//  measurement_frequencies_ptr->zeros();
//
//  ParserIterator it(parser);
//
//  const Flow* flow_ptr = nullptr;
//  size_t total = 0;
//  while ((flow_ptr = it.Next()) != nullptr) {
//    uint64_t pkt_count = GetFlowPktCountNoSeq(*flow_ptr, time_threshold);
//    if (pkt_count == 0) {
//      continue;
//    }
//
//    if (pkt_count > 2) {
//      continue;
//    }
//
//    measurement_frequencies_ptr->at(pkt_count - 1) += 1;
//    total++;
//  }
//
////  for (size_t i = 0; i < 2; ++i) {
////    measurement_frequencies_ptr->at(i) /= total;
////  }
//
//  measurement_frequencies_ptr->print("Measurement frequencies:");
//
//  auto orig_flow_seq = GetOriginalFlowFrequencies(*measurement_frequencies_ptr,
//                                                  sample_prob);
//
//  orig_flow_seq->print("Original frequencies:");
//}

//void AddFlowSizeClusters(const Parser& parser, uint64_t time_threshold,
//                         double sample_prob, Datapoint* datapoint) {
//  Unused(datapoint);
////  ClusterVector flow_sizes_and_flow_counts;
//  GetFlowSizes(parser, time_threshold, sample_prob);
////
////  for (const auto& flow_size_and_flow_count : flow_sizes_and_flow_counts) {
////    uint64_t flow_size = flow_size_and_flow_count.first;
////    uint64_t flow_count = flow_size_and_flow_count.second;
////    std::cout << "flow size " << flow_size << " flow count " << flow_count
////              << "\n";
////
////    FlowSizeCluster* cluster = datapoint->add_active_flows();
////    cluster->set_flow_count(flow_count);
////    cluster->set_mean_flow_pkt_count(flow_size);
////
////    double prob = ProbSeeAtLeastXPkts(loss_prob, flow_size, 1);
////    cluster->set_see_prob(prob);
////  }
//}

// Returns the i-th percentile of the values in 'values'. Values should
// be sorted before calling this function.
double GetPercentile(const std::vector<double>& values, size_t i) {
  if (i > 100 || i == 0) {
    throw std::logic_error("Invalid percentile " + std::to_string(i));
  }

  if (values.size() == 1) {
    return values[0];
  }

  size_t max_index = values.size() - 1;
  double double_index = max_index * (i / 100.0);

  double index_integer_part;
  double index_fractional_part = modf(double_index, &index_integer_part);

  if (index_fractional_part == 0) {
    return values[index_integer_part];
  }

  return (values[index_integer_part] + values[index_integer_part + 1]) / 2.0;
}

void FlowDistRunner::QueryAllFlows(const Parser& parser) {
  ParserInfo info = parser.GetInfoNoLock();

  uint64_t last_rx = info.last_rx;
  uint64_t first_rx = info.first_rx;

  if ((last_rx - first_rx) < config_.lookback_period()) {
    return;
  }

  Datapoint* datapoint = dist_.add_datapoints();
  datapoint->set_timestamp(info.last_rx);
  datapoint->set_total_flow_hits(info.flow_hits);
  datapoint->set_total_flow_misses(info.flow_misses);
  datapoint->set_total_flows_in_mem(info.num_flows_in_mem);
  datapoint->set_total_mem_usage_bytes(info.mem_usage_bytes);
  datapoint->set_total_pkts_seen(info.total_pkts_seen);

  datapoint->set_ip_len_per_sec(info.ip_len_seen_per_sec);
  datapoint->set_payload_per_sec(info.payload_seen_per_sec);
  datapoint->set_tcp_payload_per_sec(info.tcp_payload_seen_per_sec);
  datapoint->set_total_tcp_syn_pkts_seen(info.total_tcp_syn_or_fin_pkts_seen);
  datapoint->set_total_tcp_flows_in_mem(info.tcp_flows_in_mem);
  datapoint->set_total_udp_flows_in_mem(info.udp_flows_in_mem);
  datapoint->set_total_icmp_flows_in_mem(info.icmp_flows_in_mem);
}

//size_t GetLeastPowerOfTwo(size_t num) {
//  size_t i;
//
//  if (num == 0) {
//    throw std::logic_error("Cannot get least power of 2 for 0");
//  }
//
//  for (i = 1; i <= 32; ++i) {
//    if (num < (1 << i)) {
//      break;
//    }
//  }
//
//  return i - 1;
//}

void PrintMap(const std::map<uint32_t, std::pair<uint32_t, uint32_t>>& map) {
  std::cout << "[";
  size_t count = 0;
  for (const auto& flow_size_and_count : map) {
    uint32_t flow_size = flow_size_and_count.first;
    const auto& flows_and_syn_count = flow_size_and_count.second;

    std::cout << "(" << flow_size << ", " << flows_and_syn_count.first << ", "
              << flows_and_syn_count.second << ")";
    count++;

    if (count != map.size()) {
      std::cout << ", ";
    }
  }

  std::cout << "]\n";
}

void FlowDistRunner::RunTrace() {
  flow_duration_file_.open("fd.out");
  FlowParserConfig fp_cfg;
  fp_cfg.OfflineTrace(config_.pcap_filename());

  fp_cfg.MutableParserConfig()->add_periodic_callback(
      [this](const Parser& parser) {
        QueryAllFlows(parser);
      });

  auto queue_ptr = std::make_shared<Parser::FlowQueue>();
  fp_cfg.FlowQueue(queue_ptr);

  fp_cfg.MutableParserConfig()->set_undersample_skip_count(
      config_.undersample_skip_count());

  fp_cfg.MutableParserConfig()->mutable_flow_config()->SetField(
      FlowConfig::HF_TCP_SEQ);

  fp_cfg.MutableParserConfig()->mutable_flow_config()->SetField(
      FlowConfig::HF_TCP_FLAGS);

  fp_cfg.MutableParserConfig()->mutable_flow_config()->SetField(
      FlowConfig::HF_PAYLOAD_SIZE);

  fp_cfg.SetBPFFilter(config_.bpf_filter());

  flowparser::FlowParser fp(fp_cfg);

  std::map<uint32_t, std::pair<uint32_t, uint32_t>> flow_sizes_no_seq;
  std::map<uint64_t, uint32_t> active_flows;
  double mean_flow_duration = 0;
  uint64_t count = 0;

  std::thread th([&queue_ptr, &flow_sizes_no_seq, &active_flows, &fp,
  &mean_flow_duration, &count, this] {
    while (true) {
      std::unique_ptr<Flow> flow_ptr = queue_ptr->ConsumeOrBlock();
      if (!flow_ptr) {
        break;
      }

      auto start_and_end = GetFlowActiveInterval(*flow_ptr, false);
      if (start_and_end.second == 0) {
        continue;
      }

//          BinFlowInActiveFlows(*flow_ptr, &active_flows);

      uint64_t duration_no_filter = start_and_end.second - start_and_end.first;

      start_and_end = GetFlowActiveInterval(*flow_ptr, true);
      uint64_t duration_filter = start_and_end.second - start_and_end.first;

      FlowInfo info = flow_ptr->GetInfo();

//          flow_duration_file_ << duration << " " << info.pkts_seen << " " << info.total_ip_len_seen << " \"" << flow_ptr->key().ToString() << "\"\n";
      flow_duration_file_ << duration_no_filter << " " << duration_filter << " " << info.pkts_seen << " " << info.total_ip_len_seen << " " << info.total_payload_seen << "\n";
//          if (duration != 0) {
//            std::cout << "dur " << duration << "\n";
      mean_flow_duration = (duration_no_filter + mean_flow_duration * count) / (count + 1);
//            std::cout << "mfd " << mean_flow_duration << "\n";
      count++;
//          }

      size_t size_no_seq = GetFlowPktCountNoSeq(*flow_ptr, 0);
      flow_sizes_no_seq[size_no_seq].first++;
      if (flow_ptr->tcp_flags_or() & TH_SYN) {
        flow_sizes_no_seq[size_no_seq].second++;
      }
    }
  });

  fp.RunTrace();
  th.join();

  std::cout << "mean duration " << mean_flow_duration << " total count "
            << count << "\n";

  for (const auto& flow_size_and_count : flow_sizes_no_seq) {
    uint32_t flow_size = flow_size_and_count.first;
    const auto& flows_and_syn_count = flow_size_and_count.second;

    FlowSizeDatapoint* flow_size_datapoint = dist_.add_flow_sizes();
    flow_size_datapoint->set_flow_size_pkts(flow_size);
    flow_size_datapoint->set_flow_count(flows_and_syn_count.first);
    flow_size_datapoint->set_syn_count(flows_and_syn_count.second);
  }

  for (const auto& timestamp_and_count : active_flows) {
    uint64_t timestamp = timestamp_and_count.first;
    uint32_t active_flows = timestamp_and_count.second;

    ActiveFlowsDatapoint* active_flows_datapoint = dist_.add_active_flows();
    active_flows_datapoint->set_count(active_flows);
    active_flows_datapoint->set_timestamp(timestamp);
  }

  *dist_.mutable_original_config() = config_;

  flow_duration_file_.close();
}

}  // namespace binner
}  // namespace example
}  // namespace flowparser

using flowparser::example::flow_dist::FlowDistConfig;
using flowparser::example::flow_dist::FlowDist;
using flowparser::example::flow_dist::FlowDistRunner;

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cout << "Supply exactly one argument.\n";

    return -1;
  }

  std::string filename(argv[1]);
  std::ifstream in_stream(filename);
  std::string serialized_protobuf((std::istreambuf_iterator<char>(in_stream)),
                                  std::istreambuf_iterator<char>());

  FlowDistConfig flow_dist_config;
  if (!flow_dist_config.ParseFromString(serialized_protobuf)) {
    std::cout << "Bad binner config protobuf\n";

    return -1;
  }

  FlowDistRunner runner(flow_dist_config);

  runner.RunTrace();

  FlowDist output_protobuf = runner.get_flow_dist();
  std::ofstream out_stream(flow_dist_config.pcap_filename() + ".flow_dist.pb");
  out_stream << output_protobuf.SerializeAsString();
  out_stream.close();

  return 0;
}
