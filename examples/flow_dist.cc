#include "flow_dist.h"

#include <cstdint>
#include <cmath>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include "../common.h"
#include "../flowparser.h"
#include "../flows.h"
#include "../parser.h"

namespace flowparser {
namespace example {
namespace flow_dist {

// Returns the i-th percentile of the values in 'values'. Values should have
// been sorted before calling this function.
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
  Datapoint* datapoint = dist_.add_datapoints();
  ParserInfo info = parser.GetInfoNoLock();

  uint64_t last_rx = info.last_rx;
  datapoint->set_timestamp(info.last_rx);
  datapoint->set_total_flow_hits(info.flow_hits);
  datapoint->set_total_flow_misses(info.flow_misses);
  datapoint->set_total_flows_in_mem(info.num_flows_in_mem);
  datapoint->set_total_mem_usage_bytes(info.mem_usage_bytes);
  datapoint->set_total_pkts_seen(info.total_pkts_seen);

  ParserIteratorNoLock it(parser);

  std::vector<double> flow_rates;
  const Flow* flow_ptr = nullptr;
  while ((flow_ptr = it.Next()) != nullptr) {

    if (flow_ptr->key().protocol() != 0x06) {
      continue;
    }

    double Bps = flow_ptr->EstimatorOrNull()->GetBytesPerSecEstimate(last_rx);
    if (Bps < 1) {
      continue;
    }

    flow_rates.push_back(Bps);
  }

  std::sort(flow_rates.begin(), flow_rates.end());
  for (size_t i = 1; i <= 100; ++i) {
    datapoint->add_rate_percentiles(GetPercentile(flow_rates, i));
  }

  double sum = 0;
  for (const double& value : flow_rates) {
    sum += value;
  }

  datapoint->set_mean(sum / flow_rates.size());
}

void FlowDistRunner::RunTrace() {
  FlowParserConfig fp_cfg;
  fp_cfg.OfflineTrace(config_.pcap_filename());

  fp_cfg.MutableParserConfig()->set_periodic_callback(
      [this](const Parser& parser) {QueryAllFlows(parser);},
      config_.period_musec());

  fp_cfg.MutableParserConfig()->mutable_flow_config()
      ->set_tcp_estimator_ewma_alpha(config_.tcp_rate_estimator_ewma_alpha());

  fp_cfg.MutableParserConfig()->set_undersample_skip_count(
      config_.undersample_skip_count());

  flowparser::FlowParser fp(fp_cfg);
  fp.RunTrace();
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
