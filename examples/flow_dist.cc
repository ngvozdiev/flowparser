#include "flow_dist.h"

#include <cstdint>
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

void FlowDistRunner::QueryAllFlows(const Parser& parser) {
  ActiveFlows* active_flows = dist_.add_datapoints();
  uint64_t last_rx = parser.GetInfoNoLock().last_rx;
  active_flows->set_timestamp(last_rx);

  ParserIteratorNoLock it(parser);

  const Flow* flow_ptr = nullptr;
  while ((flow_ptr = it.Next()) != nullptr) {
    if (flow_ptr->key().protocol() != 0x06) {
      continue;
    }

    active_flows->add_flow_rates(
        flow_ptr->EstimatorOrNull()->GetBytesPerSecEstimate(last_rx));
  }
}

void FlowDistRunner::RunTrace() {
  FlowParserConfig fp_cfg;
  fp_cfg.OfflineTrace(config_.pcap_filename());

  fp_cfg.MutableParserConfig()->set_periodic_callback(
      [this](const Parser& parser) {QueryAllFlows(parser);},
      config_.bin_size());

  fp_cfg.MutableParserConfig()->mutable_flow_config()
      ->set_tcp_estimator_ewma_alpha(config_.ewma_alpha());

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
