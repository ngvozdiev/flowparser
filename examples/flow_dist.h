#include "flow_dist.pb.h"

namespace flowparser {
class Parser;
} /* namespace flowparser */

namespace flowparser {
namespace example {
namespace flow_dist {

class FlowDistRunner {
 public:
  FlowDistRunner(const FlowDistConfig& config)
      : config_(config) {
  }

  const FlowDist& get_flow_dist() const {
    return dist_;
  }

  // Goes through all active flows and stores their average rates in a new
  // datapoint.
  void QueryAllFlows(const Parser& parser);

  void RunTrace();

 private:
  const FlowDistConfig& config_;

  FlowDist dist_;
};

}  // namespace flow_dist
}  // namespace example
}  // namespace flowparser
