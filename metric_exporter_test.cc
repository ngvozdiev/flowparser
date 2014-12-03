#include <random>
#include <fstream>
#include <streambuf>
#include <map>

#include "gtest/gtest.h"
#include "metric_exporter.h"

namespace flowparser {
namespace test {

class SingleHistoryTestMetric : public Metric<1, uint32_t> {
 public:
  void AddValue(uint32_t value) {
    ProtectedAddValue(value);
  }
};

class LongHistoryTestMetric : public Metric<1000, uint32_t> {
 public:
  void AddValue(uint32_t value) {
    ProtectedAddValue(value);
  }
};

class ReallyLongHistoryTestMetric : public Metric<1000000, uint32_t> {
 public:
  void AddValue(uint32_t value) {
    ProtectedAddValue(value);
  }
};

TEST(Metric, Init) {
  SingleHistoryTestMetric int_metric;

  ASSERT_FALSE(int_metric.MostRecent().ok());
  ASSERT_TRUE(int_metric.HistoryCopy().empty());
}

TEST(Metric, SingleElementHistory) {
  SingleHistoryTestMetric int_metric;

  int_metric.AddValue(10);

  auto value = int_metric.MostRecent().ValueOrDie();

  ASSERT_EQ(std::get<2>(value), 10);

  ASSERT_EQ(1, int_metric.HistoryCopy().size());
  ASSERT_EQ(value, int_metric.HistoryCopy().at(0));
}

TEST(Metric, SingleElementHistoryEpochReset) {
  SingleHistoryTestMetric int_metric;

  int_metric.AddValue(10);
  int_metric.NewEpoch();

  ASSERT_FALSE(int_metric.MostRecent().ok());
  ASSERT_TRUE(int_metric.HistoryCopy().empty());
}

TEST(Metric, SingleElementHistoryWrap) {
  SingleHistoryTestMetric int_metric;

  int_metric.AddValue(10);
  int_metric.AddValue(11);

  auto value = int_metric.MostRecent().ValueOrDie();
  ASSERT_EQ(std::get<2>(value), 11);

  ASSERT_EQ(1, int_metric.HistoryCopy().size());
  ASSERT_EQ(value, int_metric.HistoryCopy().at(0));
}

TEST(Metric, SingleElementHistoryWrapIdIncremental) {
  SingleHistoryTestMetric int_metric;

  int_metric.AddValue(10);
  auto value_one = int_metric.MostRecent().ValueOrDie();
  uint64_t id_one = SingleHistoryTestMetric::Id(value_one);

  int_metric.AddValue(11);
  auto value_two = int_metric.MostRecent().ValueOrDie();
  uint64_t id_two = SingleHistoryTestMetric::Id(value_two);

  ASSERT_TRUE(id_one < id_two);
}

TEST(Metric, LongHistory) {
  LongHistoryTestMetric int_metric;

  uint64_t last_id = 0;
  for (size_t total_count = 1; total_count < 1000; ++total_count) {
    for (size_t i = 0; i < total_count; ++i) {
      int_metric.AddValue(i);
    }

    auto value = int_metric.MostRecent().ValueOrDie();
    ASSERT_EQ(std::get<2>(value), total_count - 1);

    std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> history = int_metric
        .HistoryCopy();

    ASSERT_EQ(total_count, history.size());
    for (size_t i = 0; i < total_count; ++i) {
      ASSERT_EQ(i, std::get<2>(history.at(i)));
      uint64_t current_id = LongHistoryTestMetric::Id(history.at(i));

      if (total_count != 0 || i != 0) {
        ASSERT_TRUE(last_id < current_id);
      }

      last_id = current_id;
    }

    int_metric.NewEpoch();
  }
}

TEST(Metric, LongHistoryOverflow) {
  LongHistoryTestMetric int_metric;

  for (size_t i = 0; i < 10000; ++i) {
    int_metric.AddValue(i);
  }

  auto value = int_metric.MostRecent().ValueOrDie();
  ASSERT_EQ(std::get<2>(value), 9999);

  std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> history = int_metric
      .HistoryCopy();

  ASSERT_EQ(1000, history.size());
  for (size_t i = 0; i < 1000; ++i) {
    ASSERT_EQ(9000 + i, std::get<2>(history.at(i)));
  }
}

TEST(Metric, ThreadSafety) {
  ReallyLongHistoryTestMetric int_metric;

  // 10 threads, 100K values each - one million values - just enough to fill up
  // the metric's history.
  std::vector<std::thread> threads(10);
  for (auto& thread : threads) {
    thread = std::thread([&int_metric] {
      for (size_t i = 0; i < 100000; ++i) {
        int_metric.AddValue(i);
      }
    });
  }

  for (auto& thread : threads) {
    thread.join();
  }

  // If the implementation is thread safe each of the 10 threads should have
  // been able to add its value, there should be no corrupted values and the
  // entire history should be full. There should be exactly 10 copies of each of
  // the values from 0 to 99999.
  std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> history = int_metric
      .HistoryCopy();

  std::array<size_t, 100000> value_counts;
  for (size_t i = 0; i < 100000; ++i) {
    value_counts[i] = 0;
  }

  for (const auto& item : history) {
    uint32_t value = std::get<2>(item);
    ASSERT_TRUE(value < 100000);
    value_counts[value]++;
  }

  for (size_t i = 0; i < 100000; ++i) {
    ASSERT_EQ(10, value_counts[i]);
  }
}

class DummyConsumer : public MetricConsumer<uint32_t> {
 public:
  DummyConsumer() {
  }

  const std::vector<StampedMetricValue>& all_values() const {
    return all_values_;
  }

 private:
  void ConsumeHistory(const std::vector<StampedMetricValue>& values) override {
    all_values_.insert(all_values_.end(), values.begin(), values.end());
  }

  std::vector<StampedMetricValue> all_values_;
};

typedef MetricManager<1000, uint32_t> DummyManager;

TEST(MetricManager, StartStopEmpty) {
  auto metric_ptr = std::make_shared<LongHistoryTestMetric>();
  DummyManager manager(metric_ptr, std::chrono::milliseconds(100));

  auto consumer_ptr = std::make_unique<DummyConsumer>();
  const DummyConsumer* consumer_naked_ptr = consumer_ptr.get();

  manager.RegisterConsumer(std::move(consumer_ptr));

  manager.Start();
  manager.Stop();

  ASSERT_TRUE(consumer_naked_ptr->all_values().empty());
}

TEST(MetricManager, InsertValueBeforeStart) {
  auto metric_ptr = std::make_shared<LongHistoryTestMetric>();
  metric_ptr->AddValue(10);

  DummyManager manager(metric_ptr, std::chrono::milliseconds(100));

  auto consumer_ptr = std::make_unique<DummyConsumer>();
  const DummyConsumer* consumer_naked_ptr = consumer_ptr.get();

  manager.RegisterConsumer(std::move(consumer_ptr));

  manager.Start();
  manager.Stop();

  ASSERT_EQ(1, consumer_naked_ptr->all_values().size());
  ASSERT_EQ(std::get<2>(consumer_naked_ptr->all_values().at(0)), 10);
}

}
}
