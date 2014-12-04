#ifndef FPARSER_LOGGER_H
#define FPARSER_LOGGER_H

#include <tuple>
#include <array>
#include <chrono>
#include <mutex>

#include "metric.h"

namespace flowparser {

using std::string;

// Severity levels for log messages.
enum LogLevel {
  DEBUG,
  INFO,
  WARN,
  ERROR
};

static constexpr char const* kLogLevelNames[] = { "DEBUG", "INFO", "WARN",
    "ERROR" };
static constexpr LogLevel kCurrentLogLevel = DEBUG;
static constexpr char const* kTimeFmt = "%Y-%m-%d %H:%M:%S";

typedef Metric<1 << 10, LogLevel, string> MetricBase;
typedef MetricManager<1 << 10, LogLevel, string> LogManager;

// A metric that records log messages.
class LogMetric : public MetricBase {
 public:
  // Extracts the log level from a metric value.
  static LogLevel Level(const StampedMetricValue& value) {
    return std::get<2>(value);
  }

  // Extracts the message from a metric value.
  static string Message(const StampedMetricValue& value) {
    return std::get<3>(value);
  }

  static string LogEntryToString(const StampedMetricValue& value) {
    uint64_t id = LogMetric::Id(value);
    LogLevel level = LogMetric::Level(value);
    const string& message = LogMetric::Message(value);

    char time_buffer[20];
    time_t timestamp = LogMetric::Timestamp(value);
    strftime(time_buffer, 20, kTimeFmt, localtime(&timestamp));

    std::stringstream ss;
    ss << "[" << kLogLevelNames[level] << "] (" << id << ") " << time_buffer
       << " -- " << message << "\n";
    return ss.str();
  }

  void Log(enum LogLevel log_level, std::string message) {
    MetricBase::ProtectedAddValue(log_level, message);
  }

  void Log(enum LogLevel log_level, const char* message) {
    MetricBase::ProtectedAddValue(log_level, string(message));
  }
};

class ConsoleLogMetricConsumer : public MetricConsumer<LogLevel, std::string> {
  void ConsumeHistory(const std::vector<StampedMetricValue>& values) override {
    for (const auto& value : values) {
      string value_to_string = LogMetric::LogEntryToString(value);
      std::cout << value_to_string;
    }
  }
};

class Log {
 public:
  Log()
      : metric_(std::make_shared<LogMetric>()),
        manager_(metric_, std::chrono::milliseconds(1000)) {
    manager_.RegisterConsumer(std::make_unique<ConsoleLogMetricConsumer>());
    manager_.Start();
  }

  LogMetric& Metric() {
    return *metric_.get();
  }

  void Flush() {
    manager_.ConsumeMetric();
  }

  ~Log() {
    manager_.Stop();
  }

 private:
  std::shared_ptr<LogMetric> metric_;
  LogManager manager_;
};

Log& TheLog() {
  static Log log;
  return log;
}

}

#endif  /* FLOWPARSER_LOGGER_H */
