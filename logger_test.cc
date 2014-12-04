#include "gtest/gtest.h"
#include "logger.h"

namespace flowparser {
namespace test {

class TestOutputCapture : public ::testing::Test {
 protected:
  virtual void SetUp() {
    buffer_.str(std::string());  // clears the buffer.
    sbuf_ = std::cout.rdbuf();
    std::cout.rdbuf(buffer_.rdbuf());
  }

  virtual void TearDown() {
    std::cout.rdbuf(sbuf_);
    const ::testing::TestInfo* const test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    if (test_info->result()->Failed()) {
      std::cout << std::endl << "Captured output from "
                << test_info->test_case_name() << " is:" << std::endl
                << buffer_.str() << std::endl;
    }
  }

  std::stringstream buffer_;
  std::streambuf* sbuf_;
};

TEST_F(TestOutputCapture, SimpleLog) {
  Log log;

  time_t time_now;
  time(&time_now);

  log.Metric().Log(LogLevel::DEBUG, "Hi");
  log.Flush();

  bool found = false;

  // 10 seconds should be plenty of time to execute the test.
  for (size_t offset = 0; offset < 10; ++offset) {
    char time_buffer[20];
    time_t offset_time = time_now + offset;
    strftime(time_buffer, 20, kTimeFmt, localtime(&offset_time));

    std::stringstream model_ss;
    model_ss << "[DEBUG] (0) " << time_buffer << " -- Hi\n";

    if (model_ss.str() == buffer_.str()) {
      found = true;
      break;
    }
  }

  ASSERT_TRUE(found);
}

}
}
