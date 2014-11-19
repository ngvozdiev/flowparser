#include "gtest/gtest.h"
#include "periodic_runner.h"

#include <random>

namespace flowparser {
namespace test {

using std::chrono::milliseconds;

// Running with zero period should be valid.
TEST(PeriodicRunner, ZeroPeriod) {
  int i = 0;
  PeriodicTask task([&i] {i++;}, milliseconds(0));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));

  task.Stop();
  ASSERT_LT(0, i);
}

TEST(PeriodicRunner, AvgPeriod) {
  int i = 0;
  PeriodicTask task([&i] {i++;}, milliseconds(10));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));

  task.Stop();
  ASSERT_EQ(10, i);
}

// Stopping the task multiple times should not crash it.
TEST(PeriodicRunner, MultiStop) {
  PeriodicTask task([] {}, milliseconds(10));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));
  task.Stop();
  task.Stop();
  task.Stop();
}

TEST(PeriodicRunner, MultiStart) {
  int i = 0;
  PeriodicTask task([&i] {i++;}, milliseconds(10));

  ASSERT_TRUE(task.Start().ok());
  ASSERT_FALSE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));
  task.Stop();

  ASSERT_EQ(10, i);
}

TEST(PeriodicRunner, StartAfterStop) {
  int i = 0;
  PeriodicTask task([&i] {i++;}, milliseconds(10));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));
  task.Stop();
  ASSERT_FALSE(task.Start().ok());

  ASSERT_EQ(10, i);
}

TEST(PeriodicRunner, SlowTask) {
  int i = 0;
  PeriodicTask task([&i] {std::this_thread::sleep_for(milliseconds(10)); i++;},
                    milliseconds(11));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(110));

  task.Stop();
  ASSERT_EQ(10, i);
}

TEST(PeriodicRunner, VerySlowTaskComplete) {
  int i = 0;
  PeriodicTask task(
      [&i] {std::this_thread::sleep_for(milliseconds(1000)); i++;},
      milliseconds(10));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(100));
  task.Stop();

  // The slow task should complete, there should only be one invocation of the
  // task.
  ASSERT_EQ(1, i);
}

// The destructor of the task object should cleanly terminate the task and join
// the running thread.
TEST(PeriodicRunner, CleanDestruction) {
  PeriodicTask task([] {std::this_thread::sleep_for(milliseconds(1));},
                    milliseconds(10));

  task.Start();
}

TEST(PeriodicRunner, AverageRate) {
  int i = 0;
  PeriodicTask task([&i]
  {
    size_t sleep_time = 10;
    i++;
    if (i == 5) {
      sleep_time = 100;
    }

    std::this_thread::sleep_for(milliseconds(sleep_time));
  },
                    milliseconds(20));

  ASSERT_TRUE(task.Start().ok());
  std::this_thread::sleep_for(milliseconds(2000));

  // When one of the calls sleeps an order of magnitude more the subsequent
  // calls should be sped up, so that the total number of calls is as if the
  // slow call was a regular one.
  ASSERT_EQ(100, i);
}

}
}
