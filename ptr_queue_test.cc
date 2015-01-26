#include <atomic>
#include <thread>
#include <map>

#include "gtest/gtest.h"
#include "ptr_queue.h"

namespace flowparser {
namespace test {

template <typename T>
void Unused(T &&)
{ }

TEST(SmallQueue, Empty) {
  PtrQueue<int, 2> small_queue;

  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceAfterClose) {
  PtrQueue<int, 2> small_queue;

  small_queue.Close();
  ASSERT_THROW(small_queue.ProduceOrBlock(std::make_unique<int>(1)),
               std::exception);
  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ConsumeAfterClose) {
  PtrQueue<int, 2> small_queue;

  small_queue.Close();
  ASSERT_FALSE(small_queue.ConsumeOrBlock().get());
  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceConsumeOne) {
  PtrQueue<int, 2> small_queue;

  small_queue.ProduceOrBlock(std::make_unique<int>(1));
  ASSERT_EQ(1, small_queue.size());

  auto result = small_queue.ConsumeOrBlock();
  ASSERT_EQ(1, *result);
  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceConsumeTwo) {
  PtrQueue<int, 2> small_queue;

  small_queue.ProduceOrBlock(std::make_unique<int>(1));
  small_queue.ProduceOrBlock(std::make_unique<int>(2));

  ASSERT_EQ(2, small_queue.size());

  auto result_one = small_queue.ConsumeOrBlock();
  auto result_two = small_queue.ConsumeOrBlock();
  ASSERT_EQ(1, *result_one);
  ASSERT_EQ(2, *result_two);
  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceConsumeSeq) {
  PtrQueue<int, 2> small_queue;

  for (size_t i = 1; i <= 10000; i++) {
    small_queue.ProduceOrBlock(std::make_unique<int>(i));

    if (i % 2 == 0) {
      auto result_one = small_queue.ConsumeOrBlock();
      auto result_two = small_queue.ConsumeOrBlock();

      ASSERT_EQ(i - 1, *result_one);
      ASSERT_EQ(i, *result_two);
    }
  }

  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceInvalidateConsume) {
  PtrQueue<int, 4> small_queue;

  small_queue.ProduceOrBlock(std::make_unique<int>(1));
  small_queue.ProduceOrBlock(std::make_unique<int>(2));
  small_queue.ProduceOrBlock(std::make_unique<int>(3));

  small_queue.Invalidate([](const int& value) {return value == 1;});
  small_queue.Invalidate([](const int& value) {return value == 2;});

  auto result = small_queue.ConsumeOrBlock();
  ASSERT_EQ(3, *result);

  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, ProduceKill) {
  PtrQueue<int, 2> small_queue;

  std::thread thread([&small_queue] {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    small_queue.Close();
  });

  small_queue.ProduceOrBlock(std::make_unique<int>(1));
  small_queue.ProduceOrBlock(std::make_unique<int>(2));

  // should block until the queue is closed.
  ASSERT_THROW(small_queue.ProduceOrBlock(std::make_unique<int>(3)),
               std::exception);

  thread.join();

  // There are still two elements in the queue
  ASSERT_EQ(2, small_queue.size());
}

TEST(SmallQueue, ConsumeKill) {
  PtrQueue<int, 2> small_queue;

  std::thread thread([&small_queue] {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    small_queue.Close();
  });

  // should block until the queue is closed.
  auto result = small_queue.ConsumeOrBlock();

  thread.join();
  ASSERT_FALSE(result);
  ASSERT_EQ(0, small_queue.size());
}

TEST(SmallQueue, InvalidateAllKill) {
  PtrQueue<int, 2> small_queue;

  std::thread thread([&small_queue] {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    small_queue.Close();
  });

  small_queue.ProduceOrBlock(std::make_unique<int>(1));
  small_queue.ProduceOrBlock(std::make_unique<int>(2));

  small_queue.Invalidate([](const int& value) {Unused(value); return true;});

  auto result = small_queue.ConsumeOrBlock();  // will block until closed

  thread.join();
  ASSERT_FALSE(result);
  ASSERT_EQ(0, small_queue.size());
}

TEST(LargeQueue, MultiProducer) {
  auto large_queue = std::make_unique<PtrQueue<int, 1 << 20>>();

  std::vector<std::thread> threads;
  for (size_t thread_num = 0; thread_num < 16; thread_num++) {
    threads.push_back(std::thread([&large_queue] {
      for (size_t count = 0; count < ((1 << 20) / 16); count++) {
        large_queue->ProduceOrBlock(std::make_unique<int>(count));
      }
    }));
  }

  for (auto& thread : threads) {
    thread.join();
  }

  ASSERT_EQ(1 << 20, large_queue->size());

  std::map<int, int> model;
  for (size_t count = 0; count < (1 << 20); count++) {
    auto result = large_queue->ConsumeOrBlock();
    int value = *result;

    model[value] += 1;
  }

  for (size_t count = 0; count < (1 << 20) / 16; count++) {
    ASSERT_EQ(model[count], 16);
  }

  ASSERT_EQ(0, large_queue->size());
}

TEST(LargeQueue, MultiProducerMultiConsumer) {
  auto large_queue = std::make_unique<PtrQueue<uint64_t, 1 << 12>>();

  std::vector<std::thread> producer_threads;
  std::vector<std::thread> consumer_threads;

  for (size_t thread_num = 0; thread_num < 16; thread_num++) {
    producer_threads.push_back(std::thread([&large_queue] {
      for (size_t count = 0; count < ((1 << 20) / 16); count++) {
        large_queue->ProduceOrBlock(std::make_unique<uint64_t>(count));
      }
    }));
  }

  std::atomic<uint64_t> sum(0);

  for (size_t thread_num = 0; thread_num < 16; thread_num++) {
    consumer_threads.push_back(std::thread([&large_queue, &sum] {
      for (size_t count = 0; count < ((1 << 20) / 16); count++) {
        auto result = large_queue->ConsumeOrBlock();

        std::atomic_fetch_add(&sum, (*result));
      }
    }));
  }

  for (auto& thread : producer_threads) {
    thread.join();
  }

  for (auto& thread : consumer_threads) {
    thread.join();
  }

  // n * (n - 1) / 2 for each of the 16 threads
  ASSERT_EQ((((1 << 20L) / 16L) * (((1 << 20L) / 16L) - 1)) * 8L, sum);
  ASSERT_EQ(0, large_queue->size());
}

}
}
