#ifndef PATHFINDER_PTR_QUEUE_H
#define PATHFINDER_PTR_QUEUE_H

#include <functional>
#include <mutex>
#include <array>
#include <condition_variable>

#include "common.h"

namespace flowparser {

// A blocking queue for passing pointers between threads. This is a multi
// consumer, multi producer queue.
template<typename T, size_t Size>
class PtrQueue {
 public:
  typedef std::function<bool(const T& item)> InvalidateCallback;

  // The size of the queue
  static constexpr size_t kQueueSize = Size;

  PtrQueue()
      : producer_(0),
        consumer_(0),
        num_items_(0),
        closed_(false) {
    static_assert(IsPowerOfTwo(Size), "Queue size must be a power of 2");
  }

  ~PtrQueue() {
    Close();
  }

  // Returns the number of items in the queue (including invalid ones)
  size_t size() {
    std::unique_lock<std::mutex> lock(mu_);
    return num_items_;
  }

  // Will produce. If the queue is already closed or if the produce action
  // blocks and the queue is closed this method will throw.
  void ProduceOrThrow(std::unique_ptr<T> item) {
    {
      std::unique_lock<std::mutex> lock(mu_);
      if (closed_) {
        throw std::logic_error("Queue already closed");
      }

      if (num_items_ == Size) {
        condition_.wait(lock, [this] {return closed_ || num_items_ < Size;});

        if (closed_) {
          throw std::logic_error("Queue closed while producing");
        }
      }

      queue_[producer_].valid = true;
      queue_[producer_].ptr = std::move(item);
      producer_ = (producer_ + 1) & kMask;

      num_items_++;
    }

    condition_.notify_all();
  }

  // Will consume. If the queue is already closed or if the consume action
  // blocks and the queue is closed this method will throw.
  std::unique_ptr<T> ConsumeOrThrow() {
    std::unique_ptr<T> return_ptr;

    {
      std::unique_lock<std::mutex> lock(mu_);
      if (closed_) {
        throw std::logic_error("Queue already closed");
      }

      while (return_ptr.get() == nullptr) {
        if (num_items_ == 0) {
          condition_.wait(lock, [this] {return closed_ || num_items_ > 0;});

          if (closed_) {
            throw std::logic_error("Queue closed while consuming");
          }
        }

        Wrapper* wrapper = &queue_[consumer_];
        consumer_ = (consumer_ + 1) & kMask;

        num_items_--;
        if (wrapper->valid) {
          return_ptr = std::move(wrapper->ptr);
        }
      }
    }

    condition_.notify_all();
    if (return_ptr.get() != nullptr) {
      return std::move(return_ptr);
    }

    // If all items were invalid we should try again.
    return ConsumeOrThrow();
  }

  // Invalidates all items for which the callback evaluates to true
  void Invalidate(InvalidateCallback callback) {
    std::unique_lock<std::mutex> lock(mu_);

    for (size_t i = 0; i < Size; i++) {
      if (queue_[i].ptr.get() != nullptr && queue_[i].valid) {
        queue_[i].valid = !callback(*queue_[i].ptr.get());
      }
    }
  }

  // After this call no more items can be produced / consumed.
  void Close() {
    std::unique_lock<std::mutex> lock(mu_);
    closed_ = true;

    condition_.notify_all();
  }

 private:
  // Items can be invalidated so we need a wrapper around the pointer
  struct Wrapper {
    std::unique_ptr<T> ptr;
    bool valid;
  };

  static constexpr size_t kMask = Size - 1;

  // Index of the next element to produce
  size_t producer_;

  // Index of the next element to consume
  size_t consumer_;

  // Number of items in the queue
  size_t num_items_;

  // Can items be added to the queue
  bool closed_;

  // A circular buffer.
  std::array<Wrapper, Size> queue_;

  // Something for consumers / producers to wait on.
  std::condition_variable condition_;

  // Mutex for the condition variable above.
  std::mutex mu_;

  DISALLOW_COPY_AND_ASSIGN(PtrQueue);
};

}

#endif  /* PATHFINDER_PTR_QUEUE_H */
