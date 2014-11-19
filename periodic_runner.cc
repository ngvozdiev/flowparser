#include "periodic_runner.h"

namespace flowparser {

void PeriodicTask::Run() {
  milliseconds negative_delay = milliseconds(0);

  while (true) {
    Timer timer;
    task_();
    milliseconds run_duration = timer.DurationMillis();

    // If the most recent run took longer than the period we add the
    // "time debt" as negative delay, to be executed later.
    milliseconds time_to_wait;
    if (run_duration > period_) {
      negative_delay = run_duration - period_;
      time_to_wait = milliseconds(0);
    } else {
      time_to_wait = period_ - run_duration;

      // Check to see if we have built up enough negative delay to cause us to
      // trigger immediately.
      if (negative_delay > time_to_wait) {
        negative_delay -= time_to_wait;
        time_to_wait = milliseconds(0);
      } else {
        time_to_wait -= negative_delay;
        negative_delay = milliseconds(0);
      }
    }

    if (time_to_wait == milliseconds(0)) {
      {
        std::unique_lock<std::mutex> lock(mu_);
        if (to_exit_) {
          return;
        }
      }

      continue;
    }

    auto to_wake_up = std::chrono::system_clock::now() + time_to_wait;
    {
      std::unique_lock<std::mutex> lock(mu_);

      wait_condition_.wait_until(lock, to_wake_up, [this, to_wake_up] {
        return (to_exit_ ||
            std::chrono::system_clock::now() >= to_wake_up);});

      if (to_exit_) {
        return;
      }
    }
  }
}

void PeriodicTask::Stop() {
  {
    std::unique_lock<std::mutex> lock(mu_);
    to_exit_ = true;
  }

  if (!thread_.joinable()) {
    return;
  }

  wait_condition_.notify_one();
  thread_.join();
}

Status PeriodicTask::Start() {
  {
    std::unique_lock<std::mutex> lock(mu_);

    if (already_run_) {
      return "Task already running / complete";
    }

    already_run_ = true;
  }

  thread_ = std::thread([this] {Run();});
  return Status::kStatusOK;
}

}
