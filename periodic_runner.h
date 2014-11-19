// A taks that runs periodically on a separate thread until killed.

#ifndef FLOWPARSER_PRUNNER_H
#define FLOWPARSER_PRUNNER_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "common.h"

namespace flowparser {

using std::chrono::milliseconds;

// A task that will execute every period (p). Care is taken to ensure that task
// execution rate will be equal to 1/p in the long run (if at all possible).
class PeriodicTask {
 public:
  PeriodicTask(std::function<void()> task, std::chrono::milliseconds period)
      : period_(period),
        task_(task),
        to_exit_(false),
        already_run_(false) {
  }

  ~PeriodicTask() {
    Stop();
  }

  // Stops execution of this periodic task. If the task is currently being
  // executed it is not interrupted. This call will block until execution is
  // complete.
  void Stop();

  // Starts the task. If the task is already running, or it has already
  // terminated will return non-ok status. When the task is started it will
  // immediately execute (as opposed to waiting for a period and then
  // executing).
  Status Start();

 private:
  // The main loop.
  void Run();

  // Period in milliseconds.
  const std::chrono::milliseconds period_;

  // The task to execute.
  const std::function<void()> task_;

  // Mutex for the condition below.
  std::mutex mu_;

  // A condition variable for the thread to wait on.
  std::condition_variable wait_condition_;

  // The thread that will be executing the task.
  std::thread thread_;

  // Set to true when the runner needs to exit, protected by mu_.
  bool to_exit_;

  // Set to true the first time the Start is called, protected by mu_.
  bool already_run_;

  DISALLOW_COPY_AND_ASSIGN(PeriodicTask);
};

}

#endif  /* FLOWPARSER_PRUNNER_H */
