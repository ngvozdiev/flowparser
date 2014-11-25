#ifndef FPARSER_COMMON_H
#define	FPARSER_COMMON_H

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <chrono>

// Used to silence unused parameter warnings from the compiler.
template <typename T>
void ignore(T &&)
{ }

// make_unique "lifted" from C++14.
namespace std {
template<class T> struct _Unique_if {
  typedef unique_ptr<T> _Single_object;
};

template<class T> struct _Unique_if<T[]> {
  typedef unique_ptr<T[]> _Unknown_bound;
};

template<class T, size_t N> struct _Unique_if<T[N]> {
  typedef void _Known_bound;
};

template<class T, class ... Args>
typename _Unique_if<T>::_Single_object make_unique(Args&&... args) {
  return unique_ptr<T>(new T(std::forward<Args>(args)...));
}

template<class T>
typename _Unique_if<T>::_Unknown_bound make_unique(size_t n) {
  typedef typename remove_extent<T>::type U;
  return unique_ptr<T>(new U[n]());
}

template<class T, class ... Args>
typename _Unique_if<T>::_Known_bound make_unique(Args&&...) = delete;
}

// A macro to disallow the copy constructor and operator= functions
// This should be used in the private: declarations for a class
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)

class Timer {
 public:
  Timer()
      : start_point_(std::chrono::system_clock::now()) {
  }

  std::chrono::milliseconds DurationMillis() {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now() - start_point_);
    return duration;
  }

 private:
  std::chrono::system_clock::time_point start_point_;

};

class Status {
 public:
  static Status kStatusOK;

  Status(const std::string& error)
      : is_ok_(false),
        error_description_(error) {
  }

  Status(const char* error)
      : is_ok_(false),
        error_description_(error) {
  }

  bool ok() const {
    return is_ok_;
  }

  std::string ToString() const {
    if (is_ok_) {
      return "Status OK";
    }

    return "Status " + error_description_;
  }

 private:
  Status()
      : is_ok_(true) {
  }

  bool is_ok_;
  std::string error_description_;
};

class OrError {
 public:
  OrError(const std::string& error)
      : status_(error) {
  }

  OrError(const char* error)
      : status_(error) {
  }

  OrError(const Status& status)
      : status_(status) {
    if (status_.ok()) {
      std::cout << "Tried to construct PtrOrError with OK status\n";
      std::abort();
    }
  }

  bool ok() {
    return status_.ok();
  }

  // Returns the status. If there is no error the status will be ok.
  const Status& status() const {
    return status_;
  }

 protected:
  OrError()
      : status_(Status::kStatusOK) {
  }

  Status status_;
};

// A class that combines a unique pointer or an error string. Can be returned
// from functions that can fail and need to return an error message.
template<class T>
class PtrOrError : public OrError {
 public:
  using OrError::OrError;

  PtrOrError(std::unique_ptr<T> value)
  : value_(std::move(value)) {
  }

  // Returns the value or dies.
  std::unique_ptr<T> ValueOrDie() {
    if (!status_.ok()) {
      std::cout << "Value or die on a non-OK satus\n";
      std::abort();
    }

    return std::move(value_);
  }

 private:
  std::unique_ptr<T> value_;
};

// A class that combines a value or an error string. Can be returned from
// functions that can fail and need to return an error message.
template<class T>
class ValueOrError : public OrError {
 public:
  using OrError::OrError;

  ValueOrError(T value)
      : value_(value) {
  }

  // Returns the value or dies.
  T ValueOrDie() {
    if (!status_.ok()) {
      std::cout << "Value or die on a non-OK satus\n";
      std::abort();
    }

    return value_;
  }

 private:
  T value_;
};

#endif	/* FPARSER_COMMON_H */
