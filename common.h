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
void Unused(T &&)
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

// Lifted from http://www.exploringbinary.com
constexpr int IsPowerOfTwo(uint32_t x) {
  return ((x != 0) && ((x & (~x + 1)) == x));
}

// A timer, useful for timing stuff.
class Timer {
 public:
  Timer()
      : start_point_(std::chrono::high_resolution_clock::now()) {
  }

  std::chrono::milliseconds DurationMillis() {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start_point_);
    return duration;
  }

 private:
  std::chrono::high_resolution_clock::time_point start_point_;
};

static constexpr uint64_t kMillion = 1000000;

#endif	/* FPARSER_COMMON_H */
