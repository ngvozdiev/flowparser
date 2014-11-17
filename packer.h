// The packer packs a sequence of unsigned integers (uin32_t) into the a
// sequence of bytes where each integer occupies 1,2,3 or 4 bytes depending on
// how big it is. Smaller integers are stored in less bytes. The sequence does
// not have to be increasing.

#ifndef FPARSER_PACKER_H
#define FPARSER_PACKER_H

#include <vector>

class PackedUintSeq {
 private:
  // The sequence.
  std::vector<char> data_;

  // Length in terms of number of integers stored.
  size_t len_;
};

#endif  /* FPARSER_PACKER_H */
