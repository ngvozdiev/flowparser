#include "gtest/gtest.h"
#include "packer.h"

#include <random>

namespace flowparser {
namespace test {

class PackerFixture : public ::testing::Test {
 protected:
  PackedUintSeq seq_;
  std::vector<uint64_t> vec_;
};

class RLEFixture : public ::testing::Test {
 protected:
  RLEField<uint64_t> seq_;
  std::vector<uint64_t> vec_;
};

TEST_F(PackerFixture, Empty) {
  ASSERT_EQ(0, seq_.SizeBytes());

  seq_.Restore(&vec_);
  ASSERT_EQ(0, vec_.size());
}

TEST(Packer, AppendByteSizes) {
  uint64_t lower_boundary = 0;
  for (size_t byte_count = 1; byte_count <= 8; byte_count++) {
    PackedUintSeq seq_;

    // Upon packing each integer is compressed to the minimum number of bytes
    // required to hold it plus 3 bits taken from the first byte.
    uint64_t upper_boundary = (1UL << ((byte_count * 8) - 3)) - 1;

    ASSERT_TRUE(seq_.Append(lower_boundary).ok());
    ASSERT_EQ(byte_count, seq_.SizeBytes());

    auto result = seq_.Append(upper_boundary);

    ASSERT_TRUE(result.ok())<< result.ToString();
    ASSERT_EQ(2 * byte_count, seq_.SizeBytes());

    lower_boundary = upper_boundary + 1;
  }
}

TEST(Packer, AppendTooLarge) {
  PackedUintSeq seq;

  seq.Append(0);
  ASSERT_FALSE(seq.Append(std::numeric_limits<uint64_t>::max()).ok());
}

TEST(Packer, AppendNonIncrementing) {
  PackedUintSeq seq;

  seq.Append(1000);
  ASSERT_FALSE(seq.Append(1).ok());
}

TEST_F(PackerFixture, Append1KSame) {
  for (size_t i = 0; i < 1000; ++i) {
    seq_.Append(1050);
  }

  seq_.Restore(&vec_);
  ASSERT_EQ(1000, vec_.size());
  for (size_t i = 0; i < 1000; ++i) {
    ASSERT_EQ(1050, vec_.at(0));
  }
}

TEST_F(PackerFixture, Append10M) {
  std::default_random_engine e(1);

  std::vector<uint64_t> model;

  uint64_t prev = 0;
  for (uint64_t i = 0; i < 10000000L; ++i) {
    uint64_t val = prev + e();
    prev = val;

    ASSERT_TRUE(seq_.Append(val).ok());
    model.push_back(val);
  }

  seq_.Restore(&vec_);
  ASSERT_EQ(model, vec_);
}

TEST_F(RLEFixture, Empty) {
  seq_.Restore(&vec_);

  ASSERT_EQ(0, seq_.SizeBytes());
  ASSERT_TRUE(vec_.empty());
}

TEST_F(RLEFixture, One) {
  seq_.Append(1);

  seq_.Restore(&vec_);

  ASSERT_EQ(1, vec_.size());
  ASSERT_EQ(1, vec_.at(0));
}

TEST_F(RLEFixture, Append1M) {
  std::vector<uint64_t> model;
  for (size_t i = 0; i < 1000000; i++) {
    uint64_t val = 100 + 5 * i;

    seq_.Append(val);
    model.push_back(val);
  }

  // Regardless of the implementation if RLE is implemented correctly the 10M
  // values should fit in 50 bytes.
  ASSERT_GT(50, seq_.SizeBytes());

  seq_.Restore(&vec_);
  ASSERT_EQ(model, vec_);
}

}  // namespace test
}  // namespace flowparser
