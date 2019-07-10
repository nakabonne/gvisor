// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <sched.h>

#include "gtest/gtest.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(ReadaheadTest, InvalidFD) {
  EXPECT_THAT(readahead(-1, 1, 1), SyscallFailsWithErrno(EBADF));
}

TEST(ReadaheadTest, InvalidOffset) {
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));
  EXPECT_THAT(readahead(fd.get(), -1, 1), SyscallFailsWithErrno(EINVAL));
}

TEST(ReadaheadTest, ValidOffset) {
  constexpr char kData[] = "123";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));
  EXPECT_THAT(readahead(fd.get(), 1, 1), SyscallSucceedsWithValue(0));
}

TEST(ReadaheadTest, PastEnd) {
  constexpr char kData[] = "123";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));
  EXPECT_THAT(readahead(fd.get(), 2, 2), SyscallSucceedsWithValue(0));
}

TEST(ReadaheadTest, CrossesEnd) {
  constexpr char kData[] = "123";
  constexpr int kDataSize = sizeof(kData) - 1;
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));
  EXPECT_THAT(readahead(fd.get(), 4, 2), SyscallSucceedsWithValue(0));
}

TEST(ReadaheadTest, WriteOnly) {
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_WRONLY));
  EXPECT_THAT(readahead(fd.get(), 0, 1), SyscallFailsWithErrno(EBADF));
}

TEST(ReadaheadTest, InvalidSize) {
  const TempPath in_file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(in_file.path(), O_RDWR));
  EXPECT_THAT(readahead(fd.get(), 0, -1), SyscallSucceedsWithValue(0));
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
