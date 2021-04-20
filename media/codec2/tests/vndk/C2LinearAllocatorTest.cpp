/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sstream>

#include <gtest/gtest.h>

#include <C2AllocatorBlob.h>
#include <C2AllocatorIon.h>
#include <C2BlockInternal.h>
#include <C2Buffer.h>
#include <C2DmaBufAllocator.h>

namespace android {

template <typename T>
class C2LinearAllocatorTest : public ::testing::Test {
public:
    constexpr static id_t kId = 0;

    void SetUp() override {
        mAlloc = std::make_shared<T>(kId);
    }

    std::shared_ptr<T> mAlloc;
};

const static C2MemoryUsage kCpuUsage{C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

using AllocatorTypes = ::testing::Types<C2AllocatorBlob, C2AllocatorIon, C2DmaBufAllocator>;
TYPED_TEST_SUITE(C2LinearAllocatorTest, AllocatorTypes);

TYPED_TEST(C2LinearAllocatorTest, MultipleMaps) {
    std::shared_ptr<C2LinearAllocation> alloc;
    c2_status_t err = this->mAlloc->newLinearAllocation(100, kCpuUsage, &alloc);
    if (err != C2_OK) {
        GTEST_SKIP() << this->mAlloc->getName() << " is not supported on this device";
        return;
    }
    std::shared_ptr<C2LinearBlock> block = _C2BlockFactory::CreateLinearBlock(alloc);
    C2WriteView view = block->map().get();
    ASSERT_EQ(C2_OK, view.error());
    for (size_t i = 0; i < view.capacity(); ++i) {
        view.base()[i] = i;
    }
    C2ConstLinearBlock readBlock = block->share(10, 10, C2Fence());
    C2ReadView readView = readBlock.map().get();
    ASSERT_EQ(C2_OK, readView.error());
    std::ostringstream ss;
    size_t mismatches = 0;
    for (size_t i = 0; i < readView.capacity(); ++i) {
        if (mismatches < 10 && i + 10 != readView.data()[i]) {
            ss << "#" << i << " exp:" << (i + 10) << " act:" << readView.data()[i] << " ";
            ++mismatches;
        }
    }
    EXPECT_EQ(0, mismatches) << ss.str();
    ss.str("");
    mismatches = 0;
    for (size_t i = 0; i < view.capacity(); ++i) {
        if (mismatches < 10 && i != view.data()[i]) {
            ss << "#" << i << " exp:" << i << " act:" << view.data()[i] << " ";
            ++mismatches;
        }
    }
    EXPECT_EQ(0, mismatches) << ss.str();
}

} // namespace android
