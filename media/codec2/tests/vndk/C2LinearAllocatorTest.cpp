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

namespace {
template <typename T>
std::string AllocatorGetName(int x) {
    return std::to_string(x);
}

template <> std::string AllocatorGetName<C2AllocatorBlob>(int) {
    return "Blob";
}

template <> std::string AllocatorGetName<C2AllocatorIon>(int) {
    return "Ion";
}

template <> std::string AllocatorGetName<C2DmaBufAllocator>(int) {
    return "DmaBuf";
}

}  // anonymous namespace

class AllocatorTypeNames {
public:
    template <typename T>
    static std::string GetName(int x) {
        return AllocatorGetName<T>(x);
    }
};
using AllocatorTypes = ::testing::Types<C2AllocatorBlob, C2AllocatorIon, C2DmaBufAllocator>;
TYPED_TEST_SUITE(C2LinearAllocatorTest, AllocatorTypes, AllocatorTypeNames);

// Test if multiple mappings from the same underlying allocation can be read successfully
TYPED_TEST(C2LinearAllocatorTest, MultipleMaps) {
    std::shared_ptr<C2LinearAllocation> alloc;
    c2_status_t err = this->mAlloc->newLinearAllocation(100, kCpuUsage, &alloc);
    if (err != C2_OK) {
        GTEST_SKIP() << "the allocator is not supported on this device";
        return;
    }
    std::shared_ptr<C2LinearBlock> block = _C2BlockFactory::CreateLinearBlock(alloc);
    {
        C2WriteView view = block->map().get();
        ASSERT_EQ(C2_OK, view.error());
        for (size_t i = 0; i < view.capacity(); ++i) {
            view.base()[i] = (i & 0xFF);
        }
    }
    C2ConstLinearBlock readBlock = block->share(0, 100, C2Fence());
    C2ReadView readView = readBlock.map().get();
    ASSERT_EQ(C2_OK, readView.error());
    std::ostringstream ss;
    size_t mismatches = 0;
    for (size_t i = 0; i < readView.capacity(); ++i) {
        if (i != readView.data()[i]) {
            if (mismatches < 10) {
                ss << "#" << i << " exp:" << (i & 0xFF)
                   << " act:" << readView.data()[i] << " ";
            }
            ++mismatches;
        }
    }
    EXPECT_EQ(0, mismatches) << "mapping for the entire block does not match the original: "
                             << ss.str();

    C2ConstLinearBlock partialReadBlock = block->share(10, 10, C2Fence());
    C2ReadView partialReadView = partialReadBlock.map().get();
    ASSERT_EQ(C2_OK, partialReadView.error());
    ss.str("");
    mismatches = 0;
    for (size_t i = 0; i < partialReadView.capacity(); ++i) {
        if (i + 10 != partialReadView.data()[i]) {
            if (mismatches < 10) {
                ss << "#" << i << " exp:" << ((i + 10) & 0xFF)
                   << " act:" << partialReadView.data()[i] << " ";
            }
            ++mismatches;
        }
    }
    EXPECT_EQ(0, mismatches) << "mapping for a part of the block does not match the original: "
                             << ss.str();
}

} // namespace android
