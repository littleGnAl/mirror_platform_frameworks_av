/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "BenchmarkBufferpoolTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <C2AllocatorGralloc.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2ParamDef.h>
#include <C2PlatformSupport.h>

#include <sys/time.h>

class BenchmarkBufferpoolTest {
  public:
    long getTimeDiff(struct timeval end_time, struct timeval start_time) {
        return ((end_time.tv_sec * 1000000 + end_time.tv_usec) -
                (start_time.tv_sec * 1000000 + start_time.tv_usec));
    }

    const int32_t mMaxIteration = 10;
    struct timeval mStart;
    struct timeval mEnd;
};

class BenchmarkLinearBufferTest : public BenchmarkBufferpoolTest,
                                  public ::testing::TestWithParam<size_t /* capacity */> {
  public:
    BenchmarkLinearBufferTest() {
        getLinearAllocator(&mLinearAllocator);
    }
    ~BenchmarkLinearBufferTest() = default;

    c2_status_t allocateLinear(size_t capacity) {
        c2_status_t err = mLinearAllocator->newLinearAllocation(
                capacity, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &mLinearAllocation);
        return err;
    }

    c2_status_t mapLinear(size_t offset, size_t size, uint8_t** address) {
        c2_status_t err = mLinearAllocation->map(
                offset, size, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, nullptr, &mAddr);
        *address = (uint8_t*)mAddr;
        return err;
    }

    c2_status_t unmapLinear(size_t size) {
        return (mLinearAllocation->unmap(mAddr, size, nullptr));
    }

    void writeData(size_t capacity, uint8_t* address) {
        for (size_t i = 0; i < capacity; ++i) {
            address[i] = i % 100u;
        }
    }

    void* mAddr;
    std::shared_ptr<C2Allocator> mLinearAllocator;
    std::shared_ptr<C2LinearAllocation> mLinearAllocation;

  private:
    void getLinearAllocator(std::shared_ptr<C2Allocator>* mLinearAllocator) {
        std::shared_ptr<C2AllocatorStore> store = android::GetCodec2PlatformAllocatorStore();
        ASSERT_EQ(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, mLinearAllocator), C2_OK);
    }
};

class BenchmarkGraphicBufferTest
    : public BenchmarkBufferpoolTest,
      public ::testing::TestWithParam<std::pair<uint32_t /* width */, uint32_t /* height */>> {
  public:
    BenchmarkGraphicBufferTest()
        : mGraphicAllocator(std::make_shared<android::C2AllocatorGralloc>('g')) {}

    ~BenchmarkGraphicBufferTest() = default;

    c2_status_t allocateGraphic(uint32_t width, uint32_t height) {
        c2_status_t err = mGraphicAllocator->newGraphicAllocation(
                width, height, HAL_PIXEL_FORMAT_YCBCR_420_888,
                {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &mGraphicAllocation);
        return err;
    }

    c2_status_t mapGraphic(C2Rect rect, C2PlanarLayout* layout, uint8_t** address) {
        c2_status_t err =
                mGraphicAllocation->map(rect, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                        nullptr, layout, address);
        mMappedRect = rect;
        memcpy(mAddrGraphic, address, sizeof(uint8_t*) * C2PlanarLayout::MAX_NUM_PLANES);
        return err;
    }

    c2_status_t unmapGraphic() {
        return (mGraphicAllocation->unmap(mAddrGraphic, mMappedRect, nullptr));
    }

    void writeData(const C2Rect rect, const C2PlaneInfo info, uint8_t* address, uint8_t value) {
        for (uint32_t row = 0; row < rect.height / info.rowSampling; ++row) {
            int32_t rowOffset = (row + rect.top / info.rowSampling) * info.rowInc;
            for (uint32_t col = 0; col < rect.width / info.colSampling; ++col) {
                int32_t colOffset = (col + rect.left / info.colSampling) * info.colInc;
                address[rowOffset + colOffset] = value;
            }
        }
    }

    std::shared_ptr<C2Allocator> mGraphicAllocator;
    std::shared_ptr<C2GraphicAllocation> mGraphicAllocation;
    C2Rect mMappedRect;
    uint8_t* mAddrGraphic[C2PlanarLayout::MAX_NUM_PLANES];
};

/**
 * The following test benchmarks time taken to allocate a linear
 * buffer(ion/dma) of different capacity(size).
 */
TEST_P(BenchmarkLinearBufferTest, LinearAllocationTest) {
    size_t kCapacity = GetParam();
    long totalTimeUs = 0;

    for (int32_t i = 0; i < mMaxIteration; i++) {
        mLinearAllocation.reset();
        gettimeofday(&mStart, NULL);
        c2_status_t status = allocateLinear(kCapacity);
        gettimeofday(&mEnd, NULL);
        if (mLinearAllocation == nullptr || status != C2_OK) {
            mLinearAllocation.reset();
            ASSERT_TRUE(false) << "C2Allocator::newLinearAllocation() failed: " << status;
        }
        totalTimeUs += getTimeDiff(mEnd, mStart);
    }
    std::cout << "Linear buffer Allocation - Size: " << kCapacity
              << ", Time: " << (totalTimeUs / mMaxIteration) << " us" << std::endl;
}

/**
 * The following test benchmarks time taken to do a map opeartion.
 * A linear buffer(ion/dma) of different capacity(size) is allocated
 * and time is measured across map-write-unmap operation happening
 * on a buffer.
 */
TEST_P(BenchmarkLinearBufferTest, LinearMappingTest) {
    size_t kCapacity = GetParam();
    c2_status_t status;
    long totalTimeUs = 0;

    for (int32_t i = 0; i < mMaxIteration; i++) {
        status = allocateLinear(kCapacity);
        if (mLinearAllocation == nullptr || status != C2_OK) {
            mLinearAllocation.reset();
            ASSERT_TRUE(false) << "C2Allocator::newLinearAllocation() failed: " << status;
        }

        mAddr = nullptr;
        uint8_t* address = nullptr;
        gettimeofday(&mStart, NULL);
        status = mapLinear(0u, kCapacity, &address);
        gettimeofday(&mEnd, NULL);
        totalTimeUs += getTimeDiff(mEnd, mStart);
        if (status != C2_OK) {
            mAddr = nullptr;
            ASSERT_TRUE(false) << "C2LinearAllocation::map() failed: " << status;
        }
        ASSERT_NE(nullptr, address);
        gettimeofday(&mStart, NULL);
        writeData(kCapacity, address);
        unmapLinear(kCapacity);
        gettimeofday(&mEnd, NULL);
        totalTimeUs += getTimeDiff(mEnd, mStart);
    }
    std::cout << "Linear buffer Map - Size: " << kCapacity
              << ", Time: " << (totalTimeUs / mMaxIteration) << " us" << std::endl;
}

/**
 * The following test benchmarks time taken to allocate a graphic
 * buffer(gralloc) of different capacity(width x height).
 */
TEST_P(BenchmarkGraphicBufferTest, GraphicAllocationTest) {
    uint32_t kWidth = GetParam().first;
    uint32_t kHeight = GetParam().second;
    long totalTimeUs = 0;

    for (int32_t i = 0; i < mMaxIteration; i++) {
        mGraphicAllocation.reset();
        gettimeofday(&mStart, NULL);
        c2_status_t status = allocateGraphic(kWidth, kHeight);
        gettimeofday(&mEnd, NULL);
        if (mGraphicAllocation == nullptr || status != C2_OK) {
            mGraphicAllocation.reset();
            ASSERT_TRUE(false) << "C2Allocator::newGraphicAllocation() failed: " << status;
        }
        totalTimeUs += getTimeDiff(mEnd, mStart);
    }
    std::cout << "Graphic buffer Allocation - Size: " << kWidth << " x " << kHeight
              << ", Time: " << (totalTimeUs / mMaxIteration) << " us" << std::endl;
}

/**
 * The following test benchmarks time taken to do a map opeartion.
 * A graphic buffer(gralloc) of different capacity(width x height)
 * is allocated and time is measured across map-write-unmap
 * operation happening on a buffer.
 */
TEST_P(BenchmarkGraphicBufferTest, GraphicMappingTest) {
    uint32_t kWidth = GetParam().first;
    uint32_t kHeight = GetParam().second;
    c2_status_t status;
    long totalTimeUs = 0;

    for (int32_t i = 0; i < mMaxIteration; i++) {
        status = allocateGraphic(kWidth, kHeight);

        if (mGraphicAllocation == nullptr || status != C2_OK) {
            mGraphicAllocation.reset();
            ASSERT_TRUE(false) << "C2Allocator::newGraphicAllocation() failed: " << status;
        }

        C2Rect rect(kWidth, kHeight);
        C2PlanarLayout layout;
        uint8_t* address[C2PlanarLayout::MAX_NUM_PLANES];
        gettimeofday(&mStart, NULL);
        status = mapGraphic(rect, &layout, address);
        gettimeofday(&mEnd, NULL);
        totalTimeUs += getTimeDiff(mEnd, mStart);

        if (status != C2_OK) {
            address[C2PlanarLayout::PLANE_Y] = nullptr;
            address[C2PlanarLayout::PLANE_U] = nullptr;
            address[C2PlanarLayout::PLANE_V] = nullptr;
            ASSERT_TRUE(false) << "C2GraphicAllocation::map() failed: " << status;
        }
        ASSERT_NE(nullptr, address[C2PlanarLayout::PLANE_Y]);
        ASSERT_NE(nullptr, address[C2PlanarLayout::PLANE_U]);
        ASSERT_NE(nullptr, address[C2PlanarLayout::PLANE_V]);

        uint8_t* y = address[C2PlanarLayout::PLANE_Y];
        C2PlaneInfo yInfo = layout.planes[C2PlanarLayout::PLANE_Y];
        uint8_t* u = address[C2PlanarLayout::PLANE_U];
        C2PlaneInfo uInfo = layout.planes[C2PlanarLayout::PLANE_U];
        uint8_t* v = address[C2PlanarLayout::PLANE_V];
        C2PlaneInfo vInfo = layout.planes[C2PlanarLayout::PLANE_V];

        gettimeofday(&mStart, NULL);
        writeData(rect, yInfo, y, 0);
        writeData(rect, uInfo, u, 0);
        writeData(rect, vInfo, v, 0);

        status = unmapGraphic();
        gettimeofday(&mEnd, NULL);
        totalTimeUs += getTimeDiff(mEnd, mStart);
        ASSERT_EQ(C2_OK, status);
    }
    std::cout << "Graphic buffer Map - Size: " << kWidth << " x " << kHeight
              << ", Time: " << (totalTimeUs / mMaxIteration) << " us" << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
        // TODO: Add usage flags
        BenchmarkLinearBufferTest, BenchmarkLinearBufferTest,
        ::testing::Values(
                    (1024u * 1024u),
                    (512u * 512u),
                    (256u * 256u),
                    (128u * 128u),
                    (64u * 64u)));

INSTANTIATE_TEST_SUITE_P(
        // TODO: Add usage flags
        BenchmarkGraphicBufferTest, BenchmarkGraphicBufferTest,
        ::testing::Values(
                    std::make_pair(320, 240),
                    std::make_pair(640, 480),
                    std::make_pair(720, 480),
                    std::make_pair(1280, 720),
                    std::make_pair(1920, 1080)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
