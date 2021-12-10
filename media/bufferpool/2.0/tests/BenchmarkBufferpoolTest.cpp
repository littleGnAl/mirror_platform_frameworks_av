/*
 * Copyright (C) 2022 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "BenchmarkBufferpoolTest"
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
#include <C2Buffer.h>
#include <C2BufferPriv.h>
#include <C2Config.h>
#include <C2ParamDef.h>
#include <C2PlatformSupport.h>

#include "BenchmarkBufferpoolEnvironment.h"
#include "Stats.h"

static BenchmarkBufferpoolEnvironment* gEnv = nullptr;

constexpr int32_t kMaxIteration = 10;

struct inputParamsLinear {
    size_t capacity;
    C2MemoryUsage usageFlags;
    string usage;
};

struct inputParamsGraphic {
    int32_t width;
    int32_t height;
    C2MemoryUsage usageFlags;
    string usage;
};

// TODO: PriorLinearAllocationTest and PriorGraphicAllocationTest
class BenchmarkBufferpoolTest {
  public:
    BenchmarkBufferpoolTest() { mStats = new Stats(); }
    ~BenchmarkBufferpoolTest() {
        delete (mStats);
        mStats = nullptr;
    }
    Stats* mStats;
};

class BenchmarkLinearBufferTest : public BenchmarkBufferpoolTest,
                                  public ::testing::TestWithParam<inputParamsLinear> {
  public:
    BenchmarkLinearBufferTest()
        : mAddr(nullptr), mLinearAllocator(nullptr), mLinearAllocation(nullptr) {
        getLinearAllocator(&mLinearAllocator);
        // Cache is always enabled for linear buffers
        mCacheDisabled = false;
    }
    ~BenchmarkLinearBufferTest() {
        if (mLinearAllocation) mLinearAllocation.reset();
        mLinearAllocation = nullptr;
        mAddr = nullptr;
    }

    c2_status_t allocateLinear(inputParamsLinear inputParams) {
        c2_status_t err = mLinearAllocator->newLinearAllocation(
                inputParams.capacity, inputParams.usageFlags, &mLinearAllocation);
        return err;
    }

    c2_status_t mapLinear(size_t offset, inputParamsLinear inputParams) {
        c2_status_t err = mLinearAllocation->map(offset, inputParams.capacity,
                                                 inputParams.usageFlags, nullptr, &mAddr);
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

    void dumpStats(string operation, size_t size, string usage, string statsFile) {
        mStats->dumpStatistics(operation, usage, (uint64_t)size, "LinearBuffer", mCacheDisabled,
                               statsFile);
    }

    void* mAddr;
    bool mCacheDisabled;
    std::shared_ptr<C2Allocator> mLinearAllocator;
    std::shared_ptr<C2LinearAllocation> mLinearAllocation;

  private:
    void getLinearAllocator(std::shared_ptr<C2Allocator>* mLinearAllocator) {
        std::shared_ptr<C2AllocatorStore> store = android::GetCodec2PlatformAllocatorStore();
        ASSERT_EQ(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, mLinearAllocator), C2_OK);
    }
};

class BenchmarkGraphicBufferTest : public BenchmarkBufferpoolTest,
                                   public ::testing::TestWithParam<inputParamsGraphic> {
  public:
    BenchmarkGraphicBufferTest()
        : mGraphicAllocator(std::make_shared<android::C2AllocatorGralloc>('g')),
          mGraphicAllocation(nullptr) {
        for (int32_t numPlane = 0; numPlane < C2PlanarLayout::MAX_NUM_PLANES; numPlane++) {
            mAddrGraphic[numPlane] = nullptr;
        }
    }

    ~BenchmarkGraphicBufferTest() {
        if (mGraphicAllocation) mGraphicAllocation.reset();
        mGraphicAllocation = nullptr;
        for (int32_t numPlane = 0; numPlane < C2PlanarLayout::MAX_NUM_PLANES; numPlane++) {
            mAddrGraphic[numPlane] = nullptr;
        }
    }

    virtual void SetUp() override {
        inputParamsGraphic params = GetParam();
        // No CPU_READ flag is presumed to disable cache in the allocator.
        if (params.usage.find("CPU_READ") == string::npos) {
            mCacheDisabled = true;
        } else {
            mCacheDisabled = false;
        }
    }

    c2_status_t allocateGraphic(inputParamsGraphic inputParams) {
        c2_status_t err = mGraphicAllocator->newGraphicAllocation(
                inputParams.width, inputParams.height, HAL_PIXEL_FORMAT_YCBCR_420_888,
                inputParams.usageFlags, &mGraphicAllocation);
        return err;
    }

    c2_status_t mapGraphic(C2Rect rect, C2MemoryUsage usageFlags, C2PlanarLayout* layout) {
        c2_status_t err = mGraphicAllocation->map(rect, usageFlags, nullptr, layout, mAddrGraphic);
        mMappedRect = rect;
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

    void dumpStats(string operation, int32_t width, int32_t height, string usage,
                   string statsFile) {
        mStats->dumpStatistics(operation, usage, width, height, "GraphicBuffer", mCacheDisabled,
                               statsFile);
    }

    bool mCacheDisabled;
    C2Rect mMappedRect;
    std::shared_ptr<C2Allocator> mGraphicAllocator;
    std::shared_ptr<C2GraphicAllocation> mGraphicAllocation;
    uint8_t* mAddrGraphic[C2PlanarLayout::MAX_NUM_PLANES];
};

/**
 * The following test benchmarks time taken to allocate a linear
 * buffer(ion/dma) of different capacity(size).
 */
TEST_P(BenchmarkLinearBufferTest, LinearAllocationTest) {
    inputParamsLinear params = GetParam();
    c2_status_t status;

    for (int32_t i = 0; i < kMaxIteration; i++) {
        mLinearAllocation.reset();
        int64_t sTime = mStats->getCurTime();
        status = allocateLinear(params);
        int64_t eTime = mStats->getCurTime();
        int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
        ASSERT_FALSE(mLinearAllocation == nullptr || status != C2_OK)
                << "C2Allocator::newLinearAllocation() failed";
        mStats->addOutputTime(timeTaken);
    }
    dumpStats("allocate", params.capacity, params.usage, gEnv->getStatsFile());
}

/**
 * The following test benchmarks time taken to do a map operation.
 * A linear buffer(ion/dma) of different capacity(size) is allocated
 * and time is measured across map-write-unmap operation happening
 * on a buffer.
 */
TEST_P(BenchmarkLinearBufferTest, LinearMappingTest) {
    inputParamsLinear params = GetParam();
    c2_status_t status;
    uint64_t totalTime = 0;

    for (int32_t i = 0; i < kMaxIteration; i++) {
        status = allocateLinear(params);
        ASSERT_FALSE(mLinearAllocation == nullptr || status != C2_OK)
                << "C2Allocator::newLinearAllocation() failed";

        mAddr = nullptr;
        int64_t sTime = mStats->getCurTime();
        status = mapLinear(0u, params);
        int64_t eTime = mStats->getCurTime();
        totalTime += mStats->getTimeDiff(sTime, eTime);
        ASSERT_FALSE(status != C2_OK || mAddr == nullptr) << "C2LinearAllocation::map() failed";
        sTime = mStats->getCurTime();
        writeData(params.capacity, (uint8_t*)mAddr);
        status = unmapLinear(params.capacity);
        eTime = mStats->getCurTime();
        totalTime += mStats->getTimeDiff(sTime, eTime);
        mStats->addOutputTime(totalTime);
        ASSERT_EQ(C2_OK, status) << "Failed to unmap the linear buffer";
    }
    dumpStats("map", params.capacity, params.usage, gEnv->getStatsFile());
}

/**
 * The following test benchmarks time taken to allocate a graphic
 * buffer(gralloc) of different capacity(width x height).
 */
TEST_P(BenchmarkGraphicBufferTest, GraphicAllocationTest) {
    inputParamsGraphic params = GetParam();
    c2_status_t status;

    for (int32_t i = 0; i < kMaxIteration; i++) {
        mGraphicAllocation.reset();
        int64_t sTime = mStats->getCurTime();
        status = allocateGraphic(params);
        int64_t eTime = mStats->getCurTime();
        int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
        ASSERT_FALSE(mGraphicAllocation == nullptr || status != C2_OK)
                << "C2Allocator::newGraphicAllocation() failed";
        mStats->addOutputTime(timeTaken);
    }
    dumpStats("allocate", params.width, params.height, params.usage, gEnv->getStatsFile());
}

/**
 * The following test benchmarks time taken to do a map operation.
 * A graphic buffer(gralloc) of different capacity(width x height)
 * is allocated and time is measured across map-write-unmap
 * operation happening on a buffer.
 */
TEST_P(BenchmarkGraphicBufferTest, GraphicMappingTest) {
    inputParamsGraphic params = GetParam();
    c2_status_t status;
    int64_t timeTaken = 0;

    for (int32_t i = 0; i < kMaxIteration; i++) {
        status = allocateGraphic(params);

        ASSERT_FALSE(mGraphicAllocation == nullptr || status != C2_OK)
                << "C2Allocator::newGraphicAllocation() failed";

        C2Rect rect(params.width, params.height);
        for (int32_t numPlane = 0; numPlane < C2PlanarLayout::MAX_NUM_PLANES; numPlane++) {
            mAddrGraphic[numPlane] = nullptr;
        }
        C2PlanarLayout layout;
        int64_t sTime = mStats->getCurTime();
        status = mapGraphic(rect, params.usageFlags, &layout);
        int64_t eTime = mStats->getCurTime();
        timeTaken += mStats->getTimeDiff(sTime, eTime);

        ASSERT_FALSE(status != C2_OK) << "C2GraphicAllocation::map() failed";
        ASSERT_NE(nullptr, mAddrGraphic[C2PlanarLayout::PLANE_Y]) << "Failed to map PLANE_Y";
        ASSERT_NE(nullptr, mAddrGraphic[C2PlanarLayout::PLANE_U]) << "Failed to map PLANE_U";
        ASSERT_NE(nullptr, mAddrGraphic[C2PlanarLayout::PLANE_V]) << "Failed to map PLANE_V";

        uint8_t* y = mAddrGraphic[C2PlanarLayout::PLANE_Y];
        uint8_t* u = mAddrGraphic[C2PlanarLayout::PLANE_U];
        uint8_t* v = mAddrGraphic[C2PlanarLayout::PLANE_V];
        C2PlaneInfo yInfo = layout.planes[C2PlanarLayout::PLANE_Y];
        C2PlaneInfo uInfo = layout.planes[C2PlanarLayout::PLANE_U];
        C2PlaneInfo vInfo = layout.planes[C2PlanarLayout::PLANE_V];

        sTime = mStats->getCurTime();
        writeData(rect, yInfo, y, 0);
        writeData(rect, uInfo, u, 0);
        writeData(rect, vInfo, v, 0);

        status = unmapGraphic();
        eTime = mStats->getCurTime();
        timeTaken += mStats->getTimeDiff(sTime, eTime);
        mStats->addOutputTime(timeTaken);
        ASSERT_EQ(C2_OK, status) << "Failed to unmap the graphic buffer";
    }
    dumpStats("map-write-unmap", params.width, params.height, params.usage, gEnv->getStatsFile());
}

INSTANTIATE_TEST_SUITE_P(
        BenchmarkLinearBufferTest, BenchmarkLinearBufferTest,
        ::testing::Values(
                inputParamsLinear{(1024u * 1024u),
                                  {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                  "CPU_READ/CPU_WRITE"},
                inputParamsLinear{(512u * 512u),
                                  {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                  "CPU_READ/CPU_WRITE"},
                inputParamsLinear{(256u * 256u),
                                  {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                  "CPU_READ/CPU_WRITE"},
                inputParamsLinear{(128u * 128u),
                                  {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                  "CPU_READ/CPU_WRITE"},
                inputParamsLinear{(64u * 64u),
                                  {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                  "CPU_READ/CPU_WRITE"},
                inputParamsLinear{(1024u * 1024u),
                                  {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                  "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsLinear{(512u * 512u),
                                  {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                  "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsLinear{(256u * 256u),
                                  {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                  "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsLinear{(128u * 128u),
                                  {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                  "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsLinear{(64u * 64u),
                                  {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                  "WRITE_PROTECTED/CPU_WRITE"}));

// TODO: Add pixel format parameter
INSTANTIATE_TEST_SUITE_P(
        BenchmarkGraphicBufferTest, BenchmarkGraphicBufferTest,
        ::testing::Values(
                inputParamsGraphic{320,
                                   240,
                                   {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                   "CPU_READ/CPU_WRITE"},
                inputParamsGraphic{640,
                                   480,
                                   {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                   "CPU_READ/CPU_WRITE"},
                inputParamsGraphic{720,
                                   480,
                                   {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                   "CPU_READ/CPU_WRITE"},
                inputParamsGraphic{1280,
                                   720,
                                   {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                   "CPU_READ/CPU_WRITE"},
                inputParamsGraphic{1920,
                                   1080,
                                   {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                                   "CPU_READ/CPU_WRITE"},
                inputParamsGraphic{320,
                                   240,
                                   {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                   "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsGraphic{640,
                                   480,
                                   {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                   "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsGraphic{720,
                                   480,
                                   {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                   "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsGraphic{1280,
                                   720,
                                   {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                   "WRITE_PROTECTED/CPU_WRITE"},
                inputParamsGraphic{1920,
                                   1080,
                                   {C2MemoryUsage::WRITE_PROTECTED, C2MemoryUsage::CPU_WRITE},
                                   "WRITE_PROTECTED/CPU_WRITE"}));

int main(int argc, char** argv) {
    gEnv = new BenchmarkBufferpoolEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    gEnv->setStatsFile("BenchmarkBufferpool_" + std::to_string(systemTime(CLOCK_MONOTONIC)) +
                       ".csv");
    int status = gEnv->writeStatsHeader();
    ALOGV("Stats file = %d\n", status);
    status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
