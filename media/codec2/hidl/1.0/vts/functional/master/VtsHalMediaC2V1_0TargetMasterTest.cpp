/*
 * Copyright (C) 2018 The Android Open Source Project
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
#define LOG_TAG "codec2_hidl_hal_master_test"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <hidl/GtestPrinter.h>
#include <hidl/ServiceManagement.h>

#include <codec2/hidl/client.h>

#include <ui/GraphicBufferAllocator.h>
#include <ui/GraphicBufferMapper.h>

#include <VtsHalHidlTargetTestBase.h>
#include "media_c2_hidl_test_common.h"

namespace {

// google.codec2 Master test setup
class Codec2MasterHalTest : public ::testing::TestWithParam<std::string> {
  public:
    virtual void SetUp() override {
        mClient = android::Codec2Client::CreateFromService(GetParam().c_str());
        ASSERT_NE(mClient, nullptr);
    }

  protected:
    static void description(const std::string& description) {
        RecordProperty("description", description);
    }

    void setPixelFormatAndBitDepth();

    std::shared_ptr<android::Codec2Client> mClient;
    std::vector<uint32_t> mSupportedPixelFormats;
    std::vector<uint32_t> mSupportedBitDepth;
    bool mSkipTest = true;
};

void Codec2MasterHalTest::setPixelFormatAndBitDepth() {
    std::vector<std::unique_ptr<C2Param>> heapParams;
    C2StoreFlexiblePixelFormatDescriptorsInfo *pixelFormatInfo = nullptr;
    if (mClient->query(
                {},
                {C2StoreFlexiblePixelFormatDescriptorsInfo::PARAM_TYPE},
                C2_MAY_BLOCK,
                &heapParams) == C2_OK
                && heapParams.size() == 1u) {
            pixelFormatInfo = C2StoreFlexiblePixelFormatDescriptorsInfo::From(
                heapParams[0].get());
    } else {
        pixelFormatInfo = nullptr;
    }

    /* check if the pixel format is supported by the device */
    if (pixelFormatInfo) {
        for (size_t i = 0; i < pixelFormatInfo->flexCount(); ++i) {
            const C2FlexiblePixelFormatDescriptorStruct &desc =
                pixelFormatInfo->m.values[i];
            mSupportedPixelFormats.push_back(desc.pixelFormat);
            mSupportedBitDepth.push_back(desc.bitDepth);
            mSkipTest = false;
        }
    }
}

void displayComponentInfo(const std::vector<C2Component::Traits>& compList) {
    for (size_t i = 0; i < compList.size(); i++) {
        std::cout << compList[i].name << " | " << compList[i].domain;
        std::cout << " | " << compList[i].kind << "\n";
    }
}

// List Components
TEST_P(Codec2MasterHalTest, ListComponents) {
    ALOGV("ListComponents Test");

    C2String name = mClient->getName();
    EXPECT_NE(name.empty(), true) << "Invalid Codec2Client Name";

    // Get List of components from all known services
    const std::vector<C2Component::Traits> listTraits = mClient->ListComponents();

    if (listTraits.size() == 0)
        ALOGE("Warning, ComponentInfo list empty");
    else {
        (void)displayComponentInfo;
        for (size_t i = 0; i < listTraits.size(); i++) {
            std::shared_ptr<android::Codec2Client::Listener> listener;
            std::shared_ptr<android::Codec2Client::Component> component;
            listener.reset(new CodecListener());
            ASSERT_NE(listener, nullptr);

            // Create component from all known services
            const c2_status_t status =
                    android::Codec2Client::CreateComponentByName(
                            listTraits[i].name.c_str(), listener, &component, &mClient);
            ASSERT_EQ(status, C2_OK)
                    << "Create component failed for " << listTraits[i].name.c_str();
        }
    }
}

TEST_P(Codec2MasterHalTest, PixelFormatInfoTest) {
    setPixelFormatAndBitDepth();
    if (mSkipTest) GTEST_SKIP() << "Pixel format not supported by device";

    const uint32_t width = 480;
    const uint32_t height = 320;
    std::shared_ptr<C2BlockPool> pool;
    ASSERT_EQ(android::OK, android::GetCodec2BlockPool(
            C2BlockPool::BASIC_GRAPHIC, nullptr, &pool));

    uint32_t i;
    for (i = 0; i < mSupportedPixelFormats.size(); i++) {
        std::shared_ptr<C2GraphicBlock> block;
        ASSERT_EQ(android::OK, pool->fetchGraphicBlock(
                width, height, mSupportedPixelFormats[i],
                C2MemoryUsage{C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE}, &block));

        uint32_t stride = 0;
        buffer_handle_t handle = nullptr;
        android::GraphicBufferAllocator& allocator = android::GraphicBufferAllocator::get();
        android::status_t error = allocator.allocate(
                width, height, static_cast<android::PixelFormat>(mSupportedPixelFormats[i]), 1,
                C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE, &handle, &stride,
                "codec2_vts_component");

        ASSERT_EQ(error, android::NO_ERROR);
        ASSERT_NE(handle, nullptr);

        android::GraphicBufferMapper& gbmapper = android::GraphicBufferMapper::get();
        buffer_handle_t buff;
        gbmapper.importBuffer(
                handle, width, height, 1,
                static_cast<android::PixelFormat>(mSupportedPixelFormats[i]),
                C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE, stride, &buff);
        EXPECT_EQ(error, android::NO_ERROR);

        android::Rect rect(0, 0, width, height);

        void* data;
        int32_t outBytesPerPixel;
        int32_t outBytesPerStride;
        error = gbmapper.lock(buff, C2MemoryUsage::CPU_READ | C2MemoryUsage::CPU_WRITE,
                              rect, &data, &outBytesPerPixel, &outBytesPerStride);
        EXPECT_EQ(error, android::NO_ERROR);

        C2GraphicView view = block->map().get();
        C2PlanarLayout layout = view.layout();

        switch (layout.type) {
            case C2PlanarLayout::TYPE_YUV: {
                const C2PlaneInfo& yPlane = layout.planes[C2PlanarLayout::PLANE_Y];
                const C2PlaneInfo& uPlane = layout.planes[C2PlanarLayout::PLANE_U];
                const C2PlaneInfo& vPlane = layout.planes[C2PlanarLayout::PLANE_V];

                if (layout.numPlanes == C2PlanarLayout::MAX_NUM_PLANES) {
                    const C2PlaneInfo& aPlane = layout.planes[C2PlanarLayout::PLANE_A];
                    ASSERT_GE(aPlane.allocatedDepth, mSupportedBitDepth[i]);
                    ASSERT_EQ(aPlane.bitDepth, mSupportedBitDepth[i]);
                }

                // Y plane
                ASSERT_GE(yPlane.allocatedDepth, mSupportedBitDepth[i]);
                ASSERT_EQ(yPlane.bitDepth, mSupportedBitDepth[i]);

                // U plane
                ASSERT_GE(uPlane.allocatedDepth, mSupportedBitDepth[i]);
                ASSERT_EQ(uPlane.bitDepth, mSupportedBitDepth[i]);

                // V plane
                ASSERT_GE(vPlane.allocatedDepth, mSupportedBitDepth[i]);
                ASSERT_EQ(vPlane.bitDepth, mSupportedBitDepth[i]);

                break;
            }

            case C2PlanarLayout::TYPE_YUVA:
            case C2PlanarLayout::TYPE_RGB:
            case C2PlanarLayout::TYPE_RGBA:
            case C2PlanarLayout::TYPE_UNKNOWN:
            default:
                break;
        }
    }
}

}  // anonymous namespace

INSTANTIATE_TEST_SUITE_P(PerInstance, Codec2MasterHalTest,
                         testing::ValuesIn(android::Codec2Client::GetServiceNames()),
                         android::hardware::PrintInstanceNameToString);
