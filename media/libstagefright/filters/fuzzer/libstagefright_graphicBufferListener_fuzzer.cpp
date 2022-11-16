/*
 * Copyright 2022 The Android Open Source Project
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
#include <gui/BufferQueueProducer.h>
#include <gui/IProducerListener.h>
#include <system/window.h>

#include "libstagefright_mediafilter_utils.h"

using namespace android;
using namespace hardware::graphics::bufferqueue;

constexpr int32_t kDimMin = 2;
constexpr int32_t kDimMax = 4096;
constexpr int32_t kSlotMin = 0;
constexpr int32_t kSlotMax = 64;
constexpr float kMinBlur = 0.0f;
constexpr float kMaxBlur = 25.0f;

constexpr android_dataspace_t kDataSpaces[] = {
        HAL_DATASPACE_UNKNOWN,
        HAL_DATASPACE_ARBITRARY,
        HAL_DATASPACE_STANDARD_SHIFT,
        HAL_DATASPACE_STANDARD_MASK,
        HAL_DATASPACE_STANDARD_UNSPECIFIED,
        HAL_DATASPACE_STANDARD_BT709,
        HAL_DATASPACE_STANDARD_BT601_625,
        HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED,
        HAL_DATASPACE_STANDARD_BT601_525,
        HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED,
        HAL_DATASPACE_STANDARD_BT2020,
        HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE,
        HAL_DATASPACE_STANDARD_BT470M,
        HAL_DATASPACE_STANDARD_FILM,
        HAL_DATASPACE_STANDARD_DCI_P3,
        HAL_DATASPACE_STANDARD_ADOBE_RGB,
        HAL_DATASPACE_TRANSFER_SHIFT,
        HAL_DATASPACE_TRANSFER_MASK,
        HAL_DATASPACE_TRANSFER_UNSPECIFIED,
        HAL_DATASPACE_TRANSFER_LINEAR,
        HAL_DATASPACE_TRANSFER_SRGB,
        HAL_DATASPACE_TRANSFER_SMPTE_170M,
        HAL_DATASPACE_TRANSFER_GAMMA2_2,
        HAL_DATASPACE_TRANSFER_GAMMA2_6,
        HAL_DATASPACE_TRANSFER_GAMMA2_8,
        HAL_DATASPACE_TRANSFER_ST2084,
        HAL_DATASPACE_TRANSFER_HLG,
        HAL_DATASPACE_RANGE_SHIFT,
        HAL_DATASPACE_RANGE_MASK,
        HAL_DATASPACE_RANGE_UNSPECIFIED,
        HAL_DATASPACE_RANGE_FULL,
        HAL_DATASPACE_RANGE_LIMITED,
        HAL_DATASPACE_RANGE_EXTENDED,
        HAL_DATASPACE_SRGB_LINEAR,
        HAL_DATASPACE_V0_SRGB_LINEAR,
        HAL_DATASPACE_V0_SCRGB_LINEAR,
        HAL_DATASPACE_SRGB,
        HAL_DATASPACE_V0_SRGB,
        HAL_DATASPACE_V0_SCRGB,
        HAL_DATASPACE_JFIF,
        HAL_DATASPACE_V0_JFIF,
        HAL_DATASPACE_BT601_625,
        HAL_DATASPACE_V0_BT601_625,
        HAL_DATASPACE_BT601_525,
        HAL_DATASPACE_V0_BT601_525,
        HAL_DATASPACE_BT709,
        HAL_DATASPACE_V0_BT709,
        HAL_DATASPACE_DCI_P3_LINEAR,
        HAL_DATASPACE_DCI_P3,
        HAL_DATASPACE_DISPLAY_P3_LINEAR,
        HAL_DATASPACE_DISPLAY_P3,
        HAL_DATASPACE_ADOBE_RGB,
        HAL_DATASPACE_BT2020_LINEAR,
        HAL_DATASPACE_BT2020,
        HAL_DATASPACE_BT2020_PQ,
        HAL_DATASPACE_DEPTH,
        HAL_DATASPACE_SENSOR,
};

constexpr int kScalingModes[] = {
        NATIVE_WINDOW_SCALING_MODE_FREEZE,
        NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW,
        NATIVE_WINDOW_SCALING_MODE_SCALE_CROP,
        NATIVE_WINDOW_SCALING_MODE_NO_SCALE_CROP,
};

constexpr int kSelectAPI[] = {
        NATIVE_WINDOW_API_EGL,
        NATIVE_WINDOW_API_CPU,
        NATIVE_WINDOW_API_MEDIA,
        NATIVE_WINDOW_API_CAMERA,
};

constexpr uint64_t kUsageTypes[] = {
        GRALLOC_USAGE_SW_READ_NEVER,  GRALLOC_USAGE_SW_READ_RARELY, GRALLOC_USAGE_SW_READ_OFTEN,
        GRALLOC_USAGE_SW_READ_MASK,   GRALLOC_USAGE_SW_WRITE_NEVER, GRALLOC_USAGE_SW_WRITE_RARELY,
        GRALLOC_USAGE_SW_WRITE_OFTEN, GRALLOC_USAGE_SW_WRITE_MASK,
};

constexpr int32_t kPixelFormatTypes[] = {
        PIXEL_FORMAT_UNKNOWN, PIXEL_FORMAT_NONE,        PIXEL_FORMAT_RGBA_8888,
        PIXEL_FORMAT_CUSTOM,  PIXEL_FORMAT_TRANSLUCENT, PIXEL_FORMAT_TRANSPARENT,
        PIXEL_FORMAT_OPAQUE,
};
class GraphicBufferListenerFuzzer {
  public:
    GraphicBufferListenerFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void callQueueBuffer(const sp<IGraphicBufferProducer>& bufferProducer);
    void handleMessages(const sp<AMessage>& msg);
    std::shared_ptr<BufferChannelBase> mBufferChannel;
    std::mutex mInputSurfaceMutex;
    std::condition_variable mConditionInputSurface;
    bool mInputSurfaceCreated = false;
    FuzzedDataProvider mFdp;
    sp<IGraphicBufferProducer> mProducer;
    bool mGraphicBufferListener = false;
    std::condition_variable mGraphicBufferListenerCondition;
};

void FuzzBufferCallback::onInputBufferAvailable(size_t /* index */,
                                                const sp<MediaCodecBuffer>& buffer) {
    (void)buffer;
}

void FuzzBufferCallback::onOutputBufferAvailable(size_t /* index */,
                                                 const sp<MediaCodecBuffer>& buffer) {
    sp<AMessage> msg = mNotify->dup();
    msg->setWhat(kWhatBufferAvailable);
    msg->post();
    (void)buffer;
};

void GraphicBufferListenerFuzzer::handleMessages(const sp<AMessage>& msg) {
    switch (msg->what()) {
        case kWhatInputSurfaceCreated: {
            sp<BufferProducerWrapper> wrapper;
            msg->findObject("producer-wrapper", (sp<RefBase>*)&wrapper);
            mProducer = std::move(wrapper->getBufferProducer());
            mInputSurfaceCreated = true;
            mConditionInputSurface.notify_one();
            break;
        }
        case kWhatBufferAvailable: {
            mGraphicBufferListener = true;
            mGraphicBufferListenerCondition.notify_one();
        }
    }
}

void GraphicBufferListenerFuzzer::callQueueBuffer(const sp<IGraphicBufferProducer>& producer) {
    const sp<android::IProducerListener> listener;
    android::IGraphicBufferProducer::QueueBufferOutput output;
    uint32_t api = mFdp.PickValueInArray(kSelectAPI);
    producer->connect(listener, api, mFdp.ConsumeBool() /* producerControlledByApp */, &output);

    sp<GraphicBuffer> buffer;
    int32_t slot = mFdp.ConsumeIntegralInRange<int32_t>(kSlotMin, kSlotMax);
    sp<Fence> fence = Fence::NO_FENCE;
    producer->setAsyncMode(false);

    uint32_t width = mFdp.ConsumeIntegralInRange<uint32_t>(kDimMin, kDimMax);
    uint32_t height = mFdp.ConsumeIntegralInRange<uint32_t>(kDimMin, kDimMax);

    int32_t pixelFormat = mFdp.PickValueInArray(kPixelFormatTypes);
    uint64_t usageType = mFdp.PickValueInArray(kUsageTypes);
    FrameEventHistoryDelta delta;
    uint64_t outBufferAge;
    status_t dequeueStatus = producer->dequeueBuffer(&slot, &fence, width, height, pixelFormat,
                                                     usageType, &outBufferAge, &delta);
    status_t requestStatus = producer->requestBuffer(slot, &buffer);

    int64_t timeStamp = mFdp.ConsumeIntegral<int64_t>();
    android_dataspace_t dataSpace = mFdp.PickValueInArray(kDataSpaces);
    int32_t rectL = mFdp.ConsumeIntegralInRange<int32_t>(0, width - 1);
    int32_t rectT = mFdp.ConsumeIntegralInRange<int32_t>(0, height - 1);
    int32_t rectR = mFdp.ConsumeIntegralInRange<int32_t>(rectL, width - 1);
    int32_t rectB = mFdp.ConsumeIntegralInRange<int32_t>(rectT, height - 1);
    int scalingMode = mFdp.PickValueInArray(kScalingModes);
    uint32_t transform = mFdp.ConsumeIntegral<uint32_t>();
    IGraphicBufferProducer::QueueBufferInput input(
            timeStamp, mFdp.ConsumeBool() /* _isAutoTimestamp */, dataSpace,
            Rect(rectL, rectT, rectR, rectB), scalingMode, transform, fence);

    status_t queueStatus = producer->queueBuffer(slot, input, &output);

    if (dequeueStatus != NO_ERROR && requestStatus != NO_ERROR && queueStatus != NO_ERROR) {
        mGraphicBufferListener = true;
        mGraphicBufferListenerCondition.notify_one();
    }
}

void GraphicBufferListenerFuzzer::process() {
    sp<FuzzAHandler> handler = sp<FuzzAHandler>::make(
            std::bind(&GraphicBufferListenerFuzzer::handleMessages, this, std::placeholders::_1));
    sp<MediaFilter> mediaFilter = sp<MediaFilter>::make();
    sp<ALooper> mediaFilterLooper = sp<ALooper>::make();
    mediaFilterLooper->start();
    mediaFilterLooper->registerHandler(handler);
    mediaFilterLooper->registerHandler(mediaFilter);

    mediaFilter->setCallback(std::make_unique<FuzzCodecCallback>(
            sp<AMessage>::make(kWhatInputSurfaceCreated, handler)));

    const sp<AMessage> initiateAllocateMsg = sp<AMessage>::make();
    initiateAllocateMsg->setString("componentName", mFdp.PickValueInArray(kComponentNames).c_str());
    mediaFilter->initiateAllocateComponent(initiateAllocateMsg);

    const sp<AMessage> configMsg = sp<AMessage>::make();
    configComponentStart(configMsg, mFdp.ConsumeIntegralInRange<int32_t>(kDimMin, kDimMax),
                         mFdp.ConsumeIntegralInRange<int32_t>(kDimMin, kDimMax),
                         mFdp.ConsumeFloatingPointInRange<float>(kMinBlur, kMaxBlur),
                         mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeIntegral<int32_t>(),
                         mFdp.ConsumeIntegral<int32_t>(), mFdp.ConsumeRandomLengthString());
    mediaFilter->initiateConfigureComponent(configMsg);

    mediaFilter->signalSetParameters(configMsg);

    mBufferChannel = mediaFilter->getBufferChannel();

    mediaFilter->initiateCreateInputSurface();

    mBufferChannel->setCallback(std::make_unique<FuzzBufferCallback>(
            sp<AMessage>::make(kWhatBufferAvailable, handler)));

    mediaFilter->initiateStart();

    std::unique_lock waitForInputSurface(mInputSurfaceMutex);
    mConditionInputSurface.wait(waitForInputSurface, [this] { return mInputSurfaceCreated; });

    sp<IGraphicBufferProducer> producer = std::move(mProducer);
    callQueueBuffer(producer);

    std::mutex graphicBufferListenerMutex;
    std::unique_lock graphicBufferListenerLock(graphicBufferListenerMutex);
    mGraphicBufferListenerCondition.wait(graphicBufferListenerLock,
                                         [this] { return mGraphicBufferListener; });
    mediaFilterLooper->stop();
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    GraphicBufferListenerFuzzer graphicBufferListenerFuzzer(data, size);
    graphicBufferListenerFuzzer.process();
    return 0;
}
