/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

#include "libstagefright_mediafilter_utils.h"

using namespace android;

constexpr uint32_t kDimMin = 1;
constexpr uint32_t kDimMax = 10000;
constexpr int32_t kMinFilterAPI = 0;
constexpr int32_t kMaxFilterAPI = 3;
constexpr float kMinBlur = 0.0f;
constexpr float kMaxBlur = 25.0f;

class FiltersFuzzer {
  public:
    FiltersFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void callInput(const sp<MediaCodecBuffer>& buffer) {
        buffer->meta()->setInt64("timeUs", 0);
        buffer->meta()->setInt32("csd", 0);
        if (mCallBufferAPIs) {
            mBufferChannel->queueInputBuffer(buffer);
        } else {
            mBufferChannel->discardBuffer(buffer);
        }
    };
    void callOutput(const sp<MediaCodecBuffer>& buffer) {
        if (mCallBufferAPIs) {
            mBufferChannel->renderOutputBuffer(buffer, 0);
        } else {
            mBufferChannel->discardBuffer(buffer);
        }
    };
    void handleMessages(const sp<AMessage>& msg);
    std::shared_ptr<BufferChannelBase> mBufferChannel;
    std::mutex mStartMutex;
    std::condition_variable mConditionStarted;
    FuzzedDataProvider mFdp;
    bool mStarted = false;
    bool mCallBufferAPIs = false;
};

void FuzzBufferCallback::onInputBufferAvailable(size_t /* index */,
                                                const sp<MediaCodecBuffer>& buffer) {
    sp<AMessage> msg = mNotify->dup();
    msg->setInt32("buffercall", kCallInput);
    msg->setObject("buffer", buffer);
    msg->post();
}

void FuzzBufferCallback::onOutputBufferAvailable(size_t /* index */,
                                                 const sp<MediaCodecBuffer>& buffer) {
    sp<AMessage> msg = mNotify->dup();
    msg->setInt32("buffercall", kCallOutput);
    msg->setObject("buffer", buffer);
    msg->post();
};

void FiltersFuzzer::handleMessages(const sp<AMessage>& msg) {
    switch (msg->what()) {
        case kWhatStartCompleted: {
            mStarted = true;
            mConditionStarted.notify_one();
            break;
        }
        case kWhatBufferAvailable: {
            sp<MediaCodecBuffer> buffer;
            int32_t buffercall;
            msg->findObject("buffer", (sp<RefBase>*)&buffer);
            msg->findInt32("buffercall", &buffercall);
            if (buffercall == kCallInput) {
                callInput(buffer);
            } else {
                if (buffercall == kCallOutput) {
                    callOutput(buffer);
                }
            }
            break;
        }
    }
}

void FiltersFuzzer::process() {
    sp<FuzzAHandler> handler = sp<FuzzAHandler>::make(
            std::bind(&FiltersFuzzer::handleMessages, this, std::placeholders::_1));
    sp<MediaFilter> mediaFilter = sp<MediaFilter>::make();
    sp<ALooper> mediaFilterLooper = sp<ALooper>::make();
    mediaFilterLooper->start();
    mediaFilterLooper->registerHandler(handler);
    mediaFilterLooper->registerHandler(mediaFilter);
    mCallBufferAPIs = mFdp.ConsumeBool();

    /**
     * MediaFilter::mState value is checked and updated in some of the APIs.
     * Thus in order to avoid aborts, the APIs outside while loop cannot
     * be randomized.
     */
    mediaFilter->setCallback(
            std::make_unique<FuzzCodecCallback>(sp<AMessage>::make(kWhatStartCompleted, handler)));
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

    mBufferChannel->setCallback(std::make_unique<FuzzBufferCallback>(
            sp<AMessage>::make(kWhatBufferAvailable, handler)));
    mediaFilter->initiateStart();

    while (mFdp.remaining_bytes()) {
        switch (mFdp.ConsumeIntegralInRange<size_t>(kMinFilterAPI, kMaxFilterAPI)) {
            case 0: {
                mediaFilter->initiateShutdown(mFdp.ConsumeBool());
                break;
            }
            case 1: {
                mediaFilter->signalFlush();
                break;
            }
            case 2: {
                mediaFilter->signalResume();
                break;
            }
            case 3: {
                std::unique_lock waitForStart(mStartMutex);
                mConditionStarted.wait(waitForStart, [this] { return mStarted; });
                mediaFilter->signalEndOfInputStream();
                break;
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FiltersFuzzer filtersFuzzer(data, size);
    filtersFuzzer.process();
    return 0;
}
