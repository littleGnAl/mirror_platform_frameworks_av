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
#include <filters/GraphicBufferListener.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/MediaCodecBuffer.h>
#include <media/stagefright/BufferProducerWrapper.h>
#include <media/stagefright/CodecBase.h>
#include <media/stagefright/MediaFilter.h>
#include <media/stagefright/RenderScriptWrapper.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

using namespace android;

const std::string kComponentNames[] = {"android.filter.zerofilter",
                                       "android.filter.saturation",
                                       "android.filter.intrinsicblur",
                                       "android.filter.RenderScript"};
const std::string kConfigureString = "video/raw";
const std::string kSetParamsString = "cacheDir";
constexpr uint32_t kDimMin = 1;
constexpr uint32_t kDimMax = 10000;
constexpr int32_t kMinFilterAPI = 0;
constexpr int32_t kMaxFilterAPI = 3;
constexpr float kMinBlur = 0.0f;
constexpr float kMaxBlur = 25.0f;

enum FuzzerWhat {
    kWhatStartCompleted,
    kWhatBufferAvailable,
};

enum {
    kCallInput,
    kCallOutput,
};

struct FuzzAHandler : public AHandler {
  public:
    FuzzAHandler(std::function<void(const sp<AMessage>&)> messageHandler)
        : mMessageHandler(messageHandler){};

  protected:
    void onMessageReceived(const sp<AMessage>& msg) override { mMessageHandler(msg); }

  private:
    std::function<void(const sp<AMessage>& msg)> mMessageHandler;
};

class FiltersFuzzer {
  public:
    FiltersFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void configComponentStart(sp<AMessage> configMsg);
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

class FuzzBufferCallback : public CodecBase::BufferCallback {
  public:
    FuzzBufferCallback(bool discardBuffer, const sp<AMessage>& notify) : mNotify(notify) {
        bufferStatus = discardBuffer;
    };
    void onInputBufferAvailable(size_t /* index */, const sp<MediaCodecBuffer>& buffer) {
        sp<AMessage> msg = mNotify->dup();
        msg->setInt32("what", kWhatBufferAvailable);
        msg->setInt32("buffercall", kCallInput);
        msg->setObject("buffer", buffer);
        msg->post();
    };
    void onOutputBufferAvailable(size_t /* index */, const sp<MediaCodecBuffer>& buffer) {
        sp<AMessage> msg = mNotify->dup();
        msg->setInt32("what", kWhatBufferAvailable);
        msg->setInt32("buffercall", kCallOutput);
        msg->setObject("buffer", buffer);
        msg->post();
    };

  private:
    bool bufferStatus;
    const sp<AMessage> mNotify;
};

class FuzzCodecCallback : public CodecBase::CodecCallback {
  public:
    FuzzCodecCallback(const sp<AMessage>& notify) : mNotify(notify){};
    void onEos(status_t /* err */){};
    void onStartCompleted() {
        sp<AMessage> msg = mNotify->dup();
        msg->setInt32("what", kWhatStartCompleted);
        msg->post();
        return;
    };
    void onStopCompleted(){};
    void onReleaseCompleted(){};
    void onFlushCompleted(){};
    void onError(status_t /* err */, enum ActionCode /* actionCode */){};
    void onComponentAllocated(const char* /* componentName */){};
    void onComponentConfigured(const sp<AMessage>& /* inputFormat */,
                               const sp<AMessage>& /* outputFormat */){};
    void onInputSurfaceCreated(const sp<AMessage>& /* inputFormat */,
                               const sp<AMessage>& /* outputFormat */,
                               const sp<BufferProducerWrapper>& /* inputSurface */){};
    void onInputSurfaceCreationFailed(status_t /* err */){};
    void onInputSurfaceAccepted(const sp<AMessage>& /* inputFormat */,
                                const sp<AMessage>& /* outputFormat */){};
    void onInputSurfaceDeclined(status_t /* err */){};
    void onSignaledInputEOS(status_t /* err */){};
    void onOutputFramesRendered(const std::list<RenderedFrameInfo>& /* done */){};
    void onOutputBuffersChanged(){};
    void onFirstTunnelFrameReady(){};

  private:
    const sp<AMessage> mNotify;
};

struct FuzzRSFilterCallback : public RenderScriptWrapper::RSFilterCallback {
  public:
    status_t processBuffers(RSC::Allocation* /* inBuffer */, RSC::Allocation* /* outBuffer */) {
        return OK;
    };
    status_t handleSetParameters(const sp<AMessage>& /* msg */) { return OK; };
};

void FiltersFuzzer::configComponentStart(sp<AMessage> configMsg) {
    configMsg->setString("mime", kConfigureString.c_str());
    configMsg->setInt32("width", mFdp.ConsumeIntegralInRange<int32_t>(kDimMin, kDimMax));
    configMsg->setInt32("height", mFdp.ConsumeIntegralInRange<int32_t>(kDimMin, kDimMax));
    configMsg->setFloat("blur-radius", mFdp.ConsumeFloatingPointInRange<float>(kMinBlur, kMaxBlur));
    configMsg->setFloat("saturation", mFdp.ConsumeFloatingPoint<float>());
    configMsg->setString("cacheDir", kSetParamsString.c_str());
    configMsg->setInt32("color-format", mFdp.ConsumeIntegral<int32_t>());
    configMsg->setInt32("invert", mFdp.ConsumeIntegral<int32_t>());

    sp<RenderScriptWrapper> rsWrapper = sp<RenderScriptWrapper>::make();
    rsWrapper->mCallback = sp<FuzzRSFilterCallback>::make();
    rsWrapper->mContext = new RSC::RS();
    rsWrapper->mContext->init(mFdp.ConsumeRandomLengthString().c_str(), RS_CONTEXT_SYNCHRONOUS);
    configMsg->setObject("rs-wrapper", rsWrapper);
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
    configComponentStart(configMsg);
    mediaFilter->initiateConfigureComponent(configMsg);

    mediaFilter->signalSetParameters(configMsg);

    mBufferChannel = mediaFilter->getBufferChannel();

    mBufferChannel->setCallback(std::make_unique<FuzzBufferCallback>(
            mFdp.ConsumeBool(), sp<AMessage>::make(kWhatBufferAvailable, handler)));
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
