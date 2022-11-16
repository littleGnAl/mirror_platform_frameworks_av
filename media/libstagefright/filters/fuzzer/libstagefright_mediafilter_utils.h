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
#include <filters/GraphicBufferListener.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/MediaCodecBuffer.h>
#include <media/stagefright/BufferProducerWrapper.h>
#include <media/stagefright/MediaFilter.h>
#include <media/stagefright/RenderScriptWrapper.h>

using namespace android;

const std::string kComponentNames[] = {"android.filter.zerofilter",
                                       "android.filter.saturation",
                                       "android.filter.intrinsicblur",
                                       "android.filter.RenderScript"};
const std::string kConfigureString = "video/raw";
const std::string kSetParamsString = "cacheDir";

enum FuzzerWhat {
    kWhatStartCompleted,
    kWhatBufferAvailable,
    kWhatInputSurfaceCreated,
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

struct FuzzRSFilterCallback : public RenderScriptWrapper::RSFilterCallback {
  public:
    status_t processBuffers(RSC::Allocation* /* inBuffer */, RSC::Allocation* /* outBuffer */) {
        return OK;
    };
    status_t handleSetParameters(const sp<AMessage>& /* msg */) { return OK; };
};

void configComponentStart(sp<AMessage> configMsg, int32_t width, int32_t height, float blur,
                          float saturation, int32_t colorFormat, int32_t invert, std::string name) {
    configMsg->setString("mime", kConfigureString.c_str());
    configMsg->setInt32("width", width);
    configMsg->setInt32("height", height);
    configMsg->setFloat("blur-radius", blur);
    configMsg->setFloat("saturation", saturation);
    configMsg->setString("cacheDir", kSetParamsString.c_str());
    configMsg->setInt32("color-format", colorFormat);
    configMsg->setInt32("invert", invert);

    sp<RenderScriptWrapper> rsWrapper = sp<RenderScriptWrapper>::make();
    rsWrapper->mCallback = sp<FuzzRSFilterCallback>::make();
    rsWrapper->mContext = new RSC::RS();
    rsWrapper->mContext->init(name.c_str() /* name */, RS_CONTEXT_SYNCHRONOUS /* flag */);
    configMsg->setObject("rs-wrapper", rsWrapper);
}

class FuzzBufferCallback : public CodecBase::BufferCallback {
  public:
    FuzzBufferCallback(const sp<AMessage>& notify) : mNotify(notify){};
    void onInputBufferAvailable(size_t /* index */, const sp<MediaCodecBuffer>& buffer);
    void onOutputBufferAvailable(size_t /* index */, const sp<MediaCodecBuffer>& buffer);

  private:
    const sp<AMessage> mNotify;
};

class FuzzCodecCallback : public CodecBase::CodecCallback {
  public:
    FuzzCodecCallback(const sp<AMessage>& notify) : mNotify(notify){};
    void onEos(status_t /* err */){};
    void onStartCompleted();
    void onStopCompleted(){};
    void onReleaseCompleted(){};
    void onFlushCompleted(){};
    void onError(status_t /* err */, enum ActionCode /* actionCode */){};
    void onComponentAllocated(const char* /* componentName */){};
    void onComponentConfigured(const sp<AMessage>& /* inputFormat */,
                               const sp<AMessage>& /* outputFormat */){};
    void onInputSurfaceCreated(const sp<AMessage>& /* inputFormat */,
                               const sp<AMessage>& /* outputFormat */,
                               const sp<BufferProducerWrapper>& inputSurface);
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

void FuzzCodecCallback::onStartCompleted() {
    sp<AMessage> msg = mNotify->dup();
    msg->setWhat(kWhatStartCompleted);
    msg->post();
    return;
};

void FuzzCodecCallback::onInputSurfaceCreated(const sp<AMessage>& /* inputFormat */,
                                              const sp<AMessage>& /* outputFormat */,
                                              const sp<BufferProducerWrapper>& inputSurface) {
    sp<BufferProducerWrapper> wrapper = std::move(inputSurface);
    sp<AMessage> msg = mNotify->dup();
    msg->setWhat(kWhatInputSurfaceCreated);
    msg->setObject("producer-wrapper", wrapper.get());
    msg->post();
    return;
}
