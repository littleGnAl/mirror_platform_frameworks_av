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
#define LOG_TAG "C2SoftRawDec"
#include <log/log.h>

#include <media/stagefright/foundation/MediaDefs.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include "C2SoftRawDec.h"

namespace android {

namespace {

constexpr char COMPONENT_NAME[] = "c2.android.raw.decoder";

}  // namespace

class C2SoftRawDec::IntfImpl : public SimpleInterface<void>::BaseParams {
public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
        : SimpleInterface<void>::BaseParams(
                helper,
                COMPONENT_NAME,
                C2Component::KIND_DECODER,
                C2Component::DOMAIN_AUDIO,
                MEDIA_MIMETYPE_AUDIO_RAW) {
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();
        setDerivedInstance(this);

        addParameter(
                DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                .withConstValue(new C2ComponentAttributesSetting(
                    C2Component::ATTRIB_IS_TEMPORAL))
                .build());

        addParameter(
                DefineParam(mSampleRate, C2_PARAMKEY_SAMPLE_RATE)
                .withDefault(new C2StreamSampleRateInfo::output(0u, 44100))
                .withFields({C2F(mSampleRate, value).greaterThan(0)})
                .withSetter((Setter<decltype(*mSampleRate)>::StrictValueWithNoDeps))
                .build());

        addParameter(
                DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                .withDefault(new C2StreamChannelCountInfo::output(0u, 2))
                .withFields({C2F(mChannelCount, value).inRange(1, 8)})
                .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mBitrate, C2_PARAMKEY_BITRATE)
                .withDefault(new C2StreamBitrateInfo::input(0u, 64000))
                .withFields({C2F(mBitrate, value).inRange(1, 98304000)})
                .withSetter(Setter<decltype(*mBitrate)>::NonStrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                .withConstValue(new C2StreamMaxBufferSizeInfo::input(0u, 64 * 1024))
                .build());

        addParameter(
                DefineParam(mOutputMaxBufferSize, C2_PARAMKEY_OUTPUT_MAX_BUFFER_SIZE)
                // default codec operates in single access-unit mode
                .withDefault(new C2StreamMaxBufferSizeInfo::output(0u, 0))
                // max output buffer size
                // 2mins of 512000/8ch/2 bytes per channel
                // 92mins of 44100/2ch/2 bytes per channel
                .withFields({C2F(mOutputMaxBufferSize, value).inRange(0, 120 * 512000 * 8 * 2)})
                .withSetter(MaxOutputSetter)
                .build());

        addParameter(
                DefineParam(mOutputThresholdBufferSize, C2_PARAMKEY_OUTPUT_THRESHOLD_BUFFER_SIZE)
                .withDefault(new C2StreamThresholdBufferSizeInfo::output(0u, 0))
                .withFields(
                        {C2F(mOutputThresholdBufferSize, value).inRange(0, 120 * 512000 * 8 * 2)})
                .withSetter(OutputThresholdSetter, mOutputMaxBufferSize)
                .build());


        addParameter(
                DefineParam(mPcmEncodingInfo, C2_PARAMKEY_PCM_ENCODING)
                .withDefault(new C2StreamPcmEncodingInfo::output(0u, C2Config::PCM_16))
                .withFields({C2F(mPcmEncodingInfo, value).oneOf({
                     C2Config::PCM_16,
                     C2Config::PCM_8,
                     C2Config::PCM_FLOAT,
                     C2Config::PCM_24,
                     C2Config::PCM_32})
                })
                .withSetter((Setter<decltype(*mPcmEncodingInfo)>::StrictValueWithNoDeps))
                .build());

    }

    static C2R OutputThresholdSetter(bool mayBlock,
            C2P<C2StreamThresholdBufferSizeInfo::output> &me,
                    const C2P<C2StreamMaxBufferSizeInfo::output> &maxSize) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        me.set().value = c2_min(me.v.value, maxSize.v.value);
        return res;
    }

    static C2R MaxOutputSetter(bool mayBlock, const C2P<C2StreamMaxBufferSizeInfo::output> &oldMe,
            C2P<C2StreamMaxBufferSizeInfo::output> &me) {
        (void)mayBlock;
        C2R res = C2R::Ok();
        if (!me.F(me.v.value).supportsAtAll(me.v.value)) {
            res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.value)));
            me.set().value = oldMe.v.value;
        }
        return res;
    }

    uint32_t getThresholdSize() const {
        return mOutputThresholdBufferSize->value;
    }

    uint32_t getMaxOutputSize() const {
        return mOutputMaxBufferSize->value;
    }

private:
    std::shared_ptr<C2StreamSampleRateInfo::output> mSampleRate;
    std::shared_ptr<C2StreamChannelCountInfo::output> mChannelCount;
    std::shared_ptr<C2StreamBitrateInfo::input> mBitrate;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::output> mOutputMaxBufferSize;
    std::shared_ptr<C2StreamThresholdBufferSizeInfo::output> mOutputThresholdBufferSize;
    std::shared_ptr<C2StreamPcmEncodingInfo::output> mPcmEncodingInfo;
};

C2SoftRawDec::C2SoftRawDec(
        const char *name,
        c2_node_id_t id,
        const std::shared_ptr<IntfImpl> &intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl) {
}

C2SoftRawDec::~C2SoftRawDec() {
    onRelease();
}

c2_status_t C2SoftRawDec::onInit() {
    mSignalledEos = false;
    return C2_OK;
}

c2_status_t C2SoftRawDec::onStop() {
    mSignalledEos = false;
    return C2_OK;
}

void C2SoftRawDec::onReset() {
    (void)onStop();
}

void C2SoftRawDec::onRelease() {
}

c2_status_t C2SoftRawDec::onFlush_sm() {
    return onStop();
}

void C2SoftRawDec::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void)pool;
    work->result = C2_OK;
    work->workletsProcessed = 1u;

    if (mSignalledEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    class FillWork {
       public:
        FillWork(uint32_t flags, C2WorkOrdinalStruct ordinal,
                 const std::shared_ptr<C2Buffer>& buffer)
            : mFlags(flags), mOrdinal(ordinal), mBuffer(buffer) {}
        ~FillWork() = default;

        void operator()(const std::unique_ptr<C2Work>& work) {
            work->worklets.front()->output.flags = (C2FrameData::flags_t)mFlags;
            work->worklets.front()->output.buffers.clear();
            work->worklets.front()->output.ordinal = mOrdinal;
            work->workletsProcessed = 1u;
            work->result = C2_OK;
            if (mBuffer) {
                work->worklets.front()->output.buffers.push_back(mBuffer);
            }
            ALOGV("timestamp = %lld, index = %lld, w/%s buffer",
                  mOrdinal.timestamp.peekll(), mOrdinal.frameIndex.peekll(),
                  mBuffer ? "" : "o");
        }

       private:
        const uint32_t mFlags;
        const C2WorkOrdinalStruct mOrdinal;
        const std::shared_ptr<C2Buffer> mBuffer;
    };

    if (work->input.buffers.empty()) {
        // we have nothing to to process.
        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.ordinal = work->input.ordinal;
        if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
            mSignalledEos = true;
            ALOGV("Signalled end-of-stream");
        }
        return;
    }

    ALOGV("in buffer attr. timestamp %lld frameindex %lld",
            (long long)work->input.ordinal.timestamp.peekull(),
            (long long)work->input.ordinal.frameIndex.peekull());
    C2ReadView rView = mDummyReadView;
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    work->worklets.front()->output.buffers.clear();
    uint32_t maxOutSize = mIntf->getMaxOutputSize();
    uint32_t thresholdSize = mIntf->getThresholdSize();
    if (maxOutSize != 0) {
        // codec operates in large buffer mode.
        ALOGV("Large audio frame mode operation");
        for (int inputIndex = 0; inputIndex < work->input.buffers.size(); inputIndex++) {
            std::shared_ptr<C2Buffer> &inputBuffer = work->input.buffers[inputIndex];
            if (!inputBuffer->hasInfo(C2LargeFrameMetadata::input::PARAM_TYPE)) {
                ALOGE("Error: Large audio frame requested with no large frame metadata.");
                work->result = C2_CORRUPTED;
                return;
            }
            std::shared_ptr<const C2LargeFrameMetadata::input> inBufferInfo =
                    std::static_pointer_cast<const C2LargeFrameMetadata::input>(
            work->input.buffers[inputIndex]->getInfo(C2LargeFrameMetadata::input::PARAM_TYPE));
            rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
            size_t inSize = rView.capacity();
            //size_t inputOffset = 0;
            if (inSize && rView.error()) {
                ALOGE("read view map failed %d", rView.error());
                work->result = rView.error();
                return;
            }
            int outputSize = 0;
            int metaIndex = 0;
            std::shared_ptr<C2LinearBlock> block;
            std::shared_ptr<C2WriteView> wView;
            uint8_t *outPtr = nullptr;
            auto allocateAndMap = [&pool, &block, &wView, maxOutSize](uint8_t **out) -> c2_status_t
            {
                c2_status_t err = C2_OK;
                C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
                wView.reset(); block.reset();
                err = pool->fetchLinearBlock(maxOutSize, usage, &block);
                if (err != C2_OK) {
                    ALOGV("Failed to allocate memory");
                    return err;
                }
                wView = std::make_shared<C2WriteView>(block->map().get());
                if(out){
                    *out = wView->data();
                }
                return err;
            };
            std::vector<C2LargeFrameMetadataStruct> currentBufferInfos;
            c2_status_t err = C2_OK;
            while (metaIndex < inBufferInfo->flexCount()) {
                const C2LargeFrameMetadataStruct &inputMeta = inBufferInfo->m.values[metaIndex];
                if (inputMeta.size > maxOutSize) {
                    // TODO: access-units too big for the output buffer.
                    // should this fall into too less buffer and return
                    // the access-unit with a warning ? or send an error?
                    // TODO: Telemetry: application consider reconfiguring output buffer.
                    // should this be part of config-update ?
                    work->result = C2_BAD_VALUE;
                    return;
                }
                if(!block) {
                    if (C2_OK != allocateAndMap(&outPtr)) {
                        work->result = C2_NO_MEMORY;
                        return;
                    }
                    outputSize = 0;
                    currentBufferInfos.clear();
                }
                if (outputSize + inputMeta.size > maxOutSize) {
                    std::shared_ptr<C2Buffer> buffer = createLinearBuffer(block, 0/*offset*/,
                            outputSize);
                    std::shared_ptr<C2LargeFrameMetadata::output> largeFrame =
                            C2LargeFrameMetadata::output::AllocShared(
                            currentBufferInfos.size(), 0u, currentBufferInfos);
                    if (C2_OK != (err = buffer->setInfo(largeFrame))) {
                        ALOGV("Large audio frame metadata attach failed with err: %d", err);
                    }
                    C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
                    outOrdinal.timestamp = currentBufferInfos.front().presentationTimeUs;
                    cloneAndSend(work->input.ordinal.frameIndex.peeku(), work,
                            FillWork(C2FrameData::FLAG_INCOMPLETE, outOrdinal, buffer));
                    ALOGV("Large audio frame sending size: %zu, ts: %ld", inputMeta.size,
                            inputMeta.presentationTimeUs);
                    block.reset();
                    currentBufferInfos.clear();
                    outputSize = 0;
                    continue;
                } else {
                    memcpy(outPtr + outputSize, rView.data() + inputMeta.offset,
                           inputMeta.size);
                    ALOGV("Making %zu for ts: %ld", inputMeta.size, inputMeta.presentationTimeUs);
                    currentBufferInfos.emplace_back(inputMeta.flags, inputMeta.size,
                            outputSize, inputMeta.presentationTimeUs);
                    outputSize += inputMeta.size;

                }
                if (outputSize > thresholdSize && (metaIndex != inBufferInfo->flexCount() - 1)) {
                    std::shared_ptr<C2Buffer> buffer = createLinearBuffer(block, 0/*offset*/,
                            outputSize);
                    std::shared_ptr<C2LargeFrameMetadata::output> largeFrame =
                            C2LargeFrameMetadata::output::AllocShared(
                            currentBufferInfos.size(), 0u, currentBufferInfos);
                    if (C2_OK != (err = buffer->setInfo(largeFrame))) {
                        ALOGV("Large audio frame metadata attach failed with err: %d", err);
                    }
                    C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
                    outOrdinal.timestamp = currentBufferInfos.front().presentationTimeUs;
                    cloneAndSend(work->input.ordinal.frameIndex.peeku(), work,
                            FillWork(C2FrameData::FLAG_INCOMPLETE, outOrdinal, buffer));
                    ALOGV("Large Audio frame sending size: %zu, ts: %ld", inputMeta.size,
                            inputMeta.presentationTimeUs);
                    block.reset();
                    currentBufferInfos.clear();
                    outputSize = 0;
                }
                metaIndex++;
            }
            // we have exhausted all input metadata but the last. we can send this out now.
            work->worklets.front()->output.flags = work->input.flags;
            work->worklets.front()->output.buffers.clear();
            C2WorkOrdinalStruct outOrdinal = work->input.ordinal;
            outOrdinal.timestamp = 0;
            if (outputSize > 0) {
                std::shared_ptr<C2Buffer> buffer = createLinearBuffer(block, 0/*offset*/,
                            outputSize);
                std::shared_ptr<C2LargeFrameMetadata::output> largeFrame =
                            C2LargeFrameMetadata::output::AllocShared(
                                    currentBufferInfos.size(), 0u, currentBufferInfos);
                if (C2_OK != (err = buffer->setInfo(largeFrame))) {
                    ALOGE("Large audio frame metadata attach failed with err: %d", err);
                }
                outOrdinal.timestamp = currentBufferInfos.front().presentationTimeUs;
                work->worklets.front()->output.buffers.push_back(buffer);
            }
            work->worklets.front()->output.ordinal = outOrdinal;
            ALOGV("Finishing: flag: %d size: %d for ts: %lld",
                    work->worklets.front()->output.flags, outputSize,
                    outOrdinal.timestamp.peekull());
            outputSize = 0;
            currentBufferInfos.clear();
            if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
                mSignalledEos = true;
            }
        }
    } else {
        // normal buffer mode operation;
        // raw codec cannot know if this is a multi-frame input, so
        // this will just return the provided input.
        ALOGV("RawDec processing in the normal path");
        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.ordinal = work->input.ordinal;
        work->worklets.front()->output.buffers.push_back(work->input.buffers[0]);
        if (work->input.flags & C2FrameData::FLAG_END_OF_STREAM) {
            mSignalledEos = true;
        }
    }
}

c2_status_t C2SoftRawDec::drain(
        uint32_t drainMode,
        const std::shared_ptr<C2BlockPool> &pool) {
    (void) pool;
    if (drainMode == NO_DRAIN) {
        ALOGW("drain with NO_DRAIN: no-op");
        return C2_OK;
    }
    if (drainMode == DRAIN_CHAIN) {
        ALOGW("DRAIN_CHAIN not supported");
        return C2_OMITTED;
    }

    return C2_OK;
}

class C2SoftRawDecFactory : public C2ComponentFactory {
public:
    C2SoftRawDecFactory() : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
            GetCodec2PlatformComponentStore()->getParamReflector())) {
    }

    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
                new C2SoftRawDec(COMPONENT_NAME,
                              id,
                              std::make_shared<C2SoftRawDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
                new SimpleInterface<C2SoftRawDec::IntfImpl>(
                        COMPONENT_NAME, id, std::make_shared<C2SoftRawDec::IntfImpl>(mHelper)),
                deleter);
        return C2_OK;
    }

    virtual ~C2SoftRawDecFactory() override = default;

private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table))
extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftRawDecFactory();
}

__attribute__((cfi_canonical_jump_table))
extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
