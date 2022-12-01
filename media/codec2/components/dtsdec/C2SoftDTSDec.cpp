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
#define LOG_TAG "C2SoftDTSDec"
#include <log/log.h>

#include <numeric>
#include <dlfcn.h>

#include <media/stagefright/foundation/MediaDefs.h>

#include <C2PlatformSupport.h>
#include <SimpleC2Interface.h>

#include "C2SoftDTSDec.h"

#define DTS_DEC_MAX_FRAME_DURATION           4096
#define DTS_DEC_DRC_DEFAULT_REF_LEVEL        -24
#define DTS_DEC_DEFAULT_CHANNEL_COUNT        6   // 5.1(C, L, R, Ls, Rs, LFE)
#define DTS_DRC_MODE_LOW                     0
#define DTS_DRC_MODE_MEDIUM                  1
#define DTS_DRC_MODE_HIGH                    2

namespace android {

namespace {

constexpr char COMPONENT_NAME[] = "c2.DTS.audio_decoder.dts";

}  // namespace

class C2SoftDTSDec::IntfImpl : public SimpleInterface<void>::BaseParams {
public:
    explicit IntfImpl(const std::shared_ptr<C2ReflectorHelper> &helper)
        : SimpleInterface<void>::BaseParams(
                helper,
                COMPONENT_NAME,
                C2Component::KIND_DECODER,
                C2Component::DOMAIN_AUDIO,
                MEDIA_MIMETYPE_AUDIO_DTS) {
        noPrivateBuffers();
        noInputReferences();
        noOutputReferences();
        noInputLatency();
        noTimeStretch();

        addParameter(
                DefineParam(mAttrib, C2_PARAMKEY_COMPONENT_ATTRIBUTES)
                .withConstValue(new C2ComponentAttributesSetting(
                    C2Component::ATTRIB_IS_TEMPORAL))
                .build());

        addParameter(
                DefineParam(mSampleRate, C2_PARAMKEY_SAMPLE_RATE)
                .withDefault(new C2StreamSampleRateInfo::output(0u, 44100))
                .withFields({C2F(mSampleRate, value).inRange(8000, 192000)})
                .withSetter((Setter<decltype(*mSampleRate)>::StrictValueWithNoDeps))
                .build());

        addParameter(
                DefineParam(mChannelCount, C2_PARAMKEY_CHANNEL_COUNT)
                .withDefault(new C2StreamChannelCountInfo::output(0u,
                    DTS_DEC_DEFAULT_CHANNEL_COUNT))
                .withFields({C2F(mChannelCount, value).inRange(1, DTS_DEC_MAX_CHANNELS)})
                .withSetter(Setter<decltype(*mChannelCount)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mInputMaxBufSize, C2_PARAMKEY_INPUT_MAX_BUFFER_SIZE)
                .withConstValue(new C2StreamMaxBufferSizeInfo::input(0u, 8192))
                .build());

        addParameter(
                DefineParam(mDrcCompressMode, C2_PARAMKEY_DRC_COMPRESSION_MODE)
                .withDefault(new C2StreamDrcCompressionModeTuning::input(0u,
                    C2Config::DRC_COMPRESSION_MEDIUM))
                .withFields({
                    C2F(mDrcCompressMode, value).oneOf({
                            C2Config::DRC_COMPRESSION_ODM_DEFAULT,
                            C2Config::DRC_COMPRESSION_NONE,
                            C2Config::DRC_COMPRESSION_LIGHT,
                            C2Config::DRC_COMPRESSION_HEAVY,
                            C2Config::DRC_COMPRESSION_MEDIUM})
                })
                .withSetter(Setter<decltype(*mDrcCompressMode)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mDrcEffectType, C2_PARAMKEY_DTS_DRC_EFFECT_TYPE)
                .withDefault(new C2StreamDtsDrcEffectTypeTuning::input(0u,
                    C2Config::DTS_DRC_EFFECT_UHD_MEDIUM_DRC_SYMMETRICAL))
                .withFields({
                    C2F(mDrcEffectType, value).oneOf({
                            C2Config::DTS_DRC_EFFECT_NO_COMPRESSION,
                            C2Config::DTS_DRC_EFFECT_LEGACY_FILM_STANDARD,
                            C2Config::DTS_DRC_EFFECT_LEGACY_FILM_LIGHT,
                            C2Config::DTS_DRC_EFFECT_LEGACY_MUSIC_STANDARD,
                            C2Config::DTS_DRC_EFFECT_LEGACY_MUSIC_LIGHT,
                            C2Config::DTS_DRC_EFFECT_LEGACY_SPEECH,
                            C2Config::DTS_DRC_EFFECT_UHD_LOW_DRC_LESS_ATTENUATION,
                            C2Config::DTS_DRC_EFFECT_UHD_LOW_DRC_LESS_BOOST,
                            C2Config::DTS_DRC_EFFECT_UHD_LOW_DRC_SYMMETRICAL,
                            C2Config::DTS_DRC_EFFECT_UHD_MEDIUM_DRC_LESS_ATTENUATION,
                            C2Config::DTS_DRC_EFFECT_UHD_MEDIUM_DRC_LESS_BOOST,
                            C2Config::DTS_DRC_EFFECT_UHD_MEDIUM_DRC_SYMMETRICAL,
                            C2Config::DTS_DRC_EFFECT_UHD_HIGH_DRC_LESS_ATTENUATION,
                            C2Config::DTS_DRC_EFFECT_UHD_HIGH_DRC_LESS_BOOST,
                            C2Config::DTS_DRC_EFFECT_UHD_HIGH_DRC_SYMMETRICAL})
                })
                .withSetter(Setter<decltype(*mDrcEffectType)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mDrcBoostFactor, C2_PARAMKEY_DRC_BOOST_FACTOR)
                .withDefault(new C2StreamDrcBoostFactorTuning::input(0u, 100))
                .withFields({C2F(mDrcBoostFactor, value).inRange(0, 100)})
                .withSetter(Setter<decltype(*mDrcBoostFactor)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mDrcAttenuationFactor, C2_PARAMKEY_DRC_ATTENUATION_FACTOR)
                .withDefault(new C2StreamDrcAttenuationFactorTuning::input(0u, 100))
                .withFields({C2F(mDrcAttenuationFactor, value).inRange(0, 100)})
                .withSetter(Setter<decltype(*mDrcAttenuationFactor)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mLoudnessNormStatus, C2_PARAMKEY_DTS_DRC_LOUDNESS_NORM_STATUS)
                .withDefault(new C2StreamDtsDrcLoudnessNormStatusTuning::input(0u,
                    C2Config::DTS_DRC_LOUDNESS_NORM_ON))
                .withFields({C2F(mLoudnessNormStatus, value).oneOf({
                    C2Config::DTS_DRC_LOUDNESS_NORM_OFF,
                    C2Config::DTS_DRC_LOUDNESS_NORM_ON})
                })
                .withSetter(Setter<decltype(*mLoudnessNormStatus)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mDrcTargetRefLevel, C2_PARAMKEY_DRC_TARGET_REFERENCE_LEVEL)
                .withDefault(new C2StreamDrcTargetReferenceLevelTuning::input(0u,
                    DTS_DEC_DRC_DEFAULT_REF_LEVEL))
                .withFields({C2F(mDrcTargetRefLevel, value).inRange(-60, -10)})
                .withSetter(Setter<decltype(*mDrcTargetRefLevel)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mLimiterType, C2_PARAMKEY_DTS_LIMITER_TYPE)
                .withDefault(new C2StreamDtsLimiterTypeTuning::input(0u,
                    C2Config::DTS_HYBRID_LIMITER_UN_LINKED))
                .withFields({C2F(mLimiterType, value).oneOf({
                    C2Config::DTS_HYBRID_LIMITER_UN_LINKED,
                    C2Config::DTS_HYBRID_LIMITER_LINKED,
                    C2Config::DTS_HARD_LIMITER_EXCEPT_LFE_CHANNEL,
                    C2Config::DTS_HARD_LIMITER_ALL_CHANNEL})
                })
                .withSetter(Setter<decltype(*mLimiterType)>::StrictValueWithNoDeps)
                .build());

        addParameter(
                DefineParam(mSpkrOutputMask, C2_PARAMKEY_DTS_OUTPUT_LAYOUT_MASK)
                .withDefault(new C2StreamDtsOutputLayoutTuning::input(0u,
                    C2Config::DTS_SPEAKER_LAYOUT_5P1))
                .withFields({C2F(mSpkrOutputMask, value).oneOf({
                    C2Config::DTS_SPEAKER_LAYOUT_STEREO,
                    C2Config::DTS_SPEAKER_LAYOUT_2P1,
                    C2Config::DTS_SPEAKER_LAYOUT_2P0P2,
                    C2Config::DTS_SPEAKER_LAYOUT_2P1P2,
                    C2Config::DTS_SPEAKER_LAYOUT_5P1,
                    C2Config::DTS_SPEAKER_LAYOUT_5P1P2,
                    C2Config::DTS_SPEAKER_LAYOUT_5P1P4,
                    C2Config::DTS_SPEAKER_LAYOUT_3P0,
                    C2Config::DTS_SPEAKER_LAYOUT_3P1,
                    C2Config::DTS_SPEAKER_LAYOUT_3P0P2,
                    C2Config::DTS_SPEAKER_LAYOUT_3P1P2,
                    C2Config::DTS_SPEAKER_LAYOUT_5P0,
                    C2Config::DTS_SPEAKER_LAYOUT_5P0P2,
                    C2Config::DTS_SPEAKER_LAYOUT_5P0P4,
                    C2Config::DTS_SPEAKER_LAYOUT_7P0,
                    C2Config::DTS_SPEAKER_LAYOUT_7P1,
                    C2Config::DTS_SPEAKER_LAYOUT_7P0P2,
                    C2Config::DTS_SPEAKER_LAYOUT_7P1P2,
                    C2Config::DTS_SPEAKER_LAYOUT_7P0P4,
                    C2Config::DTS_SPEAKER_LAYOUT_7P1P4})
                })
                .withSetter(Setter<decltype(*mSpkrOutputMask)>::StrictValueWithNoDeps)
                .build());
    }

    int32_t getDrcEnableFlag() const {
        return mDrcCompressMode->value == C2Config::DRC_COMPRESSION_NONE ? 0 : 1; }
    int32_t getDrcCompressMode() const {
        int32_t dtsDRCMode;
        switch(mDrcCompressMode->value) {
            case C2Config::DRC_COMPRESSION_LIGHT:
                dtsDRCMode = DTS_DRC_MODE_LOW; break;
            case C2Config::DRC_COMPRESSION_MEDIUM:
                dtsDRCMode = DTS_DRC_MODE_MEDIUM; break;
            case C2Config::DRC_COMPRESSION_HEAVY:
                dtsDRCMode = DTS_DRC_MODE_HIGH; break;
            default:
                dtsDRCMode = DTS_DRC_MODE_MEDIUM; break;
        }
        return dtsDRCMode;
    }
    int32_t getDrcTargetRefLevel() const { return ( mDrcTargetRefLevel->value * 100); }
    int32_t getDrcBoostFactor() const { return mDrcBoostFactor->value; }
    int32_t getDrcAttenuationFactor() const { return mDrcAttenuationFactor->value; }
    int32_t getDrcEffectType() const { return mDrcEffectType->value; }
    uint32_t getLimiterType() const { return mLimiterType->value; }
    uint32_t getLoudnessNormStatus() const { return mLoudnessNormStatus->value; }
    uint32_t getOutputLayoutMask() const { return mSpkrOutputMask->value; }

private:
    std::shared_ptr<C2StreamSampleRateInfo::output> mSampleRate;
    std::shared_ptr<C2StreamChannelCountInfo::output> mChannelCount;
    std::shared_ptr<C2StreamDtsOutputLayoutTuning::input> mSpkrOutputMask;
    std::shared_ptr<C2StreamMaxBufferSizeInfo::input> mInputMaxBufSize;
    std::shared_ptr<C2StreamDrcCompressionModeTuning::input> mDrcCompressMode;
    std::shared_ptr<C2StreamDtsDrcEffectTypeTuning::input> mDrcEffectType;
    std::shared_ptr<C2StreamDrcBoostFactorTuning::input> mDrcBoostFactor;
    std::shared_ptr<C2StreamDrcAttenuationFactorTuning::input> mDrcAttenuationFactor;
    std::shared_ptr<C2StreamDtsDrcLoudnessNormStatusTuning::input> mLoudnessNormStatus;
    std::shared_ptr<C2StreamDrcTargetReferenceLevelTuning::input> mDrcTargetRefLevel;
    std::shared_ptr<C2StreamDtsLimiterTypeTuning::input> mLimiterType;
};

C2SoftDTSDec::C2SoftDTSDec(const char *name, c2_node_id_t id,
                     const std::shared_ptr<IntfImpl> &intfImpl)
    : SimpleC2Component(std::make_shared<SimpleInterface<IntfImpl>>(name, id, intfImpl)),
      mIntf(intfImpl),
      dtsDecHandle(nullptr),
      dtsInBuffer(nullptr),
      dtsOutBuffer(nullptr),
      dtsConfigParam(nullptr),
      dtsAPIs(nullptr),
      mC2LibHandle(nullptr),
      samplingRate(0),
      numChannels(0) {
}

C2SoftDTSDec::~C2SoftDTSDec() {
    onRelease();
}

c2_status_t C2SoftDTSDec::onInit() {
    status_t err = initDecoder();
    return err == OK ? C2_OK : C2_NO_MEMORY;
}

c2_status_t C2SoftDTSDec::onStop() {
    dtsDecResult dtsError = DTS_DEC_ERROR_OK;
    status_t err = OK;

    ALOGV("onStop()");
    dtsError = dtsAPIs->DTS_Dec_DeInitialize(dtsDecHandle);
    if(dtsError != DTS_DEC_ERROR_OK){
        ALOGE("DTS_Dec_DeInitialize() failed with error %d", dtsError);
        return C2_NO_INIT;
    }

    err = initDecoder();
    return err == OK ? C2_OK : C2_NO_INIT;
}

void C2SoftDTSDec::onReset() {
    ALOGV("onReset()");
    (void)onStop();
}

void C2SoftDTSDec::onRelease() {
    ALOGV("onRelease()");
    dtsAPIs->DTS_Dec_DeInitialize(dtsDecHandle);

    if(dtsDecHandle){
        free(dtsDecHandle);
        dtsDecHandle = NULL;
    }
    if(dtsAPIs) {
        delete dtsAPIs;
        dtsAPIs = NULL;
    }
    if(dtsInBuffer) {
        delete dtsInBuffer;
        dtsInBuffer = NULL;
    }
    if(dtsOutBuffer) {
        delete dtsOutBuffer;
        dtsOutBuffer = NULL;
    }
    if(dtsConfigParam) {
        delete dtsConfigParam;
        dtsConfigParam = NULL;
    }
}

status_t C2SoftDTSDec::initDecoder() {
    const char *error;
    dtsDecResult dtsError = DTS_DEC_ERROR_OK;
    int32_t dtsDecInstSize = 0;

    ALOGV("initDecoder()");
    dtsAPIs = new dtsC2WrapperAPIs{};
    dtsInBuffer = new dtsC2InputBufferConfig{};
    dtsOutBuffer = new dtsC2OutputBufferConfig{};
    dtsConfigParam = new dtsC2ConfigParam{};

    mC2LibHandle = dlopen(DTS_DEC_LIB, RTLD_LAZY);
    if (mC2LibHandle) {
        dtsAPIs->DTS_Dec_GetSizeOf = (int (*)())(dlsym(mC2LibHandle, "DTS_Dec_GetSizeOf"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_GetSizeOf', error (%s)", error);
            return  C2_NOT_FOUND;
        }
        dtsAPIs->DTS_Dec_Initialize = (dtsDecResult (*)(dtsHandleType))
                                      (dlsym(mC2LibHandle, "DTS_Dec_Initialize"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_Initialize', error (%s)", error);
            return  C2_NOT_FOUND;
        }
        dtsAPIs->DTS_Dec_DeInitialize = (dtsDecResult (*)(dtsHandleType))
                                      (dlsym(mC2LibHandle, "DTS_Dec_DeInitialize"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_DeInitialize', error (%s)", error);
            return  C2_NOT_FOUND;
        }
        dtsAPIs->DTS_Dec_DecodeFrame = (dtsDecResult (*)(dtsHandleType, dtsC2InputBufferConfig *,
                          dtsC2OutputBufferConfig *)) (dlsym(mC2LibHandle, "DTS_Dec_DecodeFrame"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_DecodeFrame', error (%s)", error);
            return  C2_NOT_FOUND;
        }
        dtsAPIs->DTS_Dec_GetParam = (dtsDecResult (*)(dtsHandleType, dtsC2ConfigParam *))
                                    (dlsym(mC2LibHandle, "DTS_Dec_GetParam"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_GetParam', error (%s)", error);
            return  C2_NOT_FOUND;
        }
        dtsAPIs->DTS_Dec_SetParam = (dtsDecResult (*)(dtsHandleType, dtsC2ConfigParam *))
                                    (dlsym(mC2LibHandle, "DTS_Dec_SetParam"));
        if ((error = dlerror()) != NULL) {
            ALOGE("Failed to dlsym 'DTS_Dec_SetParam', error (%s)", error);
            return  C2_NOT_FOUND;
        }
    }
    else {
        ALOGE("dlopen of %s failed, error (%s)", DTS_DEC_LIB, dlerror());
    }

    dtsDecInstSize = dtsAPIs->DTS_Dec_GetSizeOf();
    dtsDecHandle = malloc( dtsDecInstSize );
    if(dtsDecHandle == NULL){
        ALOGE("Memory allocation failed");
        return NO_MEMORY;
    }

    dtsError = dtsAPIs->DTS_Dec_Initialize( dtsDecHandle);
    if(dtsError != DTS_DEC_ERROR_OK){
        ALOGE("DTS_Dec_Initialize failed with error %d", dtsError);
        return NO_INIT;
    }

    //Get the default configuration from the decoder
    dtsError = dtsAPIs->DTS_Dec_GetParam(dtsDecHandle, dtsConfigParam);
    if(dtsError != DTS_DEC_ERROR_OK){
        ALOGE("DTS_Dec_GetParam failed with error %d", dtsError);
        return BAD_VALUE ;
    }

    return OK ;
}

//TO DO: Parse the incoming bitstream and find the actual frame duration.
static status_t calculateOutSize(uint8_t *header, size_t inSize,
                                 std::vector<size_t> *decodedSizes) {
    (void)header; //Unused
    (void)inSize; //Unused
    decodedSizes->push_back(DTS_DEC_MAX_FRAME_DURATION * DTS_DEC_MAX_CHANNELS * sizeof(int16_t));
    if (decodedSizes->empty()) return UNKNOWN_ERROR;

    return OK;
}

c2_status_t C2SoftDTSDec::onFlush_sm() {
    return onStop();
}

c2_status_t C2SoftDTSDec::drain(
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

static void fillEmptyWork(const std::unique_ptr<C2Work> &work) {
    work->worklets.front()->output.flags = work->input.flags;
    work->worklets.front()->output.buffers.clear();
    work->worklets.front()->output.ordinal = work->input.ordinal;
    work->workletsProcessed = 1u;
}

void C2SoftDTSDec::process(
        const std::unique_ptr<C2Work> &work,
        const std::shared_ptr<C2BlockPool> &pool) {

    dtsDecResult dtsError;
    // Initialize output work
    work->result = C2_OK;
    work->workletsProcessed = 1u;
    work->worklets.front()->output.configUpdate.clear();
    work->worklets.front()->output.flags = work->input.flags;

    if (mSignalledError || mSignalledOutputEos) {
        work->result = C2_BAD_VALUE;
        return;
    }

    bool eos = ((work->input.flags & C2FrameData::FLAG_END_OF_STREAM) != 0);
    size_t inSize = 0u;
    size_t offset = 0u;
    C2ReadView rView = mDummyReadView;
    if (!work->input.buffers.empty()) {
        rView = work->input.buffers[0]->data().linearBlocks().front().map().get();
        inSize = rView.capacity();
        if (inSize && rView.error()) {
            ALOGE("read view map failed %d", rView.error());
            work->result = rView.error();
            return;
        }

        dtsInBuffer->pBuffer        =   const_cast<uint8_t *>(rView.data());
        dtsInBuffer->nFrameSize     =   inSize;
        dtsInBuffer->nOffset        =   offset;
    }

    if (inSize == 0 && (!eos)) {
        work->worklets.front()->output.flags = work->input.flags;
        work->worklets.front()->output.buffers.clear();
        work->worklets.front()->output.ordinal = work->input.ordinal;
        return;
    }
    ALOGV("in buffer attr. size %zu timestamp %d frameindex %d", inSize,
          (int)work->input.ordinal.timestamp.peeku(), (int)work->input.ordinal.frameIndex.peeku());

    size_t calOutSize = 0;
    std::vector<size_t> decodedSizes;
    if (inSize && OK != calculateOutSize(dtsInBuffer->pBuffer, inSize, &decodedSizes)) {
        work->result = C2_CORRUPTED;
        return;
    }
    calOutSize = std::accumulate(decodedSizes.begin(), decodedSizes.end(), 0);

    std::shared_ptr<C2LinearBlock> block;
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    c2_status_t err = pool->fetchLinearBlock(calOutSize, usage, &block);
    if (err != C2_OK) {
        ALOGE("fetchLinearBlock for Output failed with status %d", err);
        work->result = C2_NO_MEMORY;
        return;
    }
    C2WriteView wView = block->map().get();
    if (wView.error()) {
        ALOGE("write view map failed %d", wView.error());
        work->result = wView.error();
        return;
    }

    dtsConfigParam->nSpkrOut = mIntf->getOutputLayoutMask();
    dtsConfigParam->bLoudnessNormEnable = mIntf->getLoudnessNormStatus();
    dtsConfigParam->nLoundnessNormTarget = mIntf->getDrcTargetRefLevel();
    dtsConfigParam->bDRCEnable = mIntf->getDrcEnableFlag();
    dtsConfigParam->nDRCMode = mIntf->getDrcCompressMode();
    dtsConfigParam->nLowDRCTypeCurveSelect = mIntf->getDrcEffectType();
    dtsConfigParam->nMediumDRCTypeCurveSelect = mIntf->getDrcEffectType();
    dtsConfigParam->nHighDRCTypeCurveSelect = mIntf->getDrcEffectType();
    dtsConfigParam->nDRCBoostPercent = mIntf->getDrcBoostFactor();
    dtsConfigParam->nDRCAttenPercent = mIntf->getDrcAttenuationFactor();
    dtsConfigParam->nLimiterType = mIntf->getLimiterType();

    //Set any configuration update to the decoder instance.
    dtsAPIs->DTS_Dec_SetParam(dtsDecHandle, dtsConfigParam);

    dtsOutBuffer->pBuffer = (wView.data());
    dtsOutBuffer->nFrameSize = 0;
    dtsOutBuffer->nOffset = 0;
    dtsOutBuffer->nAllocSize = calOutSize;

    //TO DO: Need to handle the cases where the input buffer has more than one DTS frame
    while(dtsInBuffer->nFrameSize != 0) {
        if ((dtsError = dtsAPIs->DTS_Dec_DecodeFrame(dtsDecHandle, dtsInBuffer, dtsOutBuffer))
                != DTS_DEC_ERROR_OK) {
            ALOGE("DTS decoder returned error %d", dtsError);
            mSignalledError = true;
            work->result = C2_CORRUPTED;
            return;
        }

        if (dtsOutBuffer->nFrameSize > 0) {
            dtsC2WrapperInstance *dtsWrapperInst = (dtsC2WrapperInstance *)dtsDecHandle;
            if (dtsWrapperInst->pOutputInfo->nSamplingRate != samplingRate
                || dtsWrapperInst->pOutputInfo->nChannels != numChannels) {
                ALOGI("Reconfiguring decoder: %d->%d Hz, %d->%d channels",
                    samplingRate, dtsWrapperInst->pOutputInfo->nSamplingRate,
                    numChannels, dtsWrapperInst->pOutputInfo->nChannels);
                samplingRate = dtsWrapperInst->pOutputInfo->nSamplingRate;
                numChannels = dtsWrapperInst->pOutputInfo->nChannels;

                C2StreamSampleRateInfo::output sampleRateInfo(0u, samplingRate);
                C2StreamChannelCountInfo::output channelCountInfo(0u, numChannels);
                std::vector<std::unique_ptr<C2SettingResult>> failures;
                c2_status_t err = mIntf->config(
                        { &sampleRateInfo, &channelCountInfo },
                        C2_MAY_BLOCK,
                        &failures);
                if (err == OK) {
                    work->worklets.front()->output.configUpdate.push_back(
                        C2Param::Copy(sampleRateInfo));
                    work->worklets.front()->output.configUpdate.push_back(
                        C2Param::Copy(channelCountInfo));
                } else {
                    ALOGE("Config Update failed");
                    mSignalledError = true;
                    work->result = C2_CORRUPTED;
                    return;
                }
            }
        }
    }

    fillEmptyWork(work);
    if (samplingRate && numChannels) {
        int outOffset = dtsOutBuffer->nOffset;
        int outSize = dtsOutBuffer->nFrameSize;
        decodedSizes.clear();
        work->worklets.front()->output.buffers.push_back(
                createLinearBuffer(block, outOffset, outSize - outOffset));
    }
    if (eos) {
        mSignalledOutputEos = true;
        ALOGV("signalled EOS");
    }
}

class C2SoftDTSDecFactory : public C2ComponentFactory {
public:
    C2SoftDTSDecFactory() : mHelper(std::static_pointer_cast<C2ReflectorHelper>(
            GetCodec2PlatformComponentStore()->getParamReflector())) {
    }

    virtual c2_status_t createComponent(
            c2_node_id_t id,
            std::shared_ptr<C2Component>* const component,
            std::function<void(C2Component*)> deleter) override {
        *component = std::shared_ptr<C2Component>(
              new C2SoftDTSDec(COMPONENT_NAME,
                            id,
                            std::make_shared<C2SoftDTSDec::IntfImpl>(mHelper)),
              deleter);
        return C2_OK;
    }

    virtual c2_status_t createInterface(
            c2_node_id_t id,
            std::shared_ptr<C2ComponentInterface>* const interface,
            std::function<void(C2ComponentInterface*)> deleter) override {
        *interface = std::shared_ptr<C2ComponentInterface>(
              new SimpleInterface<C2SoftDTSDec::IntfImpl>(
                      COMPONENT_NAME, id, std::make_shared<C2SoftDTSDec::IntfImpl>(mHelper)),
              deleter);
        return C2_OK;
    }

    virtual ~C2SoftDTSDecFactory() override = default;

private:
    std::shared_ptr<C2ReflectorHelper> mHelper;
};

}  // namespace android

__attribute__((cfi_canonical_jump_table))
extern "C" ::C2ComponentFactory* CreateCodec2Factory() {
    ALOGV("in %s", __func__);
    return new ::android::C2SoftDTSDecFactory();
}

__attribute__((cfi_canonical_jump_table))
extern "C" void DestroyCodec2Factory(::C2ComponentFactory* factory) {
    ALOGV("in %s", __func__);
    delete factory;
}
