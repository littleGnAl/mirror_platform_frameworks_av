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

#define LOG_TAG "EffectHalAidl"
//#define LOG_NDEBUG 0

#include <memory>

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/AidlConversionUtil.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "EffectHalAidl.h"

#include <aidl/android/hardware/audio/effect/IEffect.h>

#include "effectsAidlConversion/AidlConversionAec.h"
#include "effectsAidlConversion/AidlConversionAgc2.h"
#include "effectsAidlConversion/AidlConversionBassBoost.h"
#include "effectsAidlConversion/AidlConversionDownmix.h"
#include "effectsAidlConversion/AidlConversionDynamicsProcessing.h"
#include "effectsAidlConversion/AidlConversionEnvReverb.h"
#include "effectsAidlConversion/AidlConversionEq.h"
#include "effectsAidlConversion/AidlConversionHapticGenerator.h"
#include "effectsAidlConversion/AidlConversionLoudnessEnhancer.h"
#include "effectsAidlConversion/AidlConversionNoiseSuppression.h"
#include "effectsAidlConversion/AidlConversionPresetReverb.h"
#include "effectsAidlConversion/AidlConversionSpatializer.h"
#include "effectsAidlConversion/AidlConversionVendorExtension.h"
#include "effectsAidlConversion/AidlConversionVirtualizer.h"
#include "effectsAidlConversion/AidlConversionVisualizer.h"

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::IFactory;
using ::aidl::android::hardware::audio::effect::Parameter;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(
        const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory>& factory,
        const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>& effect,
        uint64_t effectId, int32_t sessionId, int32_t ioId,
        const ::aidl::android::hardware::audio::effect::Descriptor& desc)
    : mFactory(factory),
      mEffect(effect),
      mEffectId(effectId),
      mSessionId(sessionId),
      mIoId(ioId),
      mDesc(desc) {
    createAidlConversion(effect, sessionId, ioId, desc);
}

EffectHalAidl::~EffectHalAidl() {
    if (mFactory) {
        mFactory->destroyEffect(mEffect);
    }
}

status_t EffectHalAidl::createAidlConversion(
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
        int32_t sessionId, int32_t ioId,
        const ::aidl::android::hardware::audio::effect::Descriptor& desc) {
    const auto& typeUuid = desc.common.id.type;
    ALOGI("%s create UUID %s", __func__, typeUuid.toString().c_str());
    if (typeUuid == kAcousticEchoCancelerTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionAec>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kAutomaticGainControl2TypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionAgc2>(effect, sessionId, ioId,
                                                                            desc);
    } else if (typeUuid == kBassBoostTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionBassBoost>(effect, sessionId,
                                                                                 ioId, desc);
    } else if (typeUuid == kDownmixTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionDownmix>(effect, sessionId,
                                                                               ioId, desc);
    } else if (typeUuid == kDynamicsProcessingTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionDp>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kEnvReverbTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionEnvReverb>(effect, sessionId,
                                                                                 ioId, desc);
    } else if (typeUuid == kEqualizerTypeUUID) {
        mConversion =
                std::make_unique<android::effect::AidlConversionEq>(effect, sessionId, ioId, desc);
    } else if (typeUuid == kHapticGeneratorTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionHapticGenerator>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kLoudnessEnhancerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionLoudnessEnhancer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kNoiseSuppressionTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionNoiseSuppression>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kPresetReverbTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionPresetReverb>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kSpatializerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionSpatializer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kVirtualizerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionVirtualizer>(
                effect, sessionId, ioId, desc);
    } else if (typeUuid == kVisualizerTypeUUID) {
        mConversion = std::make_unique<android::effect::AidlConversionVisualizer>(effect, sessionId,
                                                                                  ioId, desc);
    } else {
        // For unknown UUID, use vendor extension implementation
        mConversion = std::make_unique<android::effect::AidlConversionVendorExtension>(
                effect, sessionId, ioId, desc);
    }
    return OK;
}

status_t EffectHalAidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    mInBuffer = buffer;
    return OK;
}

status_t EffectHalAidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    mOutBuffer = buffer;
    return OK;
}


// write to input FMQ here, wait for statusMQ STATUS_OK, and read from output FMQ
status_t EffectHalAidl::process() {
    ALOGW("%s not implemented yet", __func__);
    const auto& retParam = mConversion->getEffectReturnParam();
    std::unique_ptr<StatusMQ> statusQ(std::make_unique<StatusMQ>(retParam.statusMQ));
    std::unique_ptr<DataMQ> inputQ(std::make_unique<DataMQ>(retParam.inputDataMQ));
    std::unique_ptr<DataMQ> outputQ(std::make_unique<DataMQ>(retParam.outputDataMQ));
    if (!statusQ->isValid() || !inputQ->isValid() || !outputQ->isValid()) {
        ALOGE("%s return with invalid FMQ", __func__);
        return BAD_VALUE;
    }

    size_t available = inputQ->availableToWrite();
    size_t numFloatR = std::min(available, mInBuffer->getSize() / sizeof(float));
    if (numFloatR == 0) {
        ALOGW("%s not able to write, floats in buffer %zu, avail %zu", __func__,
              mInBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    if (!inputQ->writeBlocking((float*)mInBuffer->ptr(), numFloatR)) {
        ALOGW("%s failed to write %zu into inputQ", __func__, numFloatR);
        return FAILED_TRANSACTION;
    }

    IEffect::Status retStatus{};
    if (!statusQ->readBlocking(&retStatus, 1) || retStatus.status != OK) {
        ALOGW("%s read status %d failed", __func__, retStatus.status);
        return FAILED_TRANSACTION;
    }

    available = outputQ->availableToWrite();
    size_t numFloatW = std::min(available, mOutBuffer->getSize() / sizeof(float));
    if (numFloatW == 0) {
        ALOGW("%s not able to read, buffer size %zu, available %zu", __func__,
              mOutBuffer->getSize() / sizeof(float), available);
        return INVALID_OPERATION;
    }
    if (!outputQ->readBlocking((float*)mOutBuffer->ptr(), numFloatW)) {
        ALOGW("%s failed to read %zu from outputQ", __func__, numFloatW);
        return FAILED_TRANSACTION;
    }

    ALOGD("%s %s consumed %zu produced %zu", __func__, mDesc.common.name.c_str(), numFloatR,
          numFloatW);
    return OK;
}

// TODO: no one using, maybe deprecate this interface
status_t EffectHalAidl::processReverse() {
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::command(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                uint32_t* replySize, void* pReplyData) {
    TIME_CHECK();
    return mConversion
                   ? mConversion->handleCommand(cmdCode, cmdSize, pCmdData, replySize, pReplyData)
                   : INVALID_OPERATION;
}

status_t EffectHalAidl::getDescriptor(effect_descriptor_t* pDescriptor) {
    TIME_CHECK();
    if (pDescriptor == nullptr) {
        ALOGE("%s null descriptor pointer", __func__);
        return BAD_VALUE;
    }
    Descriptor aidlDesc;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getDescriptor(&aidlDesc)));

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(aidlDesc));
    return OK;
}

status_t EffectHalAidl::close() {
    TIME_CHECK();
    return statusTFromBinderStatus(mEffect->close());
}

status_t EffectHalAidl::dump(int fd) {
    ALOGD("%s dump %s with fd %d", __func__, mDesc.common.name.c_str(), fd);
    return mEffect->dump(fd, nullptr, 0);
}

} // namespace effect
} // namespace android
