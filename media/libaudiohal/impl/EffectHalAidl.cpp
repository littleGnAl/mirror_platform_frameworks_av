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

#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/audiohal/AudioHalUtils.h>
#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_spatializer.h>
#include <system/audio_effects/effect_visualizer.h>

#include "EffectHalAidl.h"

#include <system/audio.h>
#include <aidl/android/hardware/audio/effect/IEffect.h>

using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::media::audio::common::AudioUuid;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(const std::shared_ptr<IEffect>& effect, uint64_t effectId,
                             int32_t sessionId, int32_t ioId, const Descriptor& desc)
    : EffectConversionHelperAidl(effect, sessionId, ioId, desc.common.id.type),
      mEffectId(effectId),
      mSessionId(sessionId),
      mIoId(ioId),
      mEffect(effect),
      mDesc(desc) {}

EffectHalAidl::~EffectHalAidl() {}

status_t EffectHalAidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGW("%s not implemented yet", __func__);
    return OK;
}

status_t EffectHalAidl::process() {
    ALOGW("%s not implemented yet", __func__);
    // write to input FMQ here?
    return OK;
}

// TODO: no one using, maybe deprecate this interface
status_t EffectHalAidl::processReverse() {
    ALOGW("%s not implemented yet", __func__);
    return OK;
}
#if 0

status_t EffectHalAidl::handleSetParameter(uint32_t cmdSize, void* pCmdData, uint32_t* replySize,
                                           void* pReplyData) {
    ALOGW("%s not implemented yet", __func__);
    if (*replySize != sizeof(effect_param_t)) {
        ALOGE("%s parameter replySize error %d", __func__, *replySize);
        return BAD_VALUE;
    }
    return OK;
}
#endif
status_t EffectHalAidl::command(uint32_t cmdCode, uint32_t cmdSize, void* pCmdData,
                                uint32_t* replySize, void* pReplyData) {
    if (pCmdData == NULL || cmdSize == 0 || replySize == NULL || pReplyData == NULL) {
        ALOGE("%s parameter error %d %d %p %p", __func__, cmdCode, cmdSize, replySize, pReplyData);
        return BAD_VALUE;
    }
    ::ndk::ScopedAStatus status;
    switch (cmdCode) {
        case EFFECT_CMD_INIT: {
            // open with default effect_config_t (convert to Parameter.Common)
            IEffect::OpenEffectReturn ret;
            Parameter::Common common;
            RETURN_IF_BINDER_FAIL(mEffect->open(common, std::nullopt, &ret));
            return OK;
        }
        case EFFECT_CMD_SET_CONFIG_REVERSE:
            return OK; // handleSetConfig(cmdSize, pCmdData, replySize, pReplyData, true /* reverse */);
        case EFFECT_CMD_SET_CONFIG:
            return OK; // handleSetConfig(cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_GET_CONFIG_REVERSE:
            return OK; // handleGetConfig(cmdSize, pCmdData, replySize, pReplyData, true /* reverse */);
        case EFFECT_CMD_GET_CONFIG:
            return OK; // handleGetConfig(cmdSize, pCmdData, replySize, pReplyData);
        case EFFECT_CMD_RESET:
            return OK; // mEffect->command(CommandId::RESET).getStatus();
        case EFFECT_CMD_ENABLE:
            return OK; // mEffect->command(CommandId::START).getStatus();
        case EFFECT_CMD_DISABLE:
            return OK; // mEffect->command(CommandId::STOP).getStatus();
        case EFFECT_CMD_SET_PARAM_DEFERRED:
            FALLTHROUGH_INTENDED;
        case EFFECT_CMD_SET_PARAM_COMMIT:
            FALLTHROUGH_INTENDED;
        case EFFECT_CMD_SET_PARAM:
            return OK;
        case EFFECT_CMD_GET_PARAM:
            return OK;
        case EFFECT_CMD_SET_DEVICE:
            return OK;
        case EFFECT_CMD_SET_VOLUME:
            return OK;
        case EFFECT_CMD_SET_AUDIO_MODE:
            return OK;
        case EFFECT_CMD_SET_INPUT_DEVICE:
            return OK;
        case EFFECT_CMD_GET_FEATURE_SUPPORTED_CONFIGS:
            return OK;
        case EFFECT_CMD_GET_FEATURE_CONFIG:
            return OK;
        case EFFECT_CMD_SET_FEATURE_CONFIG:
            return OK;
        case EFFECT_CMD_SET_AUDIO_SOURCE:
            return OK;
        case EFFECT_CMD_OFFLOAD:
            return OK;
        case EFFECT_CMD_DUMP:
            return OK;
        case EFFECT_CMD_FIRST_PROPRIETARY:
            return OK;
        default:
            return INVALID_OPERATION;
    }
}

status_t EffectHalAidl::getDescriptor(effect_descriptor_t* pDescriptor) {
    ALOGW("%s %p", __func__, pDescriptor);
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    Descriptor aidlDesc;
    RETURN_IF_BINDER_FAIL(mEffect->getDescriptor(&aidlDesc));

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(aidlDesc));
    return OK;
}

status_t EffectHalAidl::close() {
    auto ret = mEffect->close();
    ALOGI("%s %s", __func__, ret.getMessage());
    return ret.getStatus();
}

status_t EffectHalAidl::dump(int fd) {
    ALOGW("%s not implemented yet, fd %d", __func__, fd);
    return OK;
}

} // namespace effect
} // namespace android
