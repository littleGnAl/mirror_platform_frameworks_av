/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <cstdint>
#include <cstring>
#include <optional>
#define LOG_TAG "EffectConversionHelperAidl"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>

#include <utils/Log.h>

#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::aidl::android::media::audio::common::AudioMode;
using ::aidl::android::media::audio::common::AudioSource;
using android::effect::utils::EffectParamReader;
using android::effect::utils::EffectParamWriter;

using ::android::status_t;

const std::map<uint32_t /* effect_command_e */, EffectConversionHelperAidl::CommandHandler>
        EffectConversionHelperAidl::mCommandHandlerMap = {
                {EFFECT_CMD_INIT, &EffectConversionHelperAidl::handleInit},
                {EFFECT_CMD_SET_PARAM, &EffectConversionHelperAidl::handleSetParameter},
                {EFFECT_CMD_GET_PARAM, &EffectConversionHelperAidl::handleGetParameter},
                {EFFECT_CMD_SET_CONFIG, &EffectConversionHelperAidl::handleSetConfig},
                {EFFECT_CMD_GET_CONFIG, &EffectConversionHelperAidl::handleGetConfig},
                {EFFECT_CMD_RESET, &EffectConversionHelperAidl::handleReset},
                {EFFECT_CMD_ENABLE, &EffectConversionHelperAidl::handleEnable},
                {EFFECT_CMD_DISABLE, &EffectConversionHelperAidl::handleDisable},
                {EFFECT_CMD_SET_AUDIO_SOURCE, &EffectConversionHelperAidl::handleSetAudioSource},
                {EFFECT_CMD_SET_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_INPUT_DEVICE, &EffectConversionHelperAidl::handleSetDevice},
                {EFFECT_CMD_SET_VOLUME, &EffectConversionHelperAidl::handleSetVolume},
                {EFFECT_CMD_OFFLOAD, &EffectConversionHelperAidl::handleSetOffload},
                {EFFECT_CMD_FIRST_PROPRIETARY, &EffectConversionHelperAidl::handleFirstPriority}};

EffectConversionHelperAidl::EffectConversionHelperAidl(
        std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect> effect,
        int32_t sessionId, int32_t ioId, const Descriptor& desc)
    : mSessionId(sessionId), mIoId(ioId), mDesc(desc), mEffect(std::move(effect)) {
    mCommon.session = sessionId;
    mCommon.ioHandle = ioId;
    mCommon.input = mCommon.output = kDefaultAudioConfig;
}

status_t EffectConversionHelperAidl::handleCommand(uint32_t cmdCode, uint32_t cmdSize,
                                                   void* pCmdData, uint32_t* replySize,
                                                   void* pReplyData) {
    const auto& handler = mCommandHandlerMap.find(cmdCode);
    if (handler == mCommandHandlerMap.end() || !handler->second) {
        ALOGE("%s handler for command %u doesn't exist", __func__, cmdCode);
        return BAD_VALUE;
    }
    return (this->*handler->second)(cmdSize, pCmdData, replySize, pReplyData);
}

status_t EffectConversionHelperAidl::handleInit(uint32_t cmdSize __unused,
                                                const void* pCmdData __unused, uint32_t* replySize,
                                                void* pReplyData) {
    if (!replySize || *replySize < sizeof(int) || !pReplyData) {
        return BAD_VALUE;
    }

    return *(status_t*)pReplyData =
                   statusTFromBinderStatus(mEffect->open(mCommon, std::nullopt, &mOpenReturn));
}

status_t EffectConversionHelperAidl::handleSetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize ||
        *replySize < sizeof(int) || !pReplyData) {
        return BAD_VALUE;
    }

    auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (!reader.validateCmdSize(cmdSize)) {
        ALOGE("%s illegal param %s size %u", __func__, reader.toString().c_str(), cmdSize);
        return BAD_VALUE;
    }

    status_t ret = setParameter(reader);
    EffectParamWriter writer(*(effect_param_t*)pReplyData);
    writer.setStatus(ret);
    return *(status_t*)pReplyData = ret;
}

status_t EffectConversionHelperAidl::handleGetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_param_t) || !pCmdData || !replySize || !pReplyData) {
        return BAD_VALUE;
    }

    const auto reader = EffectParamReader(*(effect_param_t*)pCmdData);
    if (*replySize < sizeof(effect_param_t) + reader.getParameterSize()) {
        ALOGE("%s illegal param %s, replySize %u", __func__, reader.toString().c_str(), *replySize);
        return BAD_VALUE;
    }

    // copy effect_param_t and parameters
    memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + reader.getParameterSize());
    auto writer = EffectParamWriter(*(effect_param_t*)pReplyData);
    status_t ret = getParameter(writer);
    writer.finishValueWrite();
    writer.setStatus(ret);
    *replySize = writer.getTotalSize();
    if (ret != OK) {
        ALOGE("%s error ret %d, %s", __func__, ret, writer.toString().c_str());
    }
    return ret;
}

status_t EffectConversionHelperAidl::handleSetConfig(uint32_t cmdSize,
                                                     const void* pCmdData __unused,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(int) || !pReplyData ||
        cmdSize != sizeof(effect_config_t)) {
        return BAD_VALUE;
    }

    // TODO: need to implement setConfig with setParameter(common)
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleGetConfig(uint32_t cmdSize __unused,
                                                     const void* pCmdData __unused,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(effect_config_t) || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    Parameter param;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(
            Parameter::Id::make<Parameter::Id::commonTag>(Parameter::common), &param)));

    const auto& common = param.get<Parameter::common>();
    effect_config_t* pConfig = (effect_config_t*)pReplyData;
    pConfig->inputCfg = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(common.input.base, true));
    pConfig->outputCfg =
            VALUE_OR_RETURN_STATUS(::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(
                    common.output.base, false));
    mCommon = common;
    return OK;
}

status_t EffectConversionHelperAidl::handleReset(uint32_t cmdSize __unused,
                                                 const void* pCmdData __unused, uint32_t* replySize,
                                                 void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::RESET));
}

status_t EffectConversionHelperAidl::handleEnable(uint32_t cmdSize __unused,
                                                  const void* pCmdData __unused,
                                                  uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::START));
}

status_t EffectConversionHelperAidl::handleDisable(uint32_t cmdSize __unused,
                                                   const void* pCmdData __unused,
                                                   uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    return statusTFromBinderStatus(mEffect->command(CommandId::STOP));
}

status_t EffectConversionHelperAidl::handleSetAudioSource(uint32_t cmdSize, const void* pCmdData,
                                                          uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }

    audio_source_t source = *(audio_source_t*)pCmdData;
    AudioSource aidlSource =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_source_t_AudioSource(source));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::source>(aidlSource))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetAudioMode(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    audio_mode_t mode = *(audio_mode_t *)pCmdData;
    AudioMode aidlMode =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_mode_t_AudioMode(mode));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::mode>(aidlMode))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetDevice(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    // TODO: convert from audio_devices_t to std::vector<AudioDeviceDescription>
    // const auto& legacyDevice = *(uint32_t*)(pCmdData);
    std::vector<AudioDeviceDescription> aidlDevices;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::deviceDescription>(aidlDevices))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}
status_t EffectConversionHelperAidl::handleSetVolume(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (cmdSize != 2 * sizeof(uint32_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    Parameter::VolumeStereo volume = {.left = (float)(*(uint32_t*)pCmdData) / (1 << 24),
                                      .right = (float)(*(uint32_t*)pCmdData + 1) / (1 << 24)};
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mEffect->setParameter(Parameter::make<Parameter::volumeStereo>(volume))));
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleSetOffload(uint32_t cmdSize, const void* pCmdData,
                                                      uint32_t* replySize, void* pReplyData) {
    if (cmdSize < sizeof(effect_offload_param_t) || !pCmdData || !replySize || !pReplyData) {
        ALOGE("%s parameter invalid %u %p %p %p", __func__, cmdSize, pCmdData, replySize,
              pReplyData);
        return BAD_VALUE;
    }
    // TODO: handle this after effectproxy implemented in libaudiohal
    return *static_cast<int32_t*>(pReplyData) = OK;
}

status_t EffectConversionHelperAidl::handleFirstPriority(uint32_t cmdSize __unused,
                                                         const void* pCmdData __unused,
                                                         uint32_t* replySize, void* pReplyData) {
    if (!replySize || !pReplyData) {
        ALOGE("%s parameter invalid %p %p", __func__, replySize, pReplyData);
        return BAD_VALUE;
    }

    // TODO to be implemented
    return OK;
}

}  // namespace effect
}  // namespace android
