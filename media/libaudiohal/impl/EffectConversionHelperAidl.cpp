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

#include <cstring>
#define LOG_TAG "EffectConversionHelperAidl"
//#define LOG_NDEBUG 0

#include <media/audiohal/AudioEffectUuid.h>
#include <media/audiohal/AudioHalUtils.h>
#include <utils/Log.h>

#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

using ::aidl::android::hardware::audio::effect::AcousticEchoCanceler;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::media::audio::common::AudioUuid;
using ::android::status_t;


const std::map<uint32_t /* effect_command_e */, EffectConversionHelperAidl::CommandHandler>
        EffectConversionHelperAidl::mCommandHandlerMap = {
                {EFFECT_CMD_INIT, &EffectConversionHelperAidl::handleInit},
                {EFFECT_CMD_SET_PARAM, &EffectConversionHelperAidl::handleSetParameter},
                {EFFECT_CMD_GET_PARAM, &EffectConversionHelperAidl::handleGetParameter},
                {EFFECT_CMD_SET_CONFIG, &EffectConversionHelperAidl::handleSetConfig},
                {EFFECT_CMD_GET_CONFIG, &EffectConversionHelperAidl::handleGetConfig}};

const std::map<AudioUuid /* TypeUUID */, std::pair<EffectConversionHelperAidl::SetParameter,
                                                   EffectConversionHelperAidl::GetParameter>>
        EffectConversionHelperAidl::mParameterHandlerMap = {
                {kAcousticEchoCancelerTypeUUID,
                 {&EffectConversionHelperAidl::setAecParameter,
                  &EffectConversionHelperAidl::getAecParameter}}};

status_t EffectConversionHelperAidl::handleInit(uint32_t cmdSize, const void* pCmdData,
                                                uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize < sizeof(int) || !pReplyData) {
        return BAD_VALUE;
    }

    const effect_param_t* param = (effect_param_t*)pCmdData;
    if (!validateCommandSize(*param, cmdSize)) {
        ALOGE("%s illegal param %s size %u", __func__, android::detail::toString(*param).c_str(),
              cmdSize);
        return BAD_VALUE;
    }

    const auto& handler = mParameterHandlerMap.find(mTypeUuid);
    if (handler == mParameterHandlerMap.end() || !handler->second.first) {
        ALOGE("%s handler for uuid %s not found", __func__, mTypeUuid.toString().c_str());
        return BAD_VALUE;
    }
            // open with default effect_config_t (convert to Parameter.Common)
            IEffect::OpenEffectReturn ret;
            Parameter::Common common;
            RETURN_IF_BINDER_FAIL(mEffect->open(common, std::nullopt, &ret));

    const SetParameter& functor = handler->second.first;
    return (this->*functor)(*(const effect_param_t*)param);
}

status_t EffectConversionHelperAidl::handleSetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < kEffectParamSize || !pCmdData || !replySize || *replySize < sizeof(int) ||
        !pReplyData) {
        return BAD_VALUE;
    }

    const effect_param_t* param = (effect_param_t*)pCmdData;
    if (!validateCommandSize(*param, cmdSize)) {
        ALOGE("%s illegal param %s size %u", __func__, android::detail::toString(*param).c_str(),
              cmdSize);
        return BAD_VALUE;
    }

    const auto& handler = mParameterHandlerMap.find(mTypeUuid);
    if (handler == mParameterHandlerMap.end() || !handler->second.first) {
        ALOGE("%s handler for uuid %s not found", __func__, mTypeUuid.toString().c_str());
        return BAD_VALUE;
    }
    const SetParameter& functor = handler->second.first;
    return *(status_t*)pReplyData = (this->*functor)(*(const effect_param_t*)param);
}

status_t EffectConversionHelperAidl::handleGetParameter(uint32_t cmdSize, const void* pCmdData,
                                                        uint32_t* replySize, void* pReplyData) {
    if (cmdSize < kEffectParamSize || !pCmdData || !replySize || !pReplyData) {
        return BAD_VALUE;
    }

    const effect_param_t* param = (effect_param_t*)pCmdData;
    if (!validateCommandSize(*param, *replySize)) {
        ALOGE("%s illegal param %s, replysize %u", __func__,
              android::detail::toString(*param).c_str(), *replySize);
        return BAD_VALUE;
    }

    const auto& handler = mParameterHandlerMap.find(mTypeUuid);
    if (handler == mParameterHandlerMap.end() || !handler->second.second) {
        ALOGE("%s handler for uuid %s not found", __func__, mTypeUuid.toString().c_str());
        return BAD_VALUE;
    }
    const GetParameter& functor = handler->second.second;
    memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + param->psize);
    effect_param_t* reply = (effect_param_t *)pReplyData;
    (this->*functor)(*reply);
    *replySize = kEffectParamSize + padding(reply->psize) + reply->vsize;
    return reply->status;
}

status_t EffectConversionHelperAidl::handleSetConfig(uint32_t cmdSize, const void* pCmdData,
                                                     uint32_t* replySize, void* pReplyData) {
    if (!replySize || *replySize != sizeof(int) || !pReplyData ||
        cmdSize != sizeof(effect_config_t)) {
        return BAD_VALUE;
    }

    const auto& legacyConfig = static_cast<const effect_config_t*>(pCmdData);
    // already open, apply latest settings
    Parameter::Common common;
    common.input.base =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfigBase(
                    legacyConfig->inputCfg, true /* isInput */));
    common.output.base =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_buffer_config_t_AudioConfigBase(
                    legacyConfig->outputCfg, false /* isInput */));
    common.session = mSessionId;
    common.ioHandle = mIoId;
    // TODO: add access mode support
    RETURN_IF_BINDER_FAIL(mEffect->setParameter(Parameter::make<Parameter::common>(common)));
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
    RETURN_IF_BINDER_FAIL(mEffect->getParameter(
            Parameter::Id::make<Parameter::Id::commonTag>(Parameter::common), &param));

    const auto& common = param.get<Parameter::common>();
    effect_config_t* pConfig = (effect_config_t*)pReplyData;
    pConfig->inputCfg = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(common.input.base, true));
    pConfig->outputCfg =
            VALUE_OR_RETURN_STATUS(::aidl::android::aidl2legacy_AudioConfigBase_buffer_config_t(
                    common.output.base, false));
    return OK;
}

status_t EffectConversionHelperAidl::setAecParameter(const effect_param_t& param) {
    const auto psize = sizeof(uint32_t);
    const auto vsize = sizeof(uint32_t);
    if (!validatePVsize(param, psize, vsize)) {
        return BAD_VALUE;
    }

    const auto& type = *(uint32_t*)param.data;
    const auto& value = *(uint32_t*)(param.data + psize);
    Parameter aidlParam;
    switch (type) {
        case AEC_PARAM_ECHO_DELAY:
            FALLTHROUGH_INTENDED;
        case AEC_PARAM_PROPERTIES: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_echoDelay_Parameter(value));
            break;
        }
        case AEC_PARAM_MOBILE_MODE: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_mobileMode_Parameter(value));
            break;
        }
        default: {
            ALOGW("%s unknown param %08x value %08x", __func__, type, value);
            return BAD_VALUE;
        }
    }

    return mEffect->setParameter(aidlParam).getStatus();
}

status_t EffectConversionHelperAidl::getAecParameter(effect_param_t& param) {
    const auto psize = sizeof(uint32_t);
    const auto vsize = sizeof(uint32_t);
    if (!validatePVsize(param, psize, vsize)) {
        return param.status = BAD_VALUE;
    }

    uint32_t value = 0;
    status_t status = BAD_VALUE;
    const auto& type = *(uint32_t*)param.data;
    switch (type) {
        case AEC_PARAM_ECHO_DELAY:
            FALLTHROUGH_INTENDED;
        case AEC_PARAM_PROPERTIES: {
            Parameter aidlParam;
            Parameter::Id id = Parameter::Id::make<Parameter::Id::acousticEchoCancelerTag>(
                    AcousticEchoCanceler::Id::make<AcousticEchoCanceler::Id::commonTag>(
                            AcousticEchoCanceler::echoDelayUs));
            RETURN_IF_BINDER_FAIL(mEffect->getParameter(id, &aidlParam));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_uint32_echoDelay(aidlParam));
            break;
        }
        case AEC_PARAM_MOBILE_MODE: {
            Parameter aidlParam;
            Parameter::Id id = Parameter::Id::make<Parameter::Id::acousticEchoCancelerTag>(
                    AcousticEchoCanceler::Id::make<AcousticEchoCanceler::Id::commonTag>(
                            AcousticEchoCanceler::mobileMode));
            RETURN_IF_BINDER_FAIL(mEffect->getParameter(id, &aidlParam));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_uint32_mobileMode(aidlParam));
            break;
        }
        default:
            ALOGW("%s unknown param %08x", __func__, type);
            break;
    }

    *(uint32_t*)(param.data + psize) = value;
    return param.status = status;
}

} // namespace effect
} // namespace android
