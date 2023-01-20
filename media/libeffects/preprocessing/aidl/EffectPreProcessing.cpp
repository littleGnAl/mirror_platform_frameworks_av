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

#define LOG_TAG "EffectPreProcessing"
#include <Utils.h>
#include <algorithm>
#include <unordered_set>

#include <android-base/logging.h>
#include <fmq/AidlMessageQueue.h>

#include <limits.h>
#include "EffectPreProcessing.h"

using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::EffectPreProcessing;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::kAcousticEchoCancelerSwImplUUID;
using aidl::android::hardware::audio::effect::kAutomaticGainControlSwImplUUID;
using aidl::android::hardware::audio::effect::kNoiseSuppressionSwImplUUID;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

bool isPreProcessingUuidSupported(const AudioUuid* uuid) {
    return (*uuid == kAcousticEchoCancelerSwImplUUID || *uuid == kAutomaticGainControlSwImplUUID ||
            *uuid == kNoiseSuppressionSwImplUUID);
}

extern "C" binder_exception_t createEffect(const AudioUuid* uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (uuid == nullptr || !isPreProcessingUuidSupported(uuid)) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<EffectPreProcessing>(*uuid);
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t queryEffect(const AudioUuid* in_impl_uuid, Descriptor* _aidl_return) {
    if (!in_impl_uuid || !isPreProcessingUuidSupported(in_impl_uuid)) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (*in_impl_uuid == kAcousticEchoCancelerSwImplUUID) {
        *_aidl_return = aidl::android::hardware::audio::effect::kAcousticEchoCancelerDesc;
    } else if (*in_impl_uuid == kAutomaticGainControlSwImplUUID) {
        *_aidl_return = aidl::android::hardware::audio::effect::kAutomaticGainControlDesc;
    } else if (*in_impl_uuid == kNoiseSuppressionSwImplUUID) {
        *_aidl_return = aidl::android::hardware::audio::effect::kNoiseSuppressionDesc;
    }
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

EffectPreProcessing::EffectPreProcessing(const AudioUuid& uuid) {
    LOG(DEBUG) << __func__ << uuid.toString();
    if (uuid == kAcousticEchoCancelerSwImplUUID) {
        mType = PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION;
        mDescriptor = &kAcousticEchoCancelerDesc;
        mEffectName = &kAcousticEchoCancelerEffectName;
    } else if (uuid == kAutomaticGainControlSwImplUUID) {
        mType = PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL;
        mDescriptor = &kAutomaticGainControlDesc;
        mEffectName = &kAutomaticGainControlEffectName;
    } else if (uuid == kNoiseSuppressionSwImplUUID) {
        mType = PreProcessingEffectType::NOISE_SUPPRESSION;
        mDescriptor = &kNoiseSuppressionDesc;
        mEffectName = &kNoiseSuppressionEffectName;
    } else {
        LOG(ERROR) << __func__ << uuid.toString() << " not supported!";
    }
}

EffectPreProcessing::~EffectPreProcessing() {
    cleanUp();
    LOG(DEBUG) << __func__;
}

ndk::ScopedAStatus EffectPreProcessing::getDescriptor(Descriptor* _aidl_return) {
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    LOG(DEBUG) << _aidl_return->toString();
    *_aidl_return = *mDescriptor;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectPreProcessing::setParameterSpecific(const Parameter::Specific& specific) {
    LOG(DEBUG) << __func__ << " specific " << specific.toString();
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto tag = specific.getTag();
    switch (tag) {
        case Parameter::Specific::acousticEchoCanceler:
            return setParameterAcousticEchoCanceler(specific);
        case Parameter::Specific::automaticGainControl:
            return setParameterAutomaticGainControl(specific);
        case Parameter::Specific::noiseSuppression:
            return setParameterNoiseSuppression(specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "specificParamNotSupported");
    }
}

ndk::ScopedAStatus EffectPreProcessing::setParameterAcousticEchoCanceler(
        const Parameter::Specific& specific) {
    auto& param = specific.get<Parameter::Specific::acousticEchoCanceler>();
    auto tag = param.getTag();

    switch (tag) {
        case AcousticEchoCanceler::echoDelayUs: {
            RETURN_IF(mContext->setAcousticEchoCancelerEchoDelay(
                              param.get<AcousticEchoCanceler::echoDelayUs>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "echoDelayNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        case AcousticEchoCanceler::mobileMode: {
            RETURN_IF(mContext->setAcousticEchoCancelerMobileMode(
                              param.get<AcousticEchoCanceler::mobileMode>()) != RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "SettingMobileModeNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "AcousticEchoCancelerTagNotSupported");
        }
    }
}

ndk::ScopedAStatus EffectPreProcessing::setParameterAutomaticGainControl(
        const Parameter::Specific& specific) {
    auto& param = specific.get<Parameter::Specific::automaticGainControl>();
    auto tag = param.getTag();

    switch (tag) {
        case AutomaticGainControl::fixedDigitalGainMb: {
            RETURN_IF(mContext->setAutomaticGainControlDigitalGain(
                              param.get<AutomaticGainControl::fixedDigitalGainMb>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "digitalGainNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        case AutomaticGainControl::levelEstimator: {
            RETURN_IF(
                    mContext->setAutomaticGainControlLevelEstimator(
                            param.get<AutomaticGainControl::levelEstimator>()) != RetCode::SUCCESS,
                    EX_ILLEGAL_ARGUMENT, "levelEstimatorNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        case AutomaticGainControl::saturationMarginMb: {
            RETURN_IF(mContext->setAutomaticGainControlSaturationMargin(
                              param.get<AutomaticGainControl::saturationMarginMb>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "saturationMarginNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "AutomaticGainControlTagNotSupported");
        }
    }
}

ndk::ScopedAStatus EffectPreProcessing::setParameterNoiseSuppression(
        const Parameter::Specific& specific) {
    auto& param = specific.get<Parameter::Specific::noiseSuppression>();
    auto tag = param.getTag();

    switch (tag) {
        case NoiseSuppression::level: {
            RETURN_IF(mContext->setNoiseSuppressionLevel(param.get<NoiseSuppression::level>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "levelNotSupported");
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "NoiseSuppressionTagNotSupported");
        }
    }
}

ndk::ScopedAStatus EffectPreProcessing::getParameterSpecific(const Parameter::Id& id,
                                                             Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();

    switch (tag) {
        case Parameter::Id::acousticEchoCancelerTag:
            return getParameterAcousticEchoCanceler(
                    id.get<Parameter::Id::acousticEchoCancelerTag>(), specific);
        case Parameter::Id::automaticGainControlTag:
            return getParameterAutomaticGainControl(
                    id.get<Parameter::Id::automaticGainControlTag>(), specific);
        case Parameter::Id::noiseSuppressionTag:
            return getParameterNoiseSuppression(id.get<Parameter::Id::noiseSuppressionTag>(),
                                                specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "wrongIdTag");
    }
}

ndk::ScopedAStatus EffectPreProcessing::getParameterAcousticEchoCanceler(
        const AcousticEchoCanceler::Id& id, Parameter::Specific* specific) {
    RETURN_IF(id.getTag() != AcousticEchoCanceler::Id::commonTag, EX_ILLEGAL_ARGUMENT,
              "AcousticEchoCancelerTagNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    AcousticEchoCanceler param;
    auto tag = id.get<AcousticEchoCanceler::Id::commonTag>();
    switch (tag) {
        case AcousticEchoCanceler::echoDelayUs: {
            param.set<AcousticEchoCanceler::echoDelayUs>(
                    mContext->getAcousticEchoCancelerEchoDelay());
            break;
        }
        case AcousticEchoCanceler::mobileMode: {
            param.set<AcousticEchoCanceler::mobileMode>(
                    mContext->getAcousticEchoCancelerMobileMode());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "AcousticEchoCancelerTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::acousticEchoCanceler>(param);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectPreProcessing::getParameterAutomaticGainControl(
        const AutomaticGainControl::Id& id, Parameter::Specific* specific) {
    RETURN_IF(id.getTag() != AutomaticGainControl::Id::commonTag, EX_ILLEGAL_ARGUMENT,
              "AutomaticGainControlTagNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    AutomaticGainControl param;

    auto tag = id.get<AutomaticGainControl::Id::commonTag>();
    switch (tag) {
        case AutomaticGainControl::fixedDigitalGainMb: {
            param.set<AutomaticGainControl::fixedDigitalGainMb>(
                    mContext->getAutomaticGainControlDigitalGain());
            break;
        }
        case AutomaticGainControl::levelEstimator: {
            param.set<AutomaticGainControl::levelEstimator>(
                    mContext->getAutomaticGainControlLevelEstimator());
            break;
        }
        case AutomaticGainControl::saturationMarginMb: {
            param.set<AutomaticGainControl::saturationMarginMb>(
                    mContext->getAutomaticGainControlSaturationMargin());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "AutomaticGainControlTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::automaticGainControl>(param);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectPreProcessing::getParameterNoiseSuppression(
        const NoiseSuppression::Id& id, Parameter::Specific* specific) {
    RETURN_IF(id.getTag() != NoiseSuppression::Id::commonTag, EX_ILLEGAL_ARGUMENT,
              "NoiseSuppressionTagNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    NoiseSuppression param;

    auto tag = id.get<NoiseSuppression::Id::commonTag>();
    switch (tag) {
        case NoiseSuppression::level: {
            param.set<NoiseSuppression::level>(mContext->getNoiseSuppressionLevel());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "NoiseSuppressionTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::noiseSuppression>(param);
    return ndk::ScopedAStatus::ok();
}

std::shared_ptr<EffectContext> EffectPreProcessing::createContext(const Parameter::Common& common) {
    if (mContext) {
        LOG(DEBUG) << __func__ << " context already exist";
    } else {
        // PreProcessingSession is a singleton
        mContext = PreProcessingSession::getPreProcessingSession().createSession(
                mType, 1 /* statusFmqDepth */, common);
    }

    return mContext;
}

std::shared_ptr<EffectContext> EffectPreProcessing::getContext() {
    return mContext;
}

RetCode EffectPreProcessing::releaseContext() {
    if (mContext) {
        PreProcessingSession::getPreProcessingSession().releaseSession(mType,
                                                                       mContext->getSessionId());
        mContext.reset();
    }
    return RetCode::SUCCESS;
}

ndk::ScopedAStatus EffectPreProcessing::commandImpl(CommandId command) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");
    switch (command) {
        case CommandId::START:
            mContext->enable();
            break;
        case CommandId::STOP:
            mContext->disable();
            break;
        case CommandId::RESET:
            mContext->disable();
            mContext->resetBuffer();
            break;
        default:
            LOG(ERROR) << __func__ << " commandId " << toString(command) << " not supported";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "commandIdNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

// Processing method running in EffectWorker thread.
IEffect::Status EffectPreProcessing::effectProcessImpl(float* in, float* out, int sampleToProcess) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!mContext, status, "nullContext");
    return mContext->lvmProcess(in, out, sampleToProcess);
}

}  // namespace aidl::android::hardware::audio::effect
