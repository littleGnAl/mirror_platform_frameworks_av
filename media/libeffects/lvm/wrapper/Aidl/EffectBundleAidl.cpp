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

#define LOG_TAG "EffectBundleAidl"
#include <Utils.h>
#include <algorithm>
#include <unordered_set>

#include <android-base/logging.h>
#include <fmq/AidlMessageQueue.h>
#include <audio_effects/effect_bassboost.h>
#include <audio_effects/effect_equalizer.h>
#include <audio_effects/effect_virtualizer.h>

#include "EffectBundleAidl.h"
#include <LVM.h>
#include <limits.h>

using aidl::android::hardware::audio::effect::EffectBundleAidl;
using aidl::android::hardware::audio::effect::EqualizerBundleImplUUID;
using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

extern "C" binder_exception_t createEffect(const AudioUuid* uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (!uuid || *uuid != EqualizerBundleImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<EffectBundleAidl>(*uuid);
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t destroyEffect(const std::shared_ptr<IEffect>& instanceSp) {
    State state;
    ndk::ScopedAStatus status = instanceSp->getState(&state);
    if (!status.isOk() || State::INIT != state) {
        LOG(ERROR) << __func__ << " instance " << instanceSp.get()
                   << " in state: " << toString(state) << ", status: " << status.getDescription();
        return EX_ILLEGAL_STATE;
    }
    LOG(DEBUG) << __func__ << " instance " << instanceSp.get() << " destroyed";
    return EX_NONE;
}

namespace aidl::android::hardware::audio::effect {

EffectBundleAidl::EffectBundleAidl(const AudioUuid& uuid) {
    // init bundle with the first effect creation.
    if (!mGlobalSession) {
        mGlobalSession = std::make_unique<GlobalSession>();
    }

    LOG(DEBUG) << __func__ << uuid.toString();
    if (uuid == EqualizerBundleImplUUID) {
        mType = BundleEffectType::EQUALIZER;
        mDescriptor = &kEqualizerDesc;
    } else {
        LOG(ERROR) << __func__ << uuid.toString() << " not supported yet!";
    }
};

EffectBundleAidl::~EffectBundleAidl() {
    cleanUp();
    LOG(DEBUG) << __func__;
};

ndk::ScopedAStatus EffectBundleAidl::open(const Parameter::Common& common,
                                          const Parameter::Specific& specific,
                                          OpenEffectReturn* _aidl_return) {
    LOG(DEBUG) << " common: " << common.toString() << " specific " << specific.toString()
               << _aidl_return->toString();
    RETURN_OK_IF(mState != State::INIT);

    // create context (together with EffectWorker thread) with GlobalSession
    mContext = mGlobalSession->getOrCreateSession(mType, 1 /* statusFmqDepth */, common);
    RETURN_IF(!mContext, EX_ILLEGAL_ARGUMENT, "createContextFailed");
    setContext(mContext);

    setSpecificParameter(specific);

    // create the worker thread
    RETURN_IF_RETCODE_NOT_SUCCESS(createThread(LOG_TAG), EX_UNSUPPORTED_OPERATION,
                                  "FailedToCreateWorker");

    mContext->dupeFmq(_aidl_return);
    mState = State::IDLE;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::close() {
    LOG(DEBUG) << __func__;
    RETURN_OK_IF(mState == State::INIT);
    RETURN_IF(mState == State::PROCESSING, EX_ILLEGAL_STATE, "WrongState:StillProcessing");
    // stop the worker thread
    mState = State::INIT;
    destroyThread();
    mGlobalSession->releaseSession(mType, mContext->getSessionId());
    mContext.reset();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::getDescriptor(Descriptor* _aidl_return) {
    LOG(DEBUG) << _aidl_return->toString();
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    *_aidl_return = *mDescriptor;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::command(CommandId in_commandId) {
    LOG(DEBUG) << __func__ << ": receive command:" << toString(in_commandId);
    RETURN_IF(mState == State::INIT, EX_ILLEGAL_STATE, "CommandStateError");
    RETURN_IF(!mContext, EX_NULL_POINTER , "nullContext");

    switch (in_commandId) {
        case CommandId::START:
            RETURN_OK_IF(mState == State::PROCESSING);
            mState = State::PROCESSING;
            mContext->enable();
            startThread();
            LOG(DEBUG) << __func__ << " state: " << toString(mState);
            return ndk::ScopedAStatus::ok();
        case CommandId::STOP:
            RETURN_OK_IF(mState == State::IDLE);
            mState = State::IDLE;
            mContext->disable();
            stopThread();
            LOG(DEBUG) << __func__ << " state: " << toString(mState);
            return ndk::ScopedAStatus::ok();
        case CommandId::RESET:
            RETURN_OK_IF(mState == State::IDLE);
            mState = State::IDLE;
            mContext->disable();
            stopThread();
            mContext->resetBuffer();
            LOG(DEBUG) << __func__ << " state: " << toString(mState);
            return ndk::ScopedAStatus::ok();
        default:
            LOG(ERROR) << __func__ << " instance still processing";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "CommandIdNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::setParameter(const Parameter& in_param) {
    RETURN_IF(mState == State::INIT, EX_ILLEGAL_STATE, "instanceNotOpen");
    RETURN_IF(!mContext, EX_NULL_POINTER , "nullContext");
    LOG(DEBUG) << __func__ << " with: " << in_param.toString();

    auto tag = in_param.getTag();
    switch (tag) {
        case Parameter::common:
            return setCommonParameter(in_param.get<Parameter::common>());
        case Parameter::deviceDescription:
            mContext->setOutputDevice(in_param.get<Parameter::deviceDescription>());
            break;
        case Parameter::mode: {
            mContext->setAudioMode(in_param.get<Parameter::mode>());
            break;
        }
        case Parameter::source: {
            mContext->setAudioSource(in_param.get<Parameter::source>());
            break;
        }
        case Parameter::volumeStereo: {
            RETURN_IF_RETCODE_NOT_SUCCESS(
                    mContext->setVolumeStereo(in_param.get<Parameter::volumeStereo>()),
                    EX_UNSUPPORTED_OPERATION, "setVolumeFailed");
            break;
        }
        case Parameter::specific:
            return setSpecificParameter(in_param.get<Parameter::specific>());
        default:
            LOG(ERROR) << __func__ << " parameter not supported: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "ParameterNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::getParameter(const Parameter::Id& in_paramId,
                                                  Parameter* _aidl_return) {
    RETURN_IF(!mContext, EX_NULL_POINTER , "nullContext");
    LOG(DEBUG) << __func__ << " with: " << in_paramId.toString();

    auto idTag = in_paramId.getTag();
    switch (idTag) {
        case Parameter::Id::commonTag: {
            return getCommonParameter(in_paramId.get<Parameter::Id::commonTag>(), _aidl_return);
        }
        case Parameter::Id::equalizerTag: {
            return getEqualizerParameter(in_paramId.get<Parameter::Id::equalizerTag>(),
                                         _aidl_return);
        }
        default:
            LOG(ERROR) << __func__ << " parameter not supported: " << toString(idTag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "ParameterNotSupported");
    }
}

ndk::ScopedAStatus EffectBundleAidl::getState(State* _aidl_return) {
    *_aidl_return = mState;
    LOG(DEBUG) << __func__ << toString(*_aidl_return);
    return ndk::ScopedAStatus::ok();
}

// Processing method running in EffectWorker thread.
IEffect::Status EffectBundleAidl::effectProcessImpl(float* in, float* out, int process) {
    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " process " << process;
    RETURN_VALUE_IF(!mContext, status, "nullContext");
    // TODO: LVM_Process
    return {STATUS_OK, process, process};
}

/// Private methods.
ndk::ScopedAStatus EffectBundleAidl::setCommonParameter(const Parameter::Common& common) {
    RETURN_IF(RetCode::SUCCESS != mContext->setParameterCommon(common), EX_ILLEGAL_ARGUMENT, "");
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::setSpecificParameter(const Parameter::Specific& specific) {
    LOG(DEBUG) << __func__ << " specific " << specific.toString();
    auto tag = specific.getTag();
    RETURN_IF(tag != Parameter::Specific::equalizer, EX_ILLEGAL_ARGUMENT,
              "specificParamNotSupported");
    RETURN_IF(mContext == nullptr, EX_NULL_POINTER , "nullContext");

    auto& eq = specific.get<Parameter::Specific::equalizer>();
    auto eqTag = eq.getTag();
    switch (eqTag) {
        case Equalizer::preset:
            RETURN_IF_RETCODE_NOT_SUCCESS(mContext->setEqPreset(eq.get<Equalizer::preset>()),
                                          EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            break;
        case Equalizer::bandLevels:
            RETURN_IF_RETCODE_NOT_SUCCESS(
                    mContext->setEqBandLevels(eq.get<Equalizer::bandLevels>()),
                    EX_ILLEGAL_ARGUMENT, "setBandLevelsFailed");
            break;
        default:
            LOG(ERROR) << __func__ << " unsupported parameter " << specific.toString();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "eqTagNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::getCommonParameter(Parameter::Tag tag, Parameter* parameter) {
    switch (tag) {
        case Parameter::common: {
            parameter->set<Parameter::common>(mContext->getParameterCommon());
            return ndk::ScopedAStatus::ok();
        }
        case Parameter::deviceDescription: {
            parameter->set<Parameter::deviceDescription>(mContext->getOutputDevice());
            return ndk::ScopedAStatus::ok();
        }
        case Parameter::mode: {
            parameter->set<Parameter::mode>(mContext->getAudioMode());
            return ndk::ScopedAStatus::ok();
        }
        case Parameter::source: {
            parameter->set<Parameter::source>(mContext->getAudioSource());
            return ndk::ScopedAStatus::ok();
        }
        case Parameter::volumeStereo: {
            parameter->set<Parameter::volumeStereo>(mContext->getVolumeStereo());
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " not handled tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "CommonTagNotSupported");
        }
    }
}

ndk::ScopedAStatus EffectBundleAidl::getEqualizerParameter(const Equalizer::Id& id,
                                                           Parameter* _aidl_return) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto idTag = id.getTag();
    RETURN_IF(idTag != Equalizer::Id::commonTag, EX_ILLEGAL_ARGUMENT, "EqIdTagNotSupported");
    Equalizer eqParam;
    auto eqTag = id.get<Equalizer::Id::commonTag>();
    switch (eqTag) {
        case Equalizer::bandLevels:
            eqParam.set<Equalizer::bandLevels>(mContext->getEqBandLevels());
            break;
        case Equalizer::preset:
            eqParam.set<Equalizer::preset>(mContext->getEqPreset());
            break;
        default:
            LOG(ERROR) << __func__ << " unsupported ID: " << id.toString();
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "eqTagNotSupported");
    }
    Parameter::Specific specParam =
            Parameter::Specific::make<Parameter::Specific::equalizer>(eqParam);
    _aidl_return->set<Parameter::specific>(specParam);
    return ndk::ScopedAStatus::ok();
}

void EffectBundleAidl::cleanUp() {
    if (State::PROCESSING == mState) {
        command(CommandId::STOP);
    }
    if (State::INIT != mState) {
        close();
    }
}

IEffect::Status EffectBundleAidl::status(binder_status_t status, size_t consumed, size_t produced) {
    IEffect::Status ret;
    ret.status = status;
    ret.fmqConsumed = consumed;
    ret.fmqProduced = produced;
    return ret;
}

}  // namespace aidl::android::hardware::audio::effect
