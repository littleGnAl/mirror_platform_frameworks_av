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

#define LOG_TAG "AHAL_LoudnessEnhancerImpl"

#include <android-base/logging.h>

#include "EffectLoudnessEnhancerAidl.h"

using aidl::android::hardware::audio::effect::IEffect;
using aidl::android::hardware::audio::effect::kLoudnessEnhancerImplUUID;
using aidl::android::hardware::audio::effect::LoudnessEnhancerImpl;
using aidl::android::hardware::audio::effect::State;
using aidl::android::media::audio::common::AudioUuid;

extern "C" binder_exception_t createEffect(const AudioUuid* in_impl_uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (!in_impl_uuid || *in_impl_uuid != kLoudnessEnhancerImplUUID) {
        LOG(ERROR) << __func__ << "uuid not supported";
        return EX_ILLEGAL_ARGUMENT;
    }
    if (instanceSpp) {
        *instanceSpp = ndk::SharedRefBase::make<LoudnessEnhancerImpl>();
        LOG(DEBUG) << __func__ << " instance " << instanceSpp->get() << " created";
        return EX_NONE;
    } else {
        LOG(ERROR) << __func__ << " invalid input parameter!";
        return EX_ILLEGAL_ARGUMENT;
    }
}

extern "C" binder_exception_t destroyEffect(const std::shared_ptr<IEffect>& instanceSp) {
    if (!instanceSp) {
        return EX_NONE;
    }
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

ndk::ScopedAStatus LoudnessEnhancerImpl::getDescriptor(Descriptor* _aidl_return) {
    RETURN_IF(!_aidl_return, EX_ILLEGAL_ARGUMENT, "Parameter:nullptr");
    LOG(DEBUG) << __func__ << kLoudnessEnhancerDesc.toString();
    *_aidl_return = kLoudnessEnhancerDesc;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus LoudnessEnhancerImpl::commandImpl(CommandId command) {
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
            mContext->reset();
            break;
        default:
            LOG(ERROR) << __func__ << " commandId " << toString(command) << " not supported";
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                    "commandIdNotSupported");
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus LoudnessEnhancerImpl::setParameterSpecific(const Parameter::Specific& specific) {
    RETURN_IF(Parameter::Specific::loudnessEnhancer != specific.getTag(), EX_ILLEGAL_ARGUMENT,
              "EffectNotSupported");
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    auto& leParam = specific.get<Parameter::Specific::loudnessEnhancer>();
    auto tag = leParam.getTag();

    switch (tag) {
        case LoudnessEnhancer::gainMb: {
            RETURN_IF(mContext->setLeGain(leParam.get<LoudnessEnhancer::gainMb>()) !=
                              RetCode::SUCCESS,
                      EX_ILLEGAL_ARGUMENT, "setGainMbFailed");
            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "LoudnessEnhancerTagNotSupported");
        }
    }
}

ndk::ScopedAStatus LoudnessEnhancerImpl::getParameterSpecific(const Parameter::Id& id,
                                                              Parameter::Specific* specific) {
    RETURN_IF(!specific, EX_NULL_POINTER, "nullPtr");
    auto tag = id.getTag();
    RETURN_IF(Parameter::Id::loudnessEnhancerTag != tag, EX_ILLEGAL_ARGUMENT, "wrongIdTag");
    auto leId = id.get<Parameter::Id::loudnessEnhancerTag>();
    auto leIdTag = leId.getTag();
    switch (leIdTag) {
        case LoudnessEnhancer::Id::commonTag:
            return getParameterLoudnessEnhancer(leId.get<LoudnessEnhancer::Id::commonTag>(),
                                                specific);
        default:
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(leIdTag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "LoudnessEnhancerTagNotSupported");
    }
}

ndk::ScopedAStatus LoudnessEnhancerImpl::getParameterLoudnessEnhancer(
        const LoudnessEnhancer::Tag& tag, Parameter::Specific* specific) {
    RETURN_IF(!mContext, EX_NULL_POINTER, "nullContext");

    LoudnessEnhancer leParam;
    switch (tag) {
        case LoudnessEnhancer::gainMb: {
            leParam.set<LoudnessEnhancer::gainMb>(mContext->getLeGain());
            break;
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCodeWithMessage(
                    EX_ILLEGAL_ARGUMENT, "LoudnessEnhancerTagNotSupported");
        }
    }

    specific->set<Parameter::Specific::loudnessEnhancer>(leParam);
    return ndk::ScopedAStatus::ok();
}

std::shared_ptr<EffectContext> LoudnessEnhancerImpl::createContext(
        const Parameter::Common& common) {
    if (mContext) {
        LOG(DEBUG) << __func__ << " context already exist";
        return mContext;
    }

    mContext = std::make_shared<LoudnessEnhancerContext>(1 /* statusFmqDepth */, common);
    return mContext;
}

RetCode LoudnessEnhancerImpl::releaseContext() {
    if (mContext) {
        mContext.reset();
    }
    return RetCode::SUCCESS;
}

// Processing method running in EffectWorker thread.
IEffect::Status LoudnessEnhancerImpl::effectProcessImpl(float* in, float* out,
                                                        int sampleToProcess) {
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " sample " << sampleToProcess;
    if (!mContext) {
        LOG(ERROR) << __func__ << " nullContext";
        return {EX_NULL_POINTER, 0, 0};
    }

    if (in == nullptr || out == nullptr ||
        mContext->getInputFrameSize() != mContext->getOutputFrameSize() ||
        mContext->getInputFrameSize() == 0) {
        return {EX_ILLEGAL_ARGUMENT, 0, 0};
    }

    LOG(DEBUG) << __func__ << " start processing";

    // PcmType is always expected to Float 32 bit.
    constexpr float scale = 1 << 15;  // power of 2 is lossless conversion to int16_t range
    constexpr float inverseScale = 1.f / scale;
    const float inputAmp = pow(10, mContext->getLeGain() / 2000.0f) * scale;
    float leftSample, rightSample;
    // Verify framecount and samplesToProcess
    for (int inIdx = 0; inIdx < sampleToProcess; inIdx += 2) {
        // makeup gain is applied on the input of the compressor
        leftSample = inputAmp * in[inIdx];
        rightSample = inputAmp * in[inIdx + 1];
        mContext->compress(&leftSample, &rightSample);
        in[inIdx] = leftSample * inverseScale;
        in[inIdx + 1] = rightSample * inverseScale;
    }
    if (in != out) {
        for (int i = 0; i < sampleToProcess; i++) {
            out[i] += in[i];
        }
    }
    return {STATUS_OK, sampleToProcess, sampleToProcess};
}

}  // namespace aidl::android::hardware::audio::effect
