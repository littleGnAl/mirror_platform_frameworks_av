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

#include "BundleTypes.h"
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

using android::hardware::audio::common::getFrameSizeInBytes;

namespace aidl::android::hardware::audio::effect {

extern "C" binder_exception_t createEffect(const AudioUuid* uuid,
                                           std::shared_ptr<IEffect>* instanceSpp) {
    if (!uuid) {
        LOG(ERROR) << __func__ << " nullptr uuid";
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

EffectBundleAidl::EffectBundleAidl(const AudioUuid& uuid) {
    // init bundle with the first effect creation.
    std::call_once(EffectBundleAidl::mInitFlag,
                   [&]() { mGloalSession = std::make_unique<GlobalSession>(); });

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
    auto tag = specific.getTag();
    //TODO: only support EQ now
    RETURN_IF(tag != Parameter::Specific::equalizer, EX_ILLEGAL_ARGUMENT, "ParameterWrong");

    // Set essential parameters before create worker thread.
    auto& input = common.input;
    auto& output = common.output;
    size_t inputFrameSize = getFrameSizeInBytes(input.base.format, input.base.channelMask);
    size_t outputFrameSize = getFrameSizeInBytes(output.base.format, output.base.channelMask);
    auto sessionContext = mGloalSession->getOrCreateSession(mType, common, specific);
    mContext = std::make_shared<EffectBundleContext>(1, input.frameCount * inputFrameSize,
                                                     output.frameCount * outputFrameSize,
                                                     sessionContext);
    RETURN_IF(mContext, EX_UNSUPPORTED_OPERATION, "FailedToCreateContext");
    setContext(mContext);

    setSpecificParameter(specific);

    LOG(DEBUG) << " common: " << common.toString() << " specific " << specific.toString();

    // create the worker thread
    RETURN_IF(!mContext, EX_UNSUPPORTED_OPERATION, "FailedToCreateContext");
    RETURN_IF_RETCODE_NOT_SUCCESS(createThread(LOG_TAG), EX_UNSUPPORTED_OPERATION,
                                  "FailedToCreateWorker");

    _aidl_return->statusMQ = mContext->getStatusFmq()->dupeDesc();
    _aidl_return->inputDataMQ = mContext->getInputDataFmq()->dupeDesc();
    _aidl_return->outputDataMQ = mContext->getOutputDataFmq()->dupeDesc();
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

    switch (in_commandId) {
        case CommandId::START:
            // start processing.
            mState = State::PROCESSING;
            mContext->enableSession();
            startThread();
            LOG(DEBUG) << __func__ << " state: " << toString(mState);
            return ndk::ScopedAStatus::ok();
        case CommandId::STOP:
            // stop processing.
            mState = State::IDLE;
            mContext->disableSession();
            stopThread();
            LOG(DEBUG) << __func__ << " state: " << toString(mState);
            return ndk::ScopedAStatus::ok();
        case CommandId::RESET:
            mState = State::IDLE;
            mContext->disableSession();
            mContext.reset();
            stopThread();
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
    LOG(DEBUG) << __func__ << " with: " << in_param.toString();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectBundleAidl::getParameter(const Parameter::Id& in_paramId,
                                             Parameter* _aidl_return) {
    LOG(DEBUG) << __func__ << in_paramId.toString() << _aidl_return->toString();
    return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                            "Parameter:IdNotSupported");
}

ndk::ScopedAStatus EffectBundleAidl::getState(State* _aidl_return) {
    LOG(DEBUG) << __func__ << toString(*_aidl_return);
    return ndk::ScopedAStatus::ok();
}

/// Private methods.

ndk::ScopedAStatus EffectBundleAidl::getCommonParameter(Parameter::Tag tag, Parameter* parameter) {
    LOG(DEBUG) << __func__ << " tag " << toString(tag) << " parameter " << parameter->toString();
    return ndk::ScopedAStatus::ok();
}

void EffectBundleAidl::cleanUp() {
}

IEffect::Status EffectBundleAidl::status(binder_status_t status, size_t consumed, size_t produced) {
    IEffect::Status ret;
    ret.status = status;
    ret.fmqByteConsumed = consumed;
    ret.fmqByteProduced = produced;
    return ret;
}

// Processing method running in EffectWorker thread.
IEffect::Status EffectBundleAidl::effectProcessImpl(float *in, float *out, int frameCount) {
    // TODO: get data buffer and process.
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " count " << frameCount;
    return status(STATUS_OK, 0, 0);
}

}  // namespace aidl::android::hardware::audio::effect
