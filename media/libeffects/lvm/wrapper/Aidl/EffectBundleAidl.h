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

#pragma once
#include <functional>
#include <map>
#include <mutex>

#include <aidl/android/hardware/audio/effect/BnEffect.h>
#include <android-base/logging.h>

#include "effect-impl/EffectContext.h"
#include "effect-impl/EffectTypes.h"
#include "effect-impl/EffectUUID.h"
#include "effect-impl/EffectWorker.h"

#include "BundleTypes.h"
#include "GlobalSession.h"
#include "SessionContext.h"

namespace aidl::android::hardware::audio::effect {

class EffectBundleContext : public EffectContext {
  public:
    EffectBundleContext(int statusDepth, int inBufferSize, int outBufferSize,
                        std::shared_ptr<SessionContext> context)
        : EffectContext(statusDepth, inBufferSize, outBufferSize), mSessionContext(context) {
        LOG(DEBUG) << __func__;
        // initBundleContext();
    }

    void enableSession() {
        if (mSessionContext) {
            mSessionContext->enable();
        } else {
            LOG(ERROR) << __func__ << " null session context";
        }
    }
    void disableSession() {
        if (mSessionContext) {
            mSessionContext->disable();
        } else {
            LOG(ERROR) << __func__ << " null session context";
        }
    }

  private:
    // Session this bundle binding to.
    std::shared_ptr<SessionContext> mSessionContext;
    // Bundle context.
    std::shared_ptr<BundleContext> mBundleContext;
};

class EffectBundleAidl : public BnEffect, EffectWorker {
  public:
    EffectBundleAidl(const AudioUuid& uuid);
    ~EffectBundleAidl();

    ndk::ScopedAStatus open(const Parameter::Common& common, const Parameter::Specific& specific,
                            OpenEffectReturn* _aidl_return) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus getDescriptor(Descriptor* _aidl_return) override;

    ndk::ScopedAStatus getState(State* _aidl_return) override;
    ndk::ScopedAStatus command(CommandId in_commandId) override;
    ndk::ScopedAStatus setParameter(const Parameter& in_param) override;
    ndk::ScopedAStatus getParameter(const Parameter::Id& in_paramId,
                                    Parameter* _aidl_return) override;

    // override EffectWorker data processing function
    IEffect::Status effectProcessImpl(float *in, float *out, int frameCount) override;

    // Make sure only init Bundle once.
    static std::once_flag mInitFlag;

  private:
    static std::unique_ptr<GlobalSession> mGloalSession;

    BundleEffectType mType = BundleEffectType::EQUALIZER;
    const Descriptor* mDescriptor;

    // Instance state INIT by default.
    State mState = State::INIT;
    int mPreset = PRESET_CUSTOM;  // the current preset

    // Effect worker context
    std::shared_ptr<EffectBundleContext> mContext;


    ndk::ScopedAStatus parseCommonParameter(const Parameter::Common& common_param);
    ndk::ScopedAStatus setSpecificParameter(const Parameter::Specific& specific);
    ndk::ScopedAStatus getCommonParameter(Parameter::Tag tag, Parameter* parameter);

    void cleanUp();
    IEffect::Status status(binder_status_t status, size_t consumed, size_t produced);
};

}  // namespace aidl::android::hardware::audio::effect
