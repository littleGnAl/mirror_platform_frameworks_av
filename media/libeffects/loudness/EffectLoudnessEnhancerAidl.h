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

#include <aidl/android/hardware/audio/effect/BnEffect.h>

#include "effect-impl/EffectImpl.h"
#include "effect-impl/EffectUUID.h"

#include <audio_effects/effect_loudnessenhancer.h>
#include "dsp/core/dynamic_range_compression.h"

namespace aidl::android::hardware::audio::effect {

using aidl::android::hardware::audio::effect::kLoudnessEnhancerImplUUID;
using aidl::android::hardware::audio::effect::kLoudnessEnhancerTypeUUID;

enum LoudnessEnhancerState {
    LOUDNESS_ENHANCER_STATE_UNINITIALIZED,
    LOUDNESS_ENHANCER_STATE_INITIALIZED,
    LOUDNESS_ENHANCER_STATE_ACTIVE,
};

class LoudnessEnhancerContext final : public EffectContext {
  public:
    LoudnessEnhancerContext(int statusDepth, const Parameter::Common& common)
        : EffectContext(statusDepth, common) {
        LOG(DEBUG) << __func__;
        mState = LOUDNESS_ENHANCER_STATE_UNINITIALIZED;
        mSampleRate = common.input.base.sampleRate;
        init_params();
    }
    ~LoudnessEnhancerContext() {
        LOG(DEBUG) << __func__;
        mState = LOUDNESS_ENHANCER_STATE_UNINITIALIZED;
        if (mCompressor != NULL) {
            delete mCompressor;
            mCompressor = NULL;
        }
    }
    RetCode enable() {
        if (mState != LOUDNESS_ENHANCER_STATE_INITIALIZED) {
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }
        mState = LOUDNESS_ENHANCER_STATE_ACTIVE;
        return RetCode::SUCCESS;
    }
    RetCode disable() {
        if (mState != LOUDNESS_ENHANCER_STATE_ACTIVE) {
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }
        mState = LOUDNESS_ENHANCER_STATE_INITIALIZED;
        return RetCode::SUCCESS;
    }
    void reset() {
        float targetAmp = pow(10, mGain / 2000.0f);  // mB to linear amplification
        if (mCompressor != NULL) {
            // Get samplingRate from input
            mCompressor->Initialize(targetAmp, mSampleRate);
        }
        resetBuffer();
    }
    void compress(float* x1, float* x2) {
        if (mCompressor != NULL) {
            mCompressor->Compress(x1, x2);
        }
    }

    RetCode setLeGain(int gainMb) {
        // TODO : Add implementation to apply new gain
        mGain = gainMb;
        return RetCode::SUCCESS;
    }
    int getLeGain() const { return mGain; }

  private:
    // LVM_Handle_t mInstance = nullptr;
    LoudnessEnhancerState mState;
    int mSampleRate = 44100;
    int mGain = 0;  // Default Gain
    // In this implementation, there is no coupling between the compression on the left and right
    // channels
    le_fx::AdaptiveDynamicRangeCompression* mCompressor;

    void init_params() {
        mGain = LOUDNESS_ENHANCER_DEFAULT_TARGET_GAIN_MB;
        float targetAmp = pow(10, mGain / 2000.0f);  // mB to linear amplification
        LOG(DEBUG) << __func__ << "Target gain = " << mGain << "mB <=> factor = " << targetAmp;

        mCompressor = new le_fx::AdaptiveDynamicRangeCompression();
        mCompressor->Initialize(targetAmp, mSampleRate);
        mState = LOUDNESS_ENHANCER_STATE_INITIALIZED;
    }
};

class LoudnessEnhancerImpl final : public EffectImpl {
  public:
    LoudnessEnhancerImpl() { LOG(DEBUG) << __func__; }
    ~LoudnessEnhancerImpl() {
        cleanUp();
        LOG(DEBUG) << __func__;
    }

    ndk::ScopedAStatus commandImpl(CommandId command) override;
    ndk::ScopedAStatus getDescriptor(Descriptor* _aidl_return) override;
    ndk::ScopedAStatus setParameterSpecific(const Parameter::Specific& specific) override;
    ndk::ScopedAStatus getParameterSpecific(const Parameter::Id& id,
                                            Parameter::Specific* specific) override;
    IEffect::Status effectProcessImpl(float* in, float* out, int process) override;
    std::shared_ptr<EffectContext> createContext(const Parameter::Common& common) override;
    RetCode releaseContext() override;

    std::shared_ptr<EffectContext> getContext() override { return mContext; }
    std::string getEffectName() override { return kEffectName; }

  private:
    std::shared_ptr<LoudnessEnhancerContext> mContext;
    /* Effect Name */
    const std::string kEffectName = "Loudness Enhancer";
    /* capabilities */
    const LoudnessEnhancer::Capability kCapability;
    /* Effect descriptor */
    const Descriptor kLoudnessEnhancerDesc = {
            .common = {.id = {.type = kLoudnessEnhancerTypeUUID,
                              .uuid = kLoudnessEnhancerImplUUID,
                              .proxy = std::nullopt},
                       .flags = {.type = Flags::Type::INSERT, .insert = Flags::Insert::FIRST},
                       .name = kEffectName,
                       .implementor = "The Android Open Source Project"},
            .capability = Capability::make<Capability::loudnessEnhancer>(kCapability)};

    ndk::ScopedAStatus getParameterLoudnessEnhancer(const LoudnessEnhancer::Tag& tag,
                                                    Parameter::Specific* specific);
};
}  // namespace aidl::android::hardware::audio::effect
