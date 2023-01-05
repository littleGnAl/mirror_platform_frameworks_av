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

#pragma once

#include <android-base/thread_annotations.h>
#include <audio_effects/effect_dynamicsprocessing.h>

#include "effect-impl/EffectContext.h"

#include <cstddef>
#include <dsp/DPBase.h>
#include <dsp/DPFrequency.h>

namespace aidl::android::hardware::audio::effect {

enum DynamicsProcessingState {
    DYNAMICS_PROCESSING_STATE_UNINITIALIZED,
    DYNAMICS_PROCESSING_STATE_INITIALIZED,
    DYNAMICS_PROCESSING_STATE_ACTIVE,
};

class DynamicsProcessingContext final : public EffectContext {
  public:
    DynamicsProcessingContext(int statusDepth, const Parameter::Common& common);
    ~DynamicsProcessingContext();

    RetCode enable();
    RetCode disable();
    void reset();

    // override EffectContext::setCommon to update mChannelCount
    RetCode setCommon(const Parameter::Common& common) override;

    RetCode setEngineArchitecture(const DynamicsProcessing::EngineArchitecture& engineArchitecture);
    RetCode setPreEq(const std::vector<DynamicsProcessing::ChannelConfig>& eqChannels);
    RetCode setPostEq(const std::vector<DynamicsProcessing::ChannelConfig>& eqChannels);
    RetCode setPreEqBand(const std::vector<DynamicsProcessing::EqBandConfig>& eqBands);
    RetCode setPostEqBand(const std::vector<DynamicsProcessing::EqBandConfig>& eqBands);
    RetCode setMbc(const std::vector<DynamicsProcessing::ChannelConfig>& mbcChannels);
    RetCode setMbcBand(const std::vector<DynamicsProcessing::MbcBandConfig>& eqBands);
    RetCode setLimiter(const std::vector<DynamicsProcessing::LimiterConfig>& limiters);
    RetCode setInputGain(const std::vector<DynamicsProcessing::InputGain>& gain);

    DynamicsProcessing::EngineArchitecture getEngineArchitecture();
    std::vector<DynamicsProcessing::ChannelConfig> getPreEq();
    std::vector<DynamicsProcessing::ChannelConfig> getPostEq();
    std::vector<DynamicsProcessing::EqBandConfig> getPreEqBand();
    std::vector<DynamicsProcessing::EqBandConfig> getPostEqBand();
    std::vector<DynamicsProcessing::ChannelConfig> getMbc();
    std::vector<DynamicsProcessing::MbcBandConfig> getMbcBand();
    std::vector<DynamicsProcessing::LimiterConfig> getLimiter();
    std::vector<DynamicsProcessing::InputGain> getInputGain();

    IEffect::Status lvmProcess(float* in, float* out, int samples);

  private:
    static constexpr float kPreferredProcessingDurationMs = 10.0f;
    static constexpr int kBandCount = 5;
    std::mutex mMutex;
    size_t mChannelCount GUARDED_BY(mMutex) = 0;
    DynamicsProcessingState mState GUARDED_BY(mMutex) = DYNAMICS_PROCESSING_STATE_UNINITIALIZED;
    std::unique_ptr<dp_fx::DPFrequency> mDpFreq GUARDED_BY(mMutex) = nullptr;
    bool mEngineInited GUARDED_BY(mMutex) = false;
    DynamicsProcessing::EngineArchitecture mEngineArchitecture GUARDED_BY(mMutex) = {
            .resolutionPreference =
                    DynamicsProcessing::ResolutionPreference::FAVOR_FREQUENCY_RESOLUTION,
            .preferredProcessingDurationMs = kPreferredProcessingDurationMs,
            .preEqStage = {.inUse = true, .bandCount = kBandCount},
            .postEqStage = {.inUse = true, .bandCount = kBandCount},
            .mbcStage = {.inUse = true, .bandCount = kBandCount},
            .limiterInUse = true,
    };

    enum class StageType { PREEQ, POSTEQ, MBC, LIMITER };

    void init();

    void dpSetFreqDomainVariant_l(const DynamicsProcessing::EngineArchitecture& engine)
            REQUIRES(mMutex);
    dp_fx::DPChannel* getChannel_l(int32_t ch) REQUIRES(mMutex);
    dp_fx::DPEq* getPreEq_l(int32_t ch) REQUIRES(mMutex);
    dp_fx::DPEq* getPostEq_l(int32_t ch) REQUIRES(mMutex);
    dp_fx::DPMbc* getMbc_l(int32_t ch) REQUIRES(mMutex);
    dp_fx::DPLimiter* getLimiter_l(int32_t ch) REQUIRES(mMutex);
    dp_fx::DPBandStage* getStageWithType_l(StageType type, int32_t ch) REQUIRES(mMutex);
    dp_fx::DPEq* getEqWithType_l(StageType type, int32_t ch) REQUIRES(mMutex);

    std::vector<DynamicsProcessing::EqBandConfig> getEqBandConfigs(StageType type);
    std::vector<DynamicsProcessing::ChannelConfig> getChannelConfig(StageType type);

    bool validateStageEnablement(const DynamicsProcessing::StageEnablement& enablement);
    bool validateEngineConfig(const DynamicsProcessing::EngineArchitecture& engine);
    bool validateCutoffFrequency(float freq);
    bool validateEqBandConfig(const DynamicsProcessing::EqBandConfig& band, int maxChannel,
                              int maxBand);
    bool validateMbcBandConfig(const DynamicsProcessing::MbcBandConfig& band, int maxChannel,
                               int maxBand);
    bool validateLimiterConfig(const DynamicsProcessing::LimiterConfig& limiter, int maxChannel);
};

}  // namespace aidl::android::hardware::audio::effect