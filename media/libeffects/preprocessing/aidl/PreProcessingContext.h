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

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>
#include <audio_processing.h>
#include <unordered_map>

#include "PreProcessingTypes.h"
#include "effect-impl/EffectContext.h"

namespace aidl::android::hardware::audio::effect {

enum PreProcEffectState {
    PRE_PROC_STATE_UNINITIALIZED,
    PRE_PROC_STATE_INITIALIZED,
    PRE_PROC_STATE_ACTIVE,
};

class PreProcessingContext final : public EffectContext {
  public:
    PreProcessingContext(int statusDepth, const Parameter::Common& common,
                         const PreProcessingEffectType& type)
        : EffectContext(statusDepth, common), mType(type) {
        LOG(DEBUG) << __func__ << type;
        mState = PRE_PROC_STATE_UNINITIALIZED;
    }
    ~PreProcessingContext() override { LOG(DEBUG) << __func__; }

    RetCode init(const Parameter::Common& common);
    RetCode deInit();

    PreProcessingEffectType getPreProcessingType() const { return mType; }

    RetCode enable();
    RetCode disable();

    RetCode setAcousticEchoCancelerEchoDelay(int echoDelayUs);
    int getAcousticEchoCancelerEchoDelay();
    RetCode setAcousticEchoCancelerMobileMode(bool mobileMode);
    bool getAcousticEchoCancelerMobileMode();

    RetCode setAutomaticGainControlDigitalGain(int gain);
    int getAutomaticGainControlDigitalGain();
    RetCode setAutomaticGainControlLevelEstimator(
            AutomaticGainControl::LevelEstimator levelEstimator);
    AutomaticGainControl::LevelEstimator getAutomaticGainControlLevelEstimator();
    RetCode setAutomaticGainControlSaturationMargin(int margin);
    int getAutomaticGainControlSaturationMargin();

    RetCode setNoiseSuppressionLevel(NoiseSuppression::Level level);
    NoiseSuppression::Level getNoiseSuppressionLevel();

    IEffect::Status lvmProcess(float* in, float* out, int samples);

  private:
    static constexpr inline int kAgcDefaultSaturationMargin = 2;
    static constexpr inline webrtc::AudioProcessing::Config::NoiseSuppression::Level
            kNsDefaultLevel = webrtc::AudioProcessing::Config::NoiseSuppression::kModerate;

    std::mutex mMutex;
    const PreProcessingEffectType mType;
    PreProcEffectState mState;  // current state

    // handle on webRTC audio processing module (APM)
    rtc::scoped_refptr<webrtc::AudioProcessing> mAudioProcessingModule;

    int mEnabledMsk;     // bit field containing IDs of enabled pre processors
    int mProcessedMsk;   // bit field containing IDs of pre processors already
                         // processed in current round
    int mRevEnabledMsk;  // bit field containing IDs of enabled pre processors with reverse channel
    int mRevProcessedMsk;  // bit field containing IDs of pre processors with reverse channel
                           // already processed in current round

    webrtc::StreamConfig mInputConfig;   // input stream configuration
    webrtc::StreamConfig mOutputConfig;  // output stream configuration

    // Acoustic Echo Canceler
    int mEchoDelayUs;
    bool mMobileMode;

    // Automatic Gain Control
    int mDigitalGain;

    // NoiseSuppression
    NoiseSuppression::Level mLevel;
};

}  // namespace aidl::android::hardware::audio::effect
