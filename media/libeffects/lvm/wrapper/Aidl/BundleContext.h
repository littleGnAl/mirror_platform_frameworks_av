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

#include <android-base/logging.h>
#include <array>

#include "BundleTypes.h"
#include "effect-impl/EffectContext.h"

namespace aidl::android::hardware::audio::effect {

class BundleContext : public EffectContext {
  public:
    BundleContext(int statusDepth, const Parameter::Common& common, const BundleEffectType& type)
        : EffectContext(statusDepth, common), mType(type) {
        LOG(DEBUG) << __func__ << type;
    }
    ~BundleContext() {
        LOG(DEBUG) << __func__;
        deInit();
    }

    RetCode init();
    void deInit();
    BundleEffectType getBundleType() const { return mType; }

    RetCode enable();
    RetCode disable();

    LVM_Handle_t getLvmInstance() const { return mInstance; }

    void setSampleRate(const int& sampleRate) { mSampleRate = sampleRate; }
    int getSampleRate() { return mSampleRate; }

    void setChMask(const aidl::android::media::audio::common::AudioChannelLayout& chMask) {
        mChMask = chMask;
    }
    aidl::android::media::audio::common::AudioChannelLayout getChMask() { return mChMask; }

    RetCode setEqPreset(const int& presetIdx);
    int getEqPreset() { return mCurPresetIdx; }

    RetCode setEqBandLevels(const std::vector<Equalizer::BandLevel>& bandLevels);
    std::vector<Equalizer::BandLevel> getEqBandLevels();

    RetCode setVolumeStereo(const Parameter::VolumeStereo& volumeStereo) override;
    Parameter::VolumeStereo getVolumeStereo() override { return mVolumeStereo; };

  private:
    bool mEnabled = false;
    BundleEffectType mType;
    LVM_Handle_t mInstance = nullptr;

    aidl::android::media::audio::common::AudioDeviceDescription mVirtualizerForcedDevice;
    aidl::android::media::audio::common::AudioChannelLayout mChMask;

    int mSampleRate = LVM_FS_44100;
    int mSamplesPerSecond = 0;
    int mSamplesToExitCountEq = 0;
    int mSamplesToExitCountBb = 0;
    int mSamplesToExitCountVirt = 0;
    int mFrameCount = 0;

    /* Bitmask whether drain is in progress due to disabling the effect.
       The corresponding bit to an effect is set by 1 << lvm_effect_en. */
    int mEffectInDrain = 0;

    /* Bitmask whether process() was called for a particular effect.
       The corresponding bit to an effect is set by 1 << lvm_effect_en. */
    int mEffectProcessCalled = 0;
    int mNumberEffectsEnabled = 0;
    int mNumberEffectsCalled = 0;
    bool mFirstVolume = false;
    // Bass
    bool mBassTempDisabled = false;
    int mBassStrengthSaved = 0;
    // Equalizer
    int mCurPresetIdx = PRESET_CUSTOM; /* Current preset being used */
    std::array<int, FIVEBAND_NUMBANDS> mBandGaindB;
    // Virtualizer
    int mVirtStrengthSaved = 0; /* Conversion between Get/Set */
    bool mVirtualizerTempDisabled = false;
    // Volume
    int mLevelSaved = 0; /* for when mute is set, level must be saved */
    bool mMuteEnabled = false; /* Must store as mute = -96dB level */

    void initControlParameter(LVM_ControlParams_t& params);
    void initHeadroomParameter(LVM_HeadroomParams_t& params);
    int16_t VolToDb(uint32_t vol);
    LVM_INT16 LVC_ToDB_s32Tos16(LVM_INT32 Lin_fix);
    RetCode updateControlParameter(const std::vector<Equalizer::BandLevel>& bandLevels);
    bool isBandLevelIndexInRange(const std::vector<Equalizer::BandLevel>& bandLevels) const;
};

}  // namespace aidl::android::hardware::audio::effect

