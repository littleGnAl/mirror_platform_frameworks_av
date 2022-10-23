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

#include "BundleTypes.h"

namespace aidl::android::hardware::audio::effect {

class BundleContext {
  public:
    BundleContext(const Parameter::Common& common, const Parameter::Specific& specific) {
      LOG(DEBUG) << __func__;
      update(common, specific);
    }
    ~BundleContext() { LOG(DEBUG) << __func__; }

    void update(const Parameter::Common& common, const Parameter::Specific& specific) {
        mSampleRate = common.input.base.sampleRate;
        mChMask = common.input.base.channelMask;
        auto tag = specific.getTag();
        if (tag == Parameter::Specific::equalizer) {
          auto& eq = specific.get<Parameter::Specific::equalizer>();
          auto eqTag = eq.getTag();
          switch (eqTag) {
            case Equalizer::preset: {
              mCurPreset = eq.get<Equalizer::preset>();
              break;
            }
            case Equalizer::bandLevels: {
              updateBandLevels(eq.get<Equalizer::bandLevels>());
              break;
            }
            default:
              break;
          }
        } else {
          // TODO: add other bundle type
        }
    }
    void setOutputDevice(const aidl::android::media::audio::common::AudioDeviceType& device) {
        mOutputDevice = device;
    }
    void setEqPreset(const int preset) { mCurPreset = preset; }
    void updateBandLevels(const std::vector<Equalizer::BandLevel>& bandLevels) {
      for (auto& it : bandLevels) {
        if (it.index >= FIVEBAND_NUMBANDS) {
          LOG(ERROR) << __func__ << " index illegal, skip: " << it.index << " - " << it.level;
          continue;
        }
        mBandGaindB[it.index] = it.level;
      }
    }

    void init() {
      mBassTempDisabled = false;
      mVirtualizerTempDisabled = false;
      mOutputDevice = aidl::android::media::audio::common::AudioDeviceType::NONE;
      mVirtualizerForcedDevice = aidl::android::media::audio::common::AudioDeviceType::NONE;
      mNumberEffectsEnabled = 0;
      mNumberEffectsCalled = 0;
      mFirstVolume = true;
      mBassStrengthSaved = 0;
      mCurPreset = PRESET_CUSTOM;
      mVirtStrengthSaved = 0;
      mLevelSaved = 0;
      mMuteEnabled = false;
      mSampleRate = LVM_FS_44100;
      mSamplesPerSecond = 0;
      mSamplesToExitCountEq = 0;
      mSamplesToExitCountBb = 0;
      mSamplesToExitCountVirt = 0;
      mFrameCount = -1;
      mVolume = 0;
      mEffectInDrain = 0;
      mEffectProcessCalled = 0;
      for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
        mBandGaindB[i] = EQNB_5BandSoftPresets[i];
      }
    }

  private:
    bool mBassTempDisabled;
    bool mVirtualizerTempDisabled;
    aidl::android::media::audio::common::AudioDeviceType mOutputDevice;
    aidl::android::media::audio::common::AudioDeviceType mVirtualizerForcedDevice;
    int mNumberEffectsEnabled;
    int mNumberEffectsCalled;
    bool mFirstVolume;
    int mBassStrengthSaved;
    // Equalizer
    int mCurPreset; /* Current preset being used */
    // Virtualzer
    int mVirtStrengthSaved; /* Conversion between Get/Set */
    // Volume
    int mLevelSaved; /* for when mute is set, level must be saved */
    bool mMuteEnabled; /* Must store as mute = -96dB level */

    int mSampleRate;
    int mSamplesPerSecond;
    int mSamplesToExitCountEq;
    int mSamplesToExitCountBb;
    int mSamplesToExitCountVirt;
    int mFrameCount;
    int32_t mBandGaindB[FIVEBAND_NUMBANDS];
    int mVolume;
    aidl::android::media::audio::common::AudioChannelLayout mChMask;

    /* Bitmask whether drain is in progress due to disabling the effect.
       The corresponding bit to an effect is set by 1 << lvm_effect_en. */
    int mEffectInDrain;

    /* Bitmask whether process() was called for a particular effect.
       The corresponding bit to an effect is set by 1 << lvm_effect_en. */
    int mEffectProcessCalled;
};
}  // namespace aidl::android::hardware::audio::effect

