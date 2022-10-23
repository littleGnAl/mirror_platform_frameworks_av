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
    BundleContext(const int& sessionId, const BundleEffectType& type)
        : mSessionId(sessionId), mType(type) {
        LOG(DEBUG) << __func__ << type;
    }
    ~BundleContext() {
        LOG(DEBUG) << __func__;
        deInit();
    }

    RetCode init();
    void deInit();
    void update(const BundleEffectType& type) { mType = type; }
    int getSessionId() { return mSessionId; }

    void enable() { mEnablement = true; }
    void disable() { mEnablement = false; }

    void setCommonParameter(const Parameter::Common& common);
    Parameter::Common getCommonParameter() { return mCommon; }

    void setSampleRate(const int& sampleRate) { mSampleRate = sampleRate; }
    int getSampleRate() { return mSampleRate; }

    void setAudioMode(const aidl::android::media::audio::common::AudioMode& mode) { mMode = mode; }
    aidl::android::media::audio::common::AudioMode getAudioMode() { return mMode; }

    void setAudioSource(const aidl::android::media::audio::common::AudioSource& source) {
        mSource = source;
    }
    aidl::android::media::audio::common::AudioSource getAudioSource() { return mSource; }

    void setChMask(const aidl::android::media::audio::common::AudioChannelLayout& chMask) {
        mChMask = chMask;
    }
    aidl::android::media::audio::common::AudioChannelLayout getChMask() { return mChMask; }

    void setOutputDevice(const aidl::android::media::audio::common::AudioDeviceType& device) {
        mOutputDevice = device;
    }
    aidl::android::media::audio::common::AudioDeviceType getOutputDevice() { return mOutputDevice; }

    RetCode setVolume(const Parameter::VolumeStereo& volume);
    Parameter::VolumeStereo getVolume() { return mVolume; }

    RetCode setEqPreset(const int& presetIdx);
    int getEqPreset() { return mCurPresetIdx; }

    RetCode setEqBandLevels(const std::vector<Equalizer::BandLevel>& bandLevels);
    std::vector<Equalizer::BandLevel> getEqBandLevels();

  private:
    bool mEnablement = false;
    int mSessionId = INVALID_SESSION_ID;
    BundleEffectType mType;
    LVM_Handle_t mInstance = nullptr;
    Parameter::Common mCommon;
    aidl::android::media::audio::common::AudioDeviceType mOutputDevice;
    aidl::android::media::audio::common::AudioDeviceType mVirtualizerForcedDevice;
    aidl::android::media::audio::common::AudioChannelLayout mChMask;
    aidl::android::media::audio::common::AudioMode mMode;
    aidl::android::media::audio::common::AudioSource mSource;
    Parameter::VolumeStereo mVolume;

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
    int32_t mBandGaindB[FIVEBAND_NUMBANDS];
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

};

}  // namespace aidl::android::hardware::audio::effect

