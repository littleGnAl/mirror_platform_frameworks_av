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

#include <audio_effects/effect_downmix.h>
#include <audio_utils/ChannelMix.h>

namespace aidl::android::hardware::audio::effect {

using aidl::android::hardware::audio::effect::kDownmixImplUUID;
using aidl::android::hardware::audio::effect::kDownmixTypeUUID;
using ::android::hardware::audio::common::getChannelCount;
using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioDeviceDescription;

enum DownmixState {
    DOWNMIX_STATE_UNINITIALIZED,
    DOWNMIX_STATE_INITIALIZED,
    DOWNMIX_STATE_ACTIVE,
};

class DownmixContext final : public EffectContext {
  public:
    DownmixContext(int statusDepth, const Parameter::Common& common)
        : EffectContext(statusDepth, common) {
        LOG(DEBUG) << __func__;
        mState = DOWNMIX_STATE_UNINITIALIZED;
        init_params(common);
    }
    ~DownmixContext() {
        LOG(DEBUG) << __func__;
        mState = DOWNMIX_STATE_UNINITIALIZED;
    }
    RetCode enable() {
        if (mState != DOWNMIX_STATE_INITIALIZED) {
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }
        mState = DOWNMIX_STATE_ACTIVE;
        return RetCode::SUCCESS;
    }
    RetCode disable() {
        if (mState != DOWNMIX_STATE_ACTIVE) {
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }
        mState = DOWNMIX_STATE_INITIALIZED;
        return RetCode::SUCCESS;
    }
    void reset() {
        disable();
        resetBuffer();
    }

    RetCode setDmType(Downmix::Type type) {
        // TODO : Add implementation to apply new gain
        mType = type;
        return RetCode::SUCCESS;
    }
    Downmix::Type getDmType() const { return mType; }

    RetCode setVolumeStereo(const Parameter::VolumeStereo& volumeStereo) override {
        // FIXME change volume
        mVolumeStereo = volumeStereo;
        return RetCode::SUCCESS;
    }
    Parameter::VolumeStereo getVolumeStereo() override { return mVolumeStereo; }

    RetCode setOutputDevice(
            const aidl::android::media::audio::common::AudioDeviceDescription& device) override {
        // FIXME change type if playing on headset vs speaker
        mOutputDevice = device;
        return RetCode::SUCCESS;
    }
    aidl::android::media::audio::common::AudioDeviceDescription getOutputDevice() {
        return mOutputDevice;
    }

    IEffect::Status lvmProcess(float* in, float* out, int samples) {
        LOG(DEBUG) << __func__ << " in " << in << " out " << out << " sample " << samples;
        IEffect::Status status = {EX_ILLEGAL_ARGUMENT, 0, 0};

        if (in == nullptr || out == nullptr || getInputFrameSize() != getOutputFrameSize() ||
            getInputFrameSize() == 0) {
            return status;
        }

        status = {EX_ILLEGAL_STATE, 0, 0};
        if (mState == DOWNMIX_STATE_UNINITIALIZED) {
            LOG(ERROR) << __func__ << "Trying to use an uninitialized downmixer";
            return status;
        } else if (mState == DOWNMIX_STATE_INITIALIZED) {
            LOG(ERROR) << __func__ << "Trying to use a non-configured downmixer";
            return status;
        }

        LOG(DEBUG) << __func__ << " start processing";
        bool accumulate = false;
        int frames = samples * sizeof(float) / getInputFrameSize();
        if (mType == Downmix::Type::STRIP) {
            int inputChannelCount = getChannelCount(mChMask);
            while (frames) {
                if (accumulate) {
                    out[0] = clamp_float(out[0] + in[0]);
                    out[1] = clamp_float(out[1] + in[1]);
                } else {
                    out[0] = in[0];
                    out[1] = in[1];
                }
                in += inputChannelCount;
                out += 2;
                frames--;
            }
        } else {
            int chMask = mChMask.get<AudioChannelLayout::layoutMask>();
            if (!mChannelMix.process(in, out, frames, accumulate, (audio_channel_mask_t)chMask)) {
                LOG(ERROR) << "Multichannel configuration " << mChMask.toString()
                           << " is not supported";
                return status;
            }
        }
        LOG(DEBUG) << __func__ << " done processing";
        return {STATUS_OK, samples, samples};
    }

  private:
    DownmixState mState;
    Downmix::Type mType;
    AudioChannelLayout mChMask;
    ::android::audio_utils::channels::ChannelMix mChannelMix;
    AudioDeviceDescription mOutputDevice;
    Parameter::VolumeStereo mVolumeStereo;

    void init_params(const Parameter::Common& common) {
        // when configuring the effect, do not allow a blank or unsupported channel mask
        AudioChannelLayout channelMask = common.input.base.channelMask;
        if (isChannelMaskValid(channelMask)) {
            LOG(ERROR) << "Downmix_Configure error: input channel mask " << channelMask.toString()
                       << " not supported";
        } else {
            mType = Downmix::Type::FOLD;
            mChMask = channelMask;
            mState = DOWNMIX_STATE_INITIALIZED;
        }
    }

    bool isChannelMaskValid(AudioChannelLayout channelMask) {
        if (channelMask.getTag() == AudioChannelLayout::layoutMask) return false;
        int chMask = channelMask.get<AudioChannelLayout::layoutMask>();
        // check against unsupported channels (up to FCC_26)
        constexpr uint32_t MAXIMUM_CHANNEL_MASK = AudioChannelLayout::LAYOUT_22POINT2 |
                                                  AudioChannelLayout::CHANNEL_FRONT_WIDE_LEFT |
                                                  AudioChannelLayout::CHANNEL_FRONT_WIDE_RIGHT;
        if (chMask & ~MAXIMUM_CHANNEL_MASK) {
            LOG(ERROR) << "Unsupported channels in " << (chMask & ~MAXIMUM_CHANNEL_MASK);
            return false;
        }
        return true;
    }

    static inline float clamp_float(float value) { return fmin(fmax(value, -1.f), 1.f); }
};

class DownmixImpl final : public EffectImpl {
  public:
    static const std::string kEffectName;
    static const Descriptor kDescriptor;
    DownmixImpl() { LOG(DEBUG) << __func__; }
    ~DownmixImpl() {
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
    std::shared_ptr<DownmixContext> mContext;
    ndk::ScopedAStatus getParameterDownmix(const Downmix::Tag& tag, Parameter::Specific* specific);
};
}  // namespace aidl::android::hardware::audio::effect
