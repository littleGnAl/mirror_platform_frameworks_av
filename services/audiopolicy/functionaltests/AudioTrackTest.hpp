/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <system/audio_effect-base.h>
#include <media/AudioSystem.h>
#include <media/AudioEffect.h>
#include <media/TypeConverter.h>
#include <media/AudioTrack.h>
#include <string>
#include <iostream>
#include <vector>
#include <math.h>
#include <memory>
#include <map>
#include <condition_variable>

class AudioTrackTest
{
public:
    AudioTrackTest(audio_stream_type_t stream) : mStream(stream) {}

    AudioTrackTest(audio_stream_type_t stream, audio_port_handle_t explicitRoutingPortId) :
        mExplicitRoutingPortId(explicitRoutingPortId), mStream(stream) {}

    AudioTrackTest(android::product_strategy_t strategyId) : mProductStrategy(strategyId) {}

    AudioTrackTest(audio_port_handle_t explicitRoutingPortId) :
        mExplicitRoutingPortId(explicitRoutingPortId) {}

    AudioTrackTest(const audio_attributes_t &attributes) :
        mAudioAttributes(attributes) {}

    AudioTrackTest(
            const audio_attributes_t &attributes, audio_port_handle_t explicitRoutingPortId) :
        mExplicitRoutingPortId(explicitRoutingPortId),
        mAudioAttributes(attributes) {}

    /**
     * @brief playSine
     * @param routedPortId output param, effectively routed port for the AudioTrack
     * @return
     */
    android::status_t playSine(audio_port_handle_t &routedPortId/*, int playTimeMs*/);

    android::status_t stop();

    bool hasStarted() { return mAudioTrack == nullptr ? false : mAudioTrack->hasStarted(); }

    bool isPlaying() { return mAudioTrack == nullptr ? false : mAudioTrack->isPlaying(); }

    audio_port_handle_t getRoutedDeviceId() { return mRoutedPortId; }

    bool waitForDeviceCb(audio_port_handle_t expectedPortId = AUDIO_PORT_HANDLE_NONE);

    bool waitForNewIAudioTrack();

    android::status_t setVolume(float volume);

    android::status_t createTrack();

    audio_io_handle_t getOutput() const { return mOutput; }

    audio_session_t getSessionId() const {
        return mAudioTrack == nullptr ? AUDIO_SESSION_NONE : mAudioTrack->getSessionId();
    }

private:
    static void AudioPlaybackCallback(int event, void *user, void *info);

    class Context
    {
    public:
        Context() = default;

        size_t fillBuffer(int16_t *raw, size_t frameCount);

        std::condition_variable mInvalidateCondVar;

        void setIAudioTrackRecreated() { mNewIAudioTrackDetected = true; }
        bool isIAudioTrackRecreated() const { return mNewIAudioTrackDetected; }
        void reset() { mNewIAudioTrackDetected = false; }

        std::mutex mMutex;

    private:
        bool mNewIAudioTrackDetected = false;
        const uint32_t mSampleRate = 48000;
        const size_t mChannelCount = audio_channel_count_from_out_mask(AUDIO_CHANNEL_OUT_STEREO);
        const double mAmplitude = 10000;
        const uint32_t mFrequency = 1000;
        const double mPhase = 0.0;
        double mTime = 0.0;
        const double mDeltaTime = 1.0 / mSampleRate;
    };

    class AudioDeviceUpdatedNotifier: public android::AudioTrack::AudioDeviceCallback
    {
    public:
        AudioDeviceUpdatedNotifier(AudioTrackTest *parent) : mParent(parent) {}
        void onAudioDeviceUpdate(audio_io_handle_t audioIo, audio_port_handle_t deviceId) override;

        AudioTrackTest *mParent;
    };

    android::sp<AudioDeviceUpdatedNotifier> mAudioDeviceCallback;

    Context mContext;

    android::sp<android::AudioTrack> mAudioTrack;

    audio_io_handle_t mOutput = AUDIO_IO_HANDLE_NONE;

    audio_config_t mAudioConfig= {
        48000,
        AUDIO_CHANNEL_OUT_STEREO,
        AUDIO_FORMAT_PCM_16_BIT,
        AUDIO_INFO_INITIALIZER,
        0,
      };

    android::product_strategy_t mProductStrategy = android::PRODUCT_STRATEGY_NONE;

    audio_port_handle_t mExplicitRoutingPortId = AUDIO_PORT_HANDLE_NONE;
    audio_stream_type_t mStream = AUDIO_STREAM_DEFAULT;
    audio_attributes_t mAudioAttributes = {AUDIO_CONTENT_TYPE_MUSIC,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    const uint32_t mNbBuffers = 4;

    audio_port_handle_t mRoutedPortId = AUDIO_PORT_HANDLE_NONE;

    std::mutex mMutex;
    std::condition_variable mCondVar;
};
