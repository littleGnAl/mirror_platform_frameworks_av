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

#include <audio_utils/sndfile.h>
#include <media/AudioSystem.h>
#include <media/AudioRecord.h>

struct SndFileCloser
{
    void operator()(void *sfHandle) const noexcept { sf_close((SNDFILE *)sfHandle); }
};

using sndFilePtr = std::unique_ptr<SNDFILE, SndFileCloser>;

class IAudioRecordContext
{
public:
    virtual ~IAudioRecordContext() = default;
    virtual size_t emptyBuffer(int16_t *raw, size_t frameCount) = 0;
};

class AudioRecordTest : public IAudioRecordContext
{
public:
    AudioRecordTest(audio_port_handle_t explicitRoutingPortId) :
        mExplicitRoutingPortId(explicitRoutingPortId) {}

    AudioRecordTest(const audio_attributes_t &attributes,
                    audio_port_handle_t explicitRoutingPortId) :
        mExplicitRoutingPortId(explicitRoutingPortId), mAudioAttributes(attributes) {}

    AudioRecordTest(const audio_attributes_t &attributes) :
        mAudioAttributes(attributes) {}

    android::status_t record(audio_port_handle_t &routedPortId);

    android::status_t recordToFile(audio_port_handle_t &routedPortId, const std::string &filePath);

    android::status_t stop();

    android::status_t createAudioRecord(
            const audio_config_t &audioConfig = AUDIO_CONFIG_INITIALIZER);

    bool waitForDeviceCb();

    audio_port_handle_t getRoutedDeviceId() { return mRoutedPortId; }

    audio_io_handle_t getInput() { return mInput; }

    audio_session_t getSessionId() const {
        return mAudioRecord == nullptr ? AUDIO_SESSION_NONE : mAudioRecord->getSessionId();
    }

private:
    class AudioDeviceUpdatedNotifier: public android::AudioRecord::AudioDeviceCallback
    {
    public:
        AudioDeviceUpdatedNotifier(AudioRecordTest *parent) : mParent(parent) {}
        void onAudioDeviceUpdate(audio_io_handle_t audioIo, audio_port_handle_t deviceId) override;

        AudioRecordTest *mParent;
    };

    android::sp<AudioDeviceUpdatedNotifier> mAudioDeviceCallback;

    size_t emptyBuffer(int16_t *i16, size_t frameCount) override;

    static void AudioRecordCallback(int event, void *user, void *info);

    android::sp<android::AudioRecord> mAudioRecord;

    sndFilePtr mSndFile;

    audio_port_handle_t mExplicitRoutingPortId = AUDIO_PORT_HANDLE_NONE;
    const uint32_t mNbBuffers = 4;

    audio_config_t mAudioConfig;

    audio_attributes_t mAudioAttributes = {AUDIO_CONTENT_TYPE_UNKNOWN,
                                           AUDIO_USAGE_UNKNOWN,
                                           AUDIO_SOURCE_MIC, AUDIO_FLAG_NONE, ""};

    audio_port_handle_t mRoutedPortId = AUDIO_PORT_HANDLE_NONE;

    audio_io_handle_t mInput = AUDIO_IO_HANDLE_NONE;

    std::mutex mMutex;
    std::condition_variable mCondVar;
};
