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

#include <media/AudioSystem.h>
#include <media/TypeConverter.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <condition_variable>
#include <iostream>
#include <math.h>
#include <memory>
#include <string>

class AudioVolumeTest
{
public:
    AudioVolumeTest() = default;
    ~AudioVolumeTest();

    android::status_t registerAudioSystemCb();

    android::status_t unregisterAudioSystemCb();

    android::status_t setVolumeForAttributes(int volumeIndex,
                                             const audio_attributes_t &attr,
                                             android::volume_group_t expectedGroupId);
private:
    class AudioVolumeGroupNotifier: public android::AudioSystem::AudioVolumeGroupCallback
    {
    public:
        AudioVolumeGroupNotifier(AudioVolumeTest *parent) : mParent(parent) {}

        void onAudioVolumeGroupChanged(android::volume_group_t group, int flags) override;
        void onServiceDied() override;

        AudioVolumeTest *mParent;
    };

    android::sp<AudioVolumeGroupNotifier> mAudioVolumeGroupCallback;

    android::volume_group_t mLastUpdatedGroup;
    std::mutex mMutex;
    std::condition_variable mCondVar;
};
