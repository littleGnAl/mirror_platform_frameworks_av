/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <string>
#include <iostream>
#include <vector>
#include <math.h>
#include <memory>
#include <map>
#include <iostream>
#include <csignal>
#include <condition_variable>
#include <atomic>

#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <gtest/gtest.h>
#include "Helper.hpp"
#include "AudioVolumeTest.hpp"

using namespace android;

android::status_t AudioVolumeTest::registerAudioSystemCb()
{
    mAudioVolumeGroupCallback = new AudioVolumeGroupNotifier(this);
    return AudioSystem::addAudioVolumeGroupCallback(mAudioVolumeGroupCallback);
}

android::status_t AudioVolumeTest::unregisterAudioSystemCb()
{
    if (mAudioVolumeGroupCallback == nullptr) {
        return NO_ERROR;
    }
    return AudioSystem::removeAudioVolumeGroupCallback(mAudioVolumeGroupCallback);
}

AudioVolumeTest::~AudioVolumeTest()
{
    unregisterAudioSystemCb();
}

android::status_t AudioVolumeTest::setVolumeForAttributes(int volumeIndex,
                                                          const audio_attributes_t &attr,
                                                          volume_group_t expectedGroupId)
{
    std::unique_lock<std::mutex> lock(mMutex);
    status_t status =
            AudioSystem::setVolumeIndexForAttributes(attr, volumeIndex, AUDIO_DEVICE_OUT_SPEAKER);
    if (status != android::OK) {
        std::cerr << "AudioSystem::getVolumeIndexForAttributes failed: " << std::endl;
        return status;
    }
    mCondVar.wait_for(
                lock, std::chrono::milliseconds(10000),
                [this, &expectedGroupId](){ return mLastUpdatedGroup == expectedGroupId; });
    return NO_ERROR;
}

android::status_t AudioVolumeTest::setStreamVolume(int volumeIndex,
                                                   audio_stream_type_t stream,
                                                   android::volume_group_t expectedGroupId)
{
    std::unique_lock<std::mutex> lock(mMutex);
    status_t status =
            AudioSystem::setStreamVolumeIndex(stream, volumeIndex, AUDIO_DEVICE_OUT_SPEAKER);
    if (status != android::OK) {
        ALOGE("AudioSystem::setVolumeIndexForAttributes failed: %d", status);
        std::cerr << "AudioSystem::getVolumeIndexForAttributes failed: " << std::endl;
        return status;
    }
    // @todo check of group changed...
    mCondVar.wait_for(
                lock, std::chrono::milliseconds(10000),
                [this, &expectedGroupId](){ return mLastUpdatedGroup == expectedGroupId; });
    return NO_ERROR;
}

void AudioVolumeTest::AudioVolumeGroupNotifier::onAudioVolumeGroupChanged(volume_group_t group,
                                                                          int flags)
{
   std::cerr << "AudioVolumeGroupNotifier::onAudioVolumeGroupChanged Group:" << group
             << ", flags=" << flags << std::endl;
   {
       std::unique_lock<std::mutex> lock(mParent->mMutex);
       mParent->mLastUpdatedGroup = group;
   }
   mParent->mCondVar.notify_one();
}

void AudioVolumeTest::AudioVolumeGroupNotifier::onServiceDied()
{
    std::cerr << "AudioVolumeGroupNotifier::onServiceDied" << std::endl;
}





