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

#include <iostream>
#include <utils/Log.h>

#include "AudioRecordTest.hpp"
#include "Helper.hpp"

using namespace android;

size_t AudioRecordTest::emptyBuffer(int16_t *i16, size_t frameCount)
{
    if (mSndFile == 0) {
        return frameCount;
    }
    sf_count_t actualWritten = sf_writef_short(mSndFile.get(), i16, frameCount);
    if (actualWritten != static_cast<int>(frameCount)) {
        ALOGE("AudioRecord::dataCallback failed to output samples to file");
    }
    frameCount -= actualWritten;
    return frameCount;
}

/*static*/
void AudioRecordTest::AudioRecordCallback(int event, void *user, void *info) {
    switch (event) {
    case AudioRecord::EVENT_MORE_DATA: {
        AudioRecord::Buffer *buffer = (AudioRecord::Buffer *)info;

        IAudioRecordContext *context = (IAudioRecordContext *)user;
        buffer->frameCount = context->emptyBuffer(buffer->i16, buffer->frameCount);
        break;
    }
    case AudioRecord::EVENT_OVERRUN: {
        ALOGE("AudioRecord::dataCallback overrun reported");
        break;
    }
    default:
        // does nothing
        break;
    }
}

status_t AudioRecordTest::recordToFile(audio_port_handle_t &routedPortId,
                                       const std::string &filePath)
{
    SF_INFO sfinfo { 0, static_cast<int>(mAudioConfig.sample_rate),
                static_cast<int>(audio_channel_count_from_in_mask(mAudioConfig.channel_mask)),
                SF_FORMAT_WAV | SF_FORMAT_PCM_16 };

    mSndFile = sndFilePtr(sf_open(filePath.c_str(), SFM_WRITE, &sfinfo));
    if (mSndFile == nullptr) {
        ALOGE("AudioRecord::sndfile failed: ");
        return NO_INIT;
    }

    return record(routedPortId);
}

status_t AudioRecordTest::record(audio_port_handle_t &routedPortId)
{
    status_t status = mAudioRecord->start();
    if (status != OK) {
        ALOGE("AudioTrack::start failed: %d", status);
        stop();
        return status;
    }

    routedPortId = mAudioRecord->getRoutedDeviceId();
    audio_port_handle_t selectedDeviceId = mAudioRecord->getInputDevice();

    if (mExplicitRoutingPortId  != AUDIO_PORT_HANDLE_NONE &&
            mExplicitRoutingPortId != routedPortId) {
        ALOGE("AudioRecordTest::AudioPolicy did not satisfy you wish to use explicit routing on"
              " portId= %d, assigned %d", mExplicitRoutingPortId, routedPortId);
        mAudioRecord->stop();
        return BAD_TYPE;
    }
    if (selectedDeviceId != AUDIO_PORT_HANDLE_NONE) {
        ALOGD("AudioRecordTest::selected Device: %d, %s", selectedDeviceId,
              Helper::getPortInfo(selectedDeviceId).c_str());
    }
    ALOGD("AudioRecordTest::session Id: %d, routed Device: %d, %s", mAudioRecord->getSessionId(),
          routedPortId, Helper::getPortInfo(routedPortId).c_str());

    return OK;
}

status_t AudioRecordTest::stop()
{
    mAudioRecord->stop();
    std::unique_lock<std::mutex> lock(mMutex);
    mAudioRecord->removeAudioDeviceCallback(mAudioDeviceCallback);
    mAudioDeviceCallback->mParent = nullptr;
    mAudioRecord.clear();

    return OK;
}

bool AudioRecordTest::waitForDeviceCb()
{
    if (mAudioRecord == nullptr) {
        return false;
    }
    std::unique_lock<std::mutex> lock(mMutex);
    bool notimeOut = true;
    if (mInput == AUDIO_IO_HANDLE_NONE) {
        // Might wait for onAudioDeviceUpdate callback, frame it to 500 ms to avoid track threadloop
        // to detect a blocking
        notimeOut = mCondVar.wait_for(lock, std::chrono::milliseconds(500),
                                      [this](){ return mInput != AUDIO_PORT_HANDLE_NONE; });
    }
    return notimeOut;
}

void AudioRecordTest::AudioDeviceUpdatedNotifier::onAudioDeviceUpdate(
        audio_io_handle_t audioIo, audio_port_handle_t deviceId)
{
    if (mParent != nullptr) {
        {
            std::unique_lock<std::mutex> lock(mParent->mMutex);
            mParent->mInput = audioIo;
            mParent->mRoutedPortId = deviceId;
        }
        mParent->mCondVar.notify_one();
    }
}

status_t AudioRecordTest::createAudioRecord(const audio_config_t &audioConfig)
{
    status_t status;
    String16 opPackageName;
    size_t frames;

    mAudioConfig = audioConfig;
    mAudioConfig.sample_rate = 16000;
    mAudioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    mAudioConfig.channel_mask = AUDIO_CHANNEL_IN_STEREO;
    status = AudioRecord::getMinFrameCount(&frames,
                                           mAudioConfig.sample_rate,
                                           mAudioConfig.format,
                                           mAudioConfig.channel_mask);
    if (status != NO_ERROR) {
        ALOGE("AudioRecord::getMinFrameCount failed status=%d", status);
        return status;
    }
    mAudioConfig.frame_count = frames;

    mAudioRecord = new AudioRecord(opPackageName);

    mAudioDeviceCallback = new AudioDeviceUpdatedNotifier(this);
    status = mAudioRecord->addAudioDeviceCallback(mAudioDeviceCallback);
    if (status != OK) {
        ALOGE("AudioTrack::addAudioDeviceCallback failed: %d", status);
        return status;
    }

    mAudioRecord->set(mAudioAttributes.source,
                      mAudioConfig.sample_rate /* sampleRate*/,
                      mAudioConfig.format,
                      mAudioConfig.channel_mask,
                      /*size_t frameCount   =*/ mAudioConfig.frame_count * mNbBuffers,
                      AudioRecordCallback, // callback,
                      this, // callbackData,
                      mAudioConfig.frame_count, //notificationFrames,
                      false /*threadCanCallJava*/,
                      AUDIO_SESSION_ALLOCATE,
                      AudioRecord::transfer_type::TRANSFER_DEFAULT, //streamTransferType,
                      AUDIO_INPUT_FLAG_NONE, // flags
                      -1,//   int uid = -1,
                      -1,//   pid_t pid = -1,
                      &mAudioAttributes,//   const audio_attributes_t* pAttributes = nullptr
                      mExplicitRoutingPortId
                      );

#if 0
    if (portId != AUDIO_PORT_HANDLE_NONE) {
        // We can force explicit routing through this api, or use the set function
        status = mAudioRecord->setInputDevice(portId);
        if (status != OK) {
            Log::Error() << "AudioRecord::setInputDevice failed to set explicit routing " << status;
        } else {
            Log::Debug() << "AudioRecord::setInputDevice OK " << status;
        }
    }
#endif

    // Did we get a valid track?
    status = mAudioRecord->initCheck();
    if (status != OK) {
        ALOGE("AudioRecord::iniCheck failed: %d", status);
        return status;
    }
    return OK;
}
