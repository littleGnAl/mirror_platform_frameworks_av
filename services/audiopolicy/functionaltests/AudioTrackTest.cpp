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

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <iostream>

#include <media/AudioCommonTypes.h>
#include <utils/Log.h>

#include "policy.h"

#include "AudioTrackTest.hpp"
#include "Helper.hpp"

using namespace android;

/*static*/
void AudioTrackTest::AudioPlaybackCallback(int event, void *user, void *info) {
    Context *ctx = static_cast<Context *>(user);
    switch (event) {
    case AudioTrack::EVENT_MORE_DATA:
    {
        AudioTrack::Buffer *buffer = (AudioTrack::Buffer *)info;
        size_t numBytesWritten = ctx->fillBuffer(buffer->i16, buffer->frameCount);
        buffer->size = numBytesWritten;
    }
        break;

    case AudioTrack::EVENT_STREAM_END:
        break;

    case AudioTrack::EVENT_NEW_IAUDIOTRACK:
        ALOGE("%s: EVENT_NEW_IAUDIOTRACK", __func__);
        {
            std::unique_lock<std::mutex> lock(ctx->mMutex);
            ctx->setIAudioTrackRecreated();
        }
        ctx->mInvalidateCondVar.notify_one();
        break;
    default:
        ALOGE("%s: event %d", __func__, event);
        break;
    }
}

bool AudioTrackTest::waitForNewIAudioTrack()
{
    if (mAudioTrack == nullptr) {
        return false;
    }
    std::unique_lock<std::mutex> lock(mContext.mMutex);
    if (mContext.isIAudioTrackRecreated()) {
        mContext.reset();
        return true;
    }
    auto timeout = mContext.mInvalidateCondVar.wait_for(lock, std::chrono::milliseconds(250));
    mContext.reset();
    return timeout != std::cv_status::timeout;
}

size_t AudioTrackTest::Context::fillBuffer(int16_t *raw, size_t frameCount)
{
    if (mTime >= std::numeric_limits<float>::max()) {
        mTime = 0.0;
    }
    for (uint32_t sample = 0; sample < frameCount; ++sample) {
        double value = mAmplitude * sin(2 * M_PI * mFrequency * mTime + mPhase);
        mTime += mDeltaTime;

        for (uint32_t channel = 0; channel < mChannelCount; channel++) {
            raw[sample + channel] = value;
        }
    }
    return mChannelCount * frameCount * 2;
}

bool AudioTrackTest::waitForDeviceCb(audio_port_handle_t expectedPortId)
{
    if (mAudioTrack == nullptr) {
        return false;
    }
    std::unique_lock<std::mutex> lock(mMutex);
    bool notimeOut = true;
    std::cerr << __func__ << " mOutput="  << mOutput << ", expectedPortId=" << expectedPortId << " mRoutedPortId=" << mAudioTrack->getRoutedDeviceId() << std::endl;
    mRoutedPortId = mAudioTrack->getRoutedDeviceId();
    if (mOutput == AUDIO_IO_HANDLE_NONE ||
            (expectedPortId != AUDIO_PORT_HANDLE_NONE && mRoutedPortId != expectedPortId)) {
        // Might wait for onAudioDeviceUpdate callback, frame it to 500 ms to avoid track threadloop
        // to detect a blocking
        std::cerr << __func__ << "WAITING mOutput="  << mOutput << ", expectedPortId=" << expectedPortId << " mRoutedPortId=" << mAudioTrack->getRoutedDeviceId() << std::endl;
        notimeOut = mCondVar.wait_for(lock, std::chrono::seconds(1),
                                      [this, &expectedPortId](){
            if (expectedPortId != AUDIO_PORT_HANDLE_NONE) {
                std::cerr << __func__ << " WAIT DONE mOutput="  << mOutput << ", expectedPortId=" << expectedPortId << " mRoutedPortId=" << mAudioTrack->getRoutedDeviceId() << std::endl;
                return mRoutedPortId == expectedPortId && mOutput != AUDIO_PORT_HANDLE_NONE;
            }
            return mOutput != AUDIO_PORT_HANDLE_NONE;
        });
    }
    return notimeOut;
}

status_t AudioTrackTest::playSine(audio_port_handle_t &routedPortId/*, int playTimeMs*/)
{
    status_t status = mAudioTrack->start();
    if (status != OK) {
        ALOGE("AudioTrack::start failed: %d", status);
        stop();
        return status;
    }
    while (!mAudioTrack->hasStarted()) {
        usleep(100);
    }
    routedPortId = mRoutedPortId;
    audio_port_handle_t selectedDeviceId = mAudioTrack->getOutputDevice();

    if (mExplicitRoutingPortId  != AUDIO_PORT_HANDLE_NONE &&
            mExplicitRoutingPortId != routedPortId) {
        ALOGE("AudioTrack::AudioPolicy did not satisfy you wish to use explicit routing on"
              " portId=%d, assigned %d", mExplicitRoutingPortId, routedPortId);
    }
    if (selectedDeviceId != AUDIO_PORT_HANDLE_NONE) {
        ALOGE("AudioTrack::selected Device: %d, %s",selectedDeviceId,
              Helper::getPortInfo(selectedDeviceId).c_str());
    }
    ALOGD("AudioTrack::session Id: %d, routed Device: %d, %s ",mAudioTrack->getSessionId(),
          routedPortId, Helper::getPortInfo(routedPortId).c_str());

    // Necessary to avoid a race condition leading to removing an active client.
    while (!mAudioTrack->isPlaying()) {
        usleep(50);
    }
    return OK;
}

status_t AudioTrackTest::stop()
{
    if (mAudioTrack == nullptr) {
        return NO_INIT;
    }
    mAudioTrack->stop();
    mAudioTrack->flush();

    while (mAudioTrack->isPlaying() || !mAudioTrack->stopped()) {
        usleep(50);
    }
    std::unique_lock<std::mutex> lock(mMutex);
    mAudioTrack->removeAudioDeviceCallback(mAudioDeviceCallback);
    mAudioDeviceCallback->mParent = nullptr;
    mAudioTrack.clear();
    return OK;
}

void AudioTrackTest::AudioDeviceUpdatedNotifier::onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                                                     audio_port_handle_t deviceId)
{
    ALOGD("%s  audioIo=%d deviceId=%d", __func__, audioIo, deviceId);
    std::cerr << __func__ << " audioIo=" << audioIo << " deviceId=" << deviceId << std::endl;
    if (mParent != nullptr) {
        if (audioIo == mParent->mOutput && deviceId == mParent->mRoutedPortId) {
            ALOGD("%s same output %d and device %d", __func__, audioIo, deviceId);
            std::cerr << __func__ << " same output audioIo=" << audioIo << " and deviceId=" << deviceId << std::endl;
            return;
        }
        {
            std::unique_lock<std::mutex> lock(mParent->mMutex);
            if (audioIo != mParent->mOutput) {
                mParent->mOutput = audioIo;
                std::cerr << __func__ << " new audioIo=" << audioIo << std::endl;
            }
            if (deviceId != mParent->mRoutedPortId && deviceId != AUDIO_PORT_HANDLE_NONE) {
                std::cerr << __func__ << " new deviceId=" << deviceId << std::endl;
                ALOGE("AudioTrackTest::onAudioDeviceUpdate \n"
                      "selected Device id: %d, info: %s, \n"
                      "original Routed Port=%s",
                      deviceId, Helper::getPortInfo(deviceId).c_str(),
                      Helper::getPortInfo(mParent->mRoutedPortId).c_str());
                mParent->mRoutedPortId = deviceId;
            }
        }
        mParent->mCondVar.notify_one();
    }
}

status_t AudioTrackTest::createTrack()
{
    status_t status;
    size_t frames;
    if (AudioTrack::getMinFrameCount(&frames, mStream, 48000) != NO_ERROR) {
        ALOGE("AudioTrack::getMinFrameCount failed: ");
        std::cerr << "AudioTrack::getMinFrameCount failed: " << std::endl;
        return NO_INIT;
    }
    mAudioConfig.frame_count = frames;
    ALOGD("AudioTrack::getMinFrameCount output: %zu", frames);

    mAudioTrack = new AudioTrack();

    mAudioDeviceCallback = new AudioDeviceUpdatedNotifier(this);
    status = mAudioTrack->addAudioDeviceCallback(mAudioDeviceCallback);
    if (status != OK) {
        ALOGE("AudioTrack::addAudioDeviceCallback failed: %d", status);
        return status;
    }

    audio_attributes_t *attributes = mStream != AUDIO_STREAM_DEFAULT ? nullptr : &mAudioAttributes;

    if (mProductStrategy != PRODUCT_STRATEGY_NONE) {
        AudioProductStrategyVector strategies;
        status_t ret = AudioSystem::listAudioProductStrategies(strategies);
        if (ret != NO_ERROR) {
            std::cerr << "AudioSystem::listAudioProductStrategies() failed: " << ret << std::endl;
            return ret;
        }
        for (const auto &strategy : strategies) {
            if (strategy.getId() == mProductStrategy) {
                auto attrVect = strategy.getAudioAttributes();
                mStream = attrVect.front().getStreamType();
                mAudioAttributes = attrVect.front().getAttributes();
                std::cout << "createTrack for strategy: " << strategy.getName()
                          << " with stream= " << toString(mStream)
                          << ", attributes= " << toString(mAudioAttributes) << std::endl;

                attributes =
                        (mAudioAttributes == defaultAttr) ? nullptr : &mAudioAttributes;

                if (attributes == nullptr && (uint32_t(mStream) >= AUDIO_STREAM_PUBLIC_CNT)) {
                    // Native AudioTrack will prevent us to create the track.
                    std::cerr << "Strategy " << strategy.getName() << " has invalid attributes "
                              << "and non-public stream " << toString(mStream)
                              << std::endl;
                    return BAD_VALUE;
                }
            }
        }
    } else {
        if (attributes == nullptr) {
            attributes = (audio_attributes_t *) calloc(1, sizeof(audio_attributes_t));
            *attributes = AudioSystem::streamTypeToAttributes(mStream);
            std::cerr << "translating stream " << toString(mStream)
                      << " to attributes " << toString(*attributes) << std::endl;
        }
        if (mStream == AUDIO_STREAM_DEFAULT) {
            mStream = AudioSystem::attributesToStreamType(*attributes);
        }
    }
    status = mAudioTrack->set(mStream,
                              mAudioConfig.sample_rate /* sampleRate*/,
                              mAudioConfig.format,
                              mAudioConfig.channel_mask,
                              /*size_t frameCount   =*/ mAudioConfig.frame_count * mNbBuffers,
                              /*audio_output_flags_t flags = */AUDIO_OUTPUT_FLAG_NONE,
                              /*callback_t cbf      = */ &AudioPlaybackCallback,
                              /*void* user          =*/  &mContext,
                              /*int32_t notificationFrames =*/ mAudioConfig.frame_count,
                              /*const sp<IMemory>& sharedBuffer =*/ 0,
                              /*bool threadCanCallJava =*/ false,
                              /*audio_session_t sessionId  =*/ AUDIO_SESSION_ALLOCATE,
                              /*transfer_type transferType =*/ AudioTrack::TRANSFER_DEFAULT,
                              /*const audio_offload_info_t *offloadInfo =*/ NULL,
                              /*uid_t uid = */AUDIO_UID_INVALID,
                              /*pid_t pid = */-1,
                              attributes,
                              /*bool doNotReconnect = */false,
                              /*float maxRequiredSpeed = */1.0f,
                              mExplicitRoutingPortId
                              );
    if (status != OK) {
        ALOGE("AudioTrack::set failed: %d", status);
        std::cerr << "AudioTrack::set failed: " << std::endl;
        mAudioTrack.clear();
        return status;
    }
    // Did we get a valid track?
    status = mAudioTrack->initCheck();
    if (status != OK) {
        ALOGE("AudioTrack::iniCheck failed: %d", status);
        std::cerr << "AudioTrack::iniCheck failed: " << std::endl;
        mAudioTrack.clear();
        return status;
    }
    mRoutedPortId = mAudioTrack->getRoutedDeviceId();

    return OK;
}

status_t AudioTrackTest::setVolume(float volume)
{
    return mAudioTrack == nullptr ? NO_INIT : mAudioTrack->setVolume(volume);
}
