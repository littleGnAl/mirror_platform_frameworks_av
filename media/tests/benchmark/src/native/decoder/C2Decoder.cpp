/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "C2Decoder"

#include "C2Decoder.h"

int32_t C2Decoder::createCodec2Component(string compName, AMediaFormat *format) {
    ALOGV("In %s", __func__);
    mListener.reset(new CodecListener(
        [this](std::list<std::unique_ptr<C2Work>>& workItems) {
            handleWorkDone(workItems);
        }));
    if (!mListener) return -1;

    if (!mStats) mStats = new Stats();

    const char *mime = nullptr;
    AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!mime) {
        ALOGE("Error in AMediaFormat_getString");
        return -1;
    }
    // Configure the plugin with Input properties
    std::vector<C2Param*> configParam;
    if (!strncmp(mime, "audio/", 6)) {
        int32_t sampleRate, numChannels;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &numChannels);
        C2StreamSampleRateInfo::output sampleRateInfo(0u, sampleRate);
        C2StreamChannelCountInfo::output channelCountInfo(0u, numChannels);
        configParam.push_back(&sampleRateInfo);
        configParam.push_back(&channelCountInfo);

    } else {
        int32_t width, height;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &width);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &height);
        C2StreamPictureSizeInfo::input inputSize(0u, width, height);
        configParam.push_back(&inputSize);
    }

    int64_t sTime = mStats->getCurTime();
    int32_t status = mClient->createComponent(compName.c_str(), mListener, &mComponent);
    if (mComponent == nullptr) {
        return -1;
    }
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    status |= mComponent->config(configParam, C2_DONT_BLOCK, &failures);
    if (failures.size() != 0) return -1;

    status |= mComponent->start();
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setInitTime(timeTaken);
    return status;
}

int32_t C2Decoder::decodeFrames(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfo) {
    ALOGD("In %s", __func__);
    typedef std::unique_lock<std::mutex> ULock;
    uint32_t maxRetry = 0;
    c2_status_t status = C2_OK;
    mStats->setStartTime();
    ALOGD("WORK Queue Size : %zu", mWorkQueue.size());
    while (1) {
        if (mNumInputFrame == frameInfo.size()) break;
        std::unique_ptr<C2Work> work;
        // Prepare C2Work
        while (!work && (maxRetry < MAX_RETRY)) {
            ULock l(mQueueLock);
            if (!mWorkQueue.empty()) {
                mStats->addInputTime();
                work.swap(mWorkQueue.front());
                mWorkQueue.pop_front();
            } else {
                mQueueCondition.wait_for(l, TIME_OUT);
                maxRetry++;
            }
        }
        if (!work && (maxRetry >= MAX_RETRY)) {
            cout << "Wait for generating C2Work exceeded timeout" << endl;
            return -1;
        }
        uint32_t flags = frameInfo[mNumInputFrame].flags;
        if (flags == AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG ) {
            flags = C2FrameData::FLAG_CODEC_CONFIG;
        }
        if (mNumInputFrame == (frameInfo.size() - 1)) {
            flags |= C2FrameData::FLAG_END_OF_STREAM;
        }
        work->input.flags = (C2FrameData::flags_t)flags;
        work->input.ordinal.timestamp = frameInfo[mNumInputFrame].presentationTimeUs;
        work->input.ordinal.frameIndex = mNumInputFrame;
        work->input.buffers.clear();
        int size = frameInfo[mNumInputFrame].size;
        if (size) {
            std::shared_ptr<C2LinearBlock> block;
            status =
                    mLinearPool->fetchLinearBlock(
                        size, {C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE},
                        &block);
            if (status != C2_OK || block == nullptr) {
                cout << "Null block" << endl;
                return status;
            }

            // Write View
            C2WriteView view = block->map().get();
            if (view.error() != C2_OK) {
                fprintf(stderr, "C2LinearBlock::map() failed : %d", view.error());
                return status;
            }
            memcpy(view.base(), inputBuffer + mOffset, size);
            work->input.buffers.emplace_back(new LinearBuffer(block));
            mStats->addFrameSize(size);
        }
        work->worklets.clear();
        work->worklets.emplace_back(new C2Worklet);

        std::list<std::unique_ptr<C2Work>> items;
        items.push_back(std::move(work));
        // queue() invokes process() function of C2 Plugin.
        status = mComponent->queue(&items);
        if (status !=  C2_OK) {
            return status;
        }
        ALOGV("Frame #%d size = %d queued", mNumInputFrame, size);
        mNumInputFrame++;
        mOffset += size;
        maxRetry = 0;
    }
    return status;
}

void C2Decoder::handleWorkDone(std::list<std::unique_ptr<C2Work>>& workItems) {
    ALOGD("In %s", __func__);
    mStats->addOutputTime();
    for (std::unique_ptr<C2Work>& work : workItems) {
        // handle configuration changes in work done
        if (work->worklets.front()->output.configUpdate.size() != 0) {
            ALOGV("Config Update");
            std::vector<std::unique_ptr<C2Param>> updates =
                std::move(work->worklets.front()->output.configUpdate);
            std::vector<C2Param*> configParam;
            std::vector<std::unique_ptr<C2SettingResult>> failures;
            for (size_t i = 0; i < updates.size(); ++i) {
                C2Param* param = updates[i].get();
                if ((param->index() ==
                            C2StreamSampleRateInfo::output::PARAM_TYPE) ||
                        (param->index() ==
                            C2StreamChannelCountInfo::output::PARAM_TYPE) ||
                        (param->index() ==
                            C2StreamPictureSizeInfo::output::PARAM_TYPE)) {
                    configParam.push_back(param);
                }
            }
            mComponent->config(configParam, C2_DONT_BLOCK, &failures);
            if (failures.size() != 0u) {
                return;
            }
        }
        mEos = (work->worklets.front()->output.flags & C2FrameData::FLAG_END_OF_STREAM) != 0;
        ALOGV("WorkDone: frameID received %d , mEos : %d",
                (int)work->worklets.front()->output.ordinal.frameIndex.peeku(), mEos);
        work->input.buffers.clear();
        work->worklets.clear();
        {
            typedef std::unique_lock<std::mutex> ULock;
            ULock l(mQueueLock);
            mWorkQueue.push_back(std::move(work));
            mQueueCondition.notify_all();
        }

    }
}

void C2Decoder::deInitCodec() {
    ALOGD("In %s", __func__);
    if (!mComponent) return;

    int64_t sTime = mStats->getCurTime();
    mComponent->stop();
    mComponent->release();
    mComponent = nullptr;
    int64_t eTime = mStats->getCurTime();
    int64_t timeTaken = mStats->getTimeDiff(sTime, eTime);
    mStats->setDeInitTime(timeTaken);
}

void C2Decoder::dumpStatistics(string inputReference, int64_t durationUs) {
    string operation = "decode";
    mStats->dumpStatistics(operation, inputReference, durationUs);
}

void C2Decoder::resetDecoder() {
    mOffset = 0;
    mNumInputFrame = 0;
    if (mStats) mStats->reset();
}