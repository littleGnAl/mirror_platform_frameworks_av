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

//#define LOG_NDEBUG 0
#define LOG_TAG "extractor"

#include "Extractor.h"

int32_t Extractor::setupExtractor(int32_t fd, size_t fileSize) {
    if (!mTimer) mTimer = new Timer();
    mTimer->resetTimer();

    mFrameBuf = (uint8_t *)calloc(kMaxBufferSize, sizeof(uint8_t));
    if (!mFrameBuf) return -1;

    int64_t sTime = mTimer->getCurTime();
    if (!mExtractor) {
        mExtractor = AMediaExtractor_new();
        media_status_t status = AMediaExtractor_setDataSourceFd(mExtractor, fd, 0, fileSize);
        if (status != AMEDIA_OK) return -1;
    }
    int64_t eTime = mTimer->getCurTime();
    int64_t timeTaken = mTimer->getTimeDiff(sTime, eTime);
    mTimer->setInitTime(timeTaken);

    if (!mExtractor) return -1;

    return AMediaExtractor_getTrackCount(mExtractor);
}

void *Extractor::getCSDSample(AMediaCodecBufferInfo &frameInfo, int32_t csdIndex) {
    char csdName[kMaxCSDStrlen];
    void *csdBuffer = nullptr;
    frameInfo.presentationTimeUs = 0;
    frameInfo.flags = AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG;
    snprintf(csdName, kMaxCSDStrlen, "csd-%d", csdIndex);

    size_t size;
    bool csdFound = AMediaFormat_getBuffer(mFormat, csdName, &csdBuffer, &size);
    if (!csdFound) return nullptr;
    frameInfo.size = (int32_t)size;

    return csdBuffer;
}

int32_t Extractor::getFrameSample(AMediaCodecBufferInfo &frameInfo) {
    int32_t size = AMediaExtractor_readSampleData(mExtractor, mFrameBuf, kMaxBufferSize);
    if (size < 0) return -1;
    frameInfo.flags = AMediaExtractor_getSampleFlags(mExtractor);
    frameInfo.size = size;
    frameInfo.presentationTimeUs = AMediaExtractor_getSampleTime(mExtractor);
    AMediaExtractor_advance(mExtractor);

    return 0;
}

int32_t Extractor::setupTrackFormat(int32_t trackId) {
    AMediaExtractor_selectTrack(mExtractor, trackId);
    mFormat = AMediaExtractor_getTrackFormat(mExtractor, trackId);
    if (!mFormat) return -1;

    return 0;
}

int32_t Extractor::extract(int32_t trackId) {
    int32_t status = setupTrackFormat(trackId);
    if (status != 0) return -1;

    int32_t idx = 0;
    AMediaCodecBufferInfo frameInfo;
    while (1) {
        memset(&frameInfo, 0, sizeof(AMediaCodecBufferInfo));
        void *csdBuffer = getCSDSample(frameInfo, idx);
        if (!csdBuffer || !frameInfo.size) break;
        idx++;
    }

    mTimer->addStartTime();
    while (1) {
        int32_t status = getFrameSample(frameInfo);
        if (status || !frameInfo.size) break;
        mTimer->addOutputTime();
    }

    if (mFormat) {
        AMediaFormat_delete(mFormat);
        mFormat = nullptr;
    }

    AMediaExtractor_unselectTrack(mExtractor, trackId);

    return 0;
}

void Extractor::resetExtractor() {
    memset(mFrameBuf, 0, kMaxBufferSize);
    mTimer->resetTimer();
}

void Extractor::deInitExtractor() {
    if (mFrameBuf) {
        free(mFrameBuf);
        mFrameBuf = nullptr;
    }
    if (mExtractor) {
        // Multiple calls result in stall. TODO: File a bug for the same
        // AMediaExtractor_delete(mExtractor);
        mExtractor = nullptr;
    }
}
