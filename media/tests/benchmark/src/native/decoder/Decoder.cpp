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
#define LOG_TAG "decoder"

#include <iostream>

#include "Decoder.h"

tuple<ssize_t, uint32_t, int64_t> readSampleData(uint8_t *inputBuffer, int32_t &offset,
                                                 vector<AMediaCodecBufferInfo> &frameInfo,
                                                 uint8_t *buf, int32_t frameID, size_t bufSize) {
    ALOGV("In %s", __func__);
    if (frameID == (int32_t)frameInfo.size()) {
        return make_tuple(0, AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM, 0);
    }
    uint32_t flags = frameInfo[frameID].flags;
    int64_t timestamp = frameInfo[frameID].presentationTimeUs;
    ssize_t bytesCount = frameInfo[frameID].size;
    if (bufSize < bytesCount) {
        ALOGE("Error : insufficient resource");
        return make_tuple(0, AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE, 0);
    }

    memcpy(buf, inputBuffer + offset, bytesCount);
    offset += bytesCount;
    return make_tuple(bytesCount, flags, timestamp);
}

void Decoder::onInputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawInputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        size_t bufSize;
        uint8_t *buf = AMediaCodec_getInputBuffer(mCodec, bufIdx, &bufSize);
        if (!buf) {
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        ssize_t bytesRead = 0;
        uint32_t flag = 0;
        int64_t presentationTimeUs = 0;
        tie(bytesRead, flag, presentationTimeUs) = readSampleData(
                mInputBuffer, mOffset, mFrameMetaData, buf, mNumInputFrame, bufSize);
        if (flag == AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE) {
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        if (flag == AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) mSawInputEOS = true;
        ALOGV("%s bytesRead : %zd presentationTimeUs : %" PRId64 " mSawInputEOS : %s", __FUNCTION__,
              bytesRead, presentationTimeUs, mSawInputEOS ? "TRUE" : "FALSE");

        int status = AMediaCodec_queueInputBuffer(mCodec, bufIdx, 0 /* offset */, bytesRead,
                                                  presentationTimeUs, flag);
        if (AMEDIA_OK != status) {
            mSignalledError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }
        mTimer->addFrameSize(bytesRead);
        mNumInputFrame++;
    }
}

void Decoder::onOutputAvailable(AMediaCodec *mediaCodec, int32_t bufIdx,
                                AMediaCodecBufferInfo *bufferInfo) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        if (mSawOutputEOS || bufIdx < 0) return;
        if (mSignalledError) {
            CallBackHandle::mSawError = true;
            mDecoderDoneCondition.notify_one();
            return;
        }

        AMediaCodec_releaseOutputBuffer(mCodec, bufIdx, false);
        mSawOutputEOS = (0 != (bufferInfo->flags & AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM));
        mNumOutputFrame++;
        ALOGV("%s index : %d  mSawOutputEOS : %s count : %u", __FUNCTION__, bufIdx,
              mSawOutputEOS ? "TRUE" : "FALSE", mNumOutputFrame);

        if (mSawOutputEOS) {
            CallBackHandle::mIsDone = true;
            mDecoderDoneCondition.notify_one();
        }
    }
}

void Decoder::onFormatChanged(AMediaCodec *mediaCodec, AMediaFormat *format) {
    ALOGV("In %s", __func__);
    if (mediaCodec == mCodec && mediaCodec) {
        ALOGV("%s { %s }", __FUNCTION__, AMediaFormat_toString(format));
        mFormat = format;
    }
}

void Decoder::setupDecoder() {
    if (!mFormat) mFormat = mExtractor->getFormat();
    if (!mTimer) mTimer = new Timer();
}

int32_t Decoder::decode(uint8_t *inputBuffer, vector<AMediaCodecBufferInfo> &frameInfo,
                        string &codecName, bool asyncMode) {
    ALOGV("In %s", __func__);
    mInputBuffer = inputBuffer;
    mFrameMetaData = frameInfo;
    mOffset = 0;

    const char *mime = nullptr;
    AMediaFormat_getString(mFormat, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!mime) return AMEDIA_ERROR_INVALID_OBJECT;

    int64_t sTime = mTimer->getCurTime();
    mCodec = createMediaCodec(mFormat, mime, codecName, false /*isEncoder*/);
    if (!mCodec) return AMEDIA_ERROR_INVALID_OBJECT;

    if (asyncMode) {
        AMediaCodecOnAsyncNotifyCallback aCB = {OnInputAvailableCB, OnOutputAvailableCB,
                                                OnFormatChangedCB, OnErrorCB};
        AMediaCodec_setAsyncNotifyCallback(mCodec, aCB, this);

        CallBackHandle *callbackHandle = new CallBackHandle();
        callbackHandle->mIOThread = thread(&CallBackHandle::ioThread, this);
    }

    AMediaCodec_start(mCodec);
    int64_t eTime = mTimer->getCurTime();
    int64_t timeTaken = mTimer->getTimeDiff(sTime, eTime);
    mTimer->setInitTime(timeTaken);

    mTimer->setStartTime();
    if (!asyncMode) {
        while (!mSawOutputEOS && !mSignalledError) {
            /* Queue input data */
            if (!mSawInputEOS) {
                ssize_t inIdx = AMediaCodec_dequeueInputBuffer(mCodec, kQueueDequeueTimeoutUs);
                if (inIdx < 0 && inIdx != AMEDIACODEC_INFO_TRY_AGAIN_LATER) {
                    ALOGE("AMediaCodec_dequeueInputBuffer returned invalid index %zd\n", inIdx);
                    return AMEDIA_ERROR_IO;
                } else if (inIdx >= 0) {
                    mTimer->addInputTime();
                    onInputAvailable(mCodec, inIdx);
                }
            }

            /* Dequeue output data */
            AMediaCodecBufferInfo info;
            ssize_t outIdx = AMediaCodec_dequeueOutputBuffer(mCodec, &info, kQueueDequeueTimeoutUs);
            if (outIdx == AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED) {
                mFormat = AMediaCodec_getOutputFormat(mCodec);
                const char *s = AMediaFormat_toString(mFormat);
                ALOGI("Output format: %s\n", s);
            } else if (outIdx >= 0) {
                mTimer->addOutputTime();
                onOutputAvailable(mCodec, outIdx, &info);
            } else if (!(outIdx == AMEDIACODEC_INFO_TRY_AGAIN_LATER ||
                         outIdx == AMEDIACODEC_INFO_OUTPUT_BUFFERS_CHANGED)) {
                ALOGE("AMediaCodec_dequeueOutputBuffer returned invalid index %zd\n", outIdx);
                return AMEDIA_ERROR_IO;
            }
        }
    } else {
        unique_lock<mutex> lock(mMutex);
        mDecoderDoneCondition.wait(lock, [this]() { return (mSawOutputEOS || mSignalledError); });
    }

    if (codecName.empty()) {
        char *decName;
        AMediaCodec_getName(mCodec, &decName);
        codecName.assign(decName);
        AMediaCodec_releaseName(mCodec, decName);
    }
    return AMEDIA_OK;
}

void Decoder::deInitCodec() {
    int64_t sTime = mTimer->getCurTime();
    if (mFormat) {
        AMediaFormat_delete(mFormat);
        mFormat = nullptr;
    }
    if (!mCodec) return;
    AMediaCodec_stop(mCodec);
    AMediaCodec_delete(mCodec);
    int64_t eTime = mTimer->getCurTime();
    int64_t timeTaken = mTimer->getTimeDiff(sTime, eTime);
    mTimer->setDeInitTime(timeTaken);
}

void Decoder::dumpStatistics(string inputReference) {
    int64_t durationUs = mExtractor->getClipDuration();
    string operation = "decode";
    mTimer->dumpStatistics(operation, inputReference, durationUs);
}

void Decoder::resetDecoder() {
    if (mTimer) mTimer->resetTimers();
    if (mInputBuffer) mInputBuffer = nullptr;
    if (!mFrameMetaData.empty()) mFrameMetaData.clear();
}
