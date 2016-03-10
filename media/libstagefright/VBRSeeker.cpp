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

//#define LOG_NDEBUG 0
#define LOG_TAG "VBRSeeker"
#include <utils/Log.h>

#include "include/VBRSeeker.h"

#include "include/avc_utils.h"
#include "include/MP3Extractor.h"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/Utils.h>

namespace android {

// static
sp<VBRSeeker> VBRSeeker::CreateFromSource(
        const sp<DataSource> &source, off64_t first_frame_pos) {
    uint32_t header;
    int64_t durationUs = 0;
    size_t frameSize;
    int bitrate;

    if (!isVBR(source, first_frame_pos)) {
        return NULL;
    }

    sp<VBRSeeker> seeker = new VBRSeeker();
    off64_t position = first_frame_pos;
    unsigned char data[4];
    while (true) {
        ssize_t n = source->readAt(position, data, 4);
        if (n < 4) {
            break; //EOS
        }

        seeker->addSeekEntry(durationUs, position);
        header = U32_AT((const uint8_t *)data);
        if (GetMPEGAudioFrameSize(header, &frameSize, NULL, NULL, &bitrate)) {
            durationUs += 8000LL * frameSize / bitrate;
            position += frameSize;
        } else {
            break;
        }
    }
    seeker->mDurationUs = durationUs;

    return seeker;
}

// static
bool VBRSeeker::isVBR(const sp<DataSource> &source, off64_t first_frame_pos) {
    uint32_t header;
    size_t frameSize;
    int bitrate;
    int firstBitrate = -1;
    int frames = 0;

    off64_t position = first_frame_pos;
    unsigned char data[4];
    while (frames < kVBRTestFrames) {
        ssize_t n = source->readAt(position, data, 4);
        if (n < 4) {
            return false;
        }
        header = U32_AT((const uint8_t *)data);
        if (GetMPEGAudioFrameSize(header, &frameSize, NULL, NULL, &bitrate)) {
            if (firstBitrate < 0) {
                firstBitrate = bitrate;
            } else if (bitrate != firstBitrate) {
                return true;
            }
            position += frameSize;
            frames++;
        } else {
            return false;
        }
    }
    return false;
}

VBRSeeker::VBRSeeker()
    : mDurationUs(-1)
{}

bool VBRSeeker::getDuration(int64_t *durationUs) {
    if (mDurationUs == -1) {
        return false;
    }

    *durationUs = mDurationUs;

    return true;
}

bool VBRSeeker::getOffsetForTime(int64_t *timeUs, off64_t *pos) {
    if (mTimes.size() == 0) {
        return false;
    }

    size_t seconds = *timeUs / 1000000;

    if (seconds < mTimes.size()) {
        *timeUs = mTimes[seconds];
        *pos = mPositions[seconds];
    } else {
        *timeUs = mTimes.top();
        *pos = mPositions.top();
    }

    return true;
}

void VBRSeeker::addSeekEntry(int64_t time, off64_t pos) {
    size_t seconds = time / 1000000;

    if (seconds < mTimes.size()) {
        return;
    }

    while (seconds > mTimes.size()) {
        mTimes.push(mTimes.top());
        mPositions.push(mPositions.top());
    }

    mTimes.push(time);
    mPositions.push(pos);
}

}  // namespace android
