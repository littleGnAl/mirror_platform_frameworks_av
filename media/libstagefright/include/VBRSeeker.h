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

#ifndef VBR_SEEKER_H_

#define VBR_SEEKER_H_

#include "include/MP3Seeker.h"

#include <utils/Vector.h>

namespace android {

class DataSource;

struct VBRSeeker : public MP3Seeker {
    static sp<VBRSeeker> CreateFromSource(
            const sp<DataSource> &source, off64_t first_frame_pos);
    static bool isVBR(const sp<DataSource> &source, off64_t first_frame_pos);

    virtual bool getDuration(int64_t *durationUs);
    virtual bool getOffsetForTime(int64_t *timeUs, off64_t *pos);

private:
    static const int kVBRTestFrames = 64;

    Vector<off64_t> mPositions;
    Vector<int64_t> mTimes;
    int64_t mDurationUs;

    VBRSeeker();

    void addSeekEntry(int64_t time, off64_t pos);

    DISALLOW_EVIL_CONSTRUCTORS(VBRSeeker);
};

}  // namespace android

#endif  // VBR_SEEKER_H_
