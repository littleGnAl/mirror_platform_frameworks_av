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
#define LOG_TAG "BenchmarkTimer"

#include <iostream>
#include <utils/Log.h>

#include "BenchmarkTimer.h"

typedef std::numeric_limits<double> dbl;

void Timer::dumpStatistics() {
    ALOGV("In %s", __func__);
    if (!mOutputTimer.size()) {
        ALOGE("Codec didn't produce any output");
        return;
    }
    int64_t totalTimeTaken = getTotalTime();
    int64_t timeToFirstFrame = *mOutputTimer.begin() - mStartTime;
    // get min and max output intervals.
    int64_t interval;
    int64_t minTimeTaken;
    int64_t maxTimeTaken;
    for (int32_t idx = 0; idx < mOutputTimer.size() - 1; idx++) {
        if (!idx) {
            interval = mOutputTimer.at(idx) - mStartTime;
            minTimeTaken = interval;
            maxTimeTaken = interval;
        } else {
            interval = mOutputTimer.at(idx + 1) - mOutputTimer.at(idx);
            if (minTimeTaken > interval) minTimeTaken = interval;
            if (maxTimeTaken < interval) maxTimeTaken = interval;
        }
    }

    // Print the Stats
    std::cout << "Setup Time : " << getInitTime() << endl;
    std::cout.precision(dbl::max_digits10);
    std::cout << "Average Time : " << (1.0 * totalTimeTaken) / mOutputTimer.size() << endl;
    std::cout << "Time to first frame : " << timeToFirstFrame << endl;
    std::cout << "Minimum Time : " << minTimeTaken << endl;
    std::cout << "Maximum Time : " << maxTimeTaken << endl;
    std::cout << "Destroy Time : " << getDeInitTime() << endl;
}
