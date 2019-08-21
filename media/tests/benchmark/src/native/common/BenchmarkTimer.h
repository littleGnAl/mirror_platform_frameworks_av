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

#ifndef __BENCHMARK_TIMER_H__
#define __BENCHMARK_TIMER_H__

#include <sys/time.h>
#include <algorithm>
#include <numeric>
#include <vector>

using namespace std;

class Timer {
  public:
    Timer() {
        gettimeofday(&mTime, nullptr);
        mInitTime = 0;
        mDeInitTime = 0;
    }

    ~Timer() {
        if (!mInputTimer.empty()) mInputTimer.clear();
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

  private:
    struct timeval mTime;

    int64_t mInitTime;
    int64_t mDeInitTime;
    int64_t mStartTime;
    std::vector<int64_t> mInputTimer;
    std::vector<int64_t> mOutputTimer;

  public:
    int64_t getCurTime() {
        gettimeofday(&mTime, nullptr);
        int64_t sTime = mTime.tv_sec * 1000000 + mTime.tv_usec;
        return sTime;
    }

    void setInitTime(int64_t initTime) { mInitTime = initTime; }

    void setDeInitTime(int64_t deInitTime) { mDeInitTime = deInitTime; }

    void addInputTime() {
        gettimeofday(&mTime, nullptr);
        int64_t sTime = mTime.tv_sec * 1000000 + mTime.tv_usec;
        mInputTimer.push_back(sTime);
    }

    void addStartTime() {
        gettimeofday(&mTime, nullptr);
        mStartTime = mTime.tv_sec * 1000000 + mTime.tv_usec;
    }

    void addOutputTime() {
        gettimeofday(&mTime, nullptr);
        int64_t eTime = mTime.tv_sec * 1000000 + mTime.tv_usec;
        mOutputTimer.push_back(eTime);
    }

    void resetTimer() {
        if (!mInputTimer.empty()) mInputTimer.clear();
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

    std::vector<int64_t> getOutputTimer() { return mOutputTimer; }

    int64_t getInitTime() { return mInitTime; }

    int64_t getDeInitTime() { return mDeInitTime; }

    int64_t getTimeDiff(int64_t sTime, int64_t eTime) { return (eTime - sTime); }

    int64_t getTotalTime() { return (*(mOutputTimer.end() - 1) - mStartTime); }

    void dumpStatistics();
};

#endif  // __BENCHMARK_TIMER_H__
