/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <stdint.h>
#include <sys/time.h>
#include <utils/Timers.h>
#include <ctime>
#include <fstream>
#include <iostream>
#include <numeric>
#include <vector>

using namespace std;

class Stats {
  public:
    Stats() {}

    ~Stats() {
        if (!mOutputTimer.empty()) mOutputTimer.clear();
    }

  private:
    std::vector<nsecs_t> mOutputTimer;

  public:
    nsecs_t getCurTime() { return systemTime(CLOCK_MONOTONIC); }

    void addOutputTime(nsecs_t timetaken) { mOutputTimer.push_back(timetaken); }

    nsecs_t getTimeDiff(nsecs_t sTime, nsecs_t eTime) { return (eTime - sTime); }

    nsecs_t getTotalTime() {
        if (mOutputTimer.empty()) return -1;
        return accumulate(mOutputTimer.begin(), mOutputTimer.end(), 0);
    }

    /**
     * Dumps the stats of the linear buffer operations.
     *
     * \param operation      describes the operation performed (i.e. allocate/map)
     * \param usageFlag      CPU_READ/CPU_WRITE flags
     * \param sizeOfBuffer   is a size of the buffer allocated.
     * \param bufferType     describes the type of buffer allocated linear/graphic.
     * \param cacheDisabled  the operating mode: cache enabled(false)/disabled(true).
     * \param statsFile      the file where the stats data is to be written.
     */
    void dumpStatistics(string operation, string usageFlag, int64_t sizeOfBuffer, string bufferType,
                        bool cacheDisabled, string statsFile) {
        ALOGV("In %s", __func__);

        nsecs_t totalTimeTakenNs = getTotalTime();

        // Write the stats data to file.
        string rowData = "";
        rowData.append(bufferType + ", ");
        rowData.append(operation + ", ");
        rowData.append(usageFlag + ", ");
        rowData.append(to_string(cacheDisabled) + ", ");
        rowData.append(to_string(sizeOfBuffer) + ", ");
        rowData.append(to_string(totalTimeTakenNs / mOutputTimer.size()) + ",\n");

        ofstream out(statsFile, ios::out | ios::app);
        if (out.bad()) {
            ALOGE("Failed to open stats file for writing: %s", statsFile.c_str());
            return;
        }
        out << rowData;
        out.close();
    }

    /**
     * Dumps the stats of the graphic buffer operations.
     *
     * \param operation      describes the operation performed (i.e. allocate/map)
     * \param usageFlag      CPU_READ/CPU_WRITE flags
     * \param width          is a width of the buffer allocated.
     * \param height         is a height of the buffer allocated.
     * \param bufferType     describes the type of buffer allocated linear/graphic.
     * \param cacheDisabled  the operating mode: cache enabled(false)/disabled(true).
     * \param statsFile      the file where the stats data is to be written.
     */
    void dumpStatistics(string operation, string usageFlag, int32_t width, int32_t height,
                        string bufferType, bool cacheDisabled, string statsFile) {
        ALOGV("In %s", __func__);

        nsecs_t totalTimeTakenNs = getTotalTime();

        // Write the stats data to file.
        string rowData = "";
        rowData.append(bufferType + ", ");
        rowData.append(operation + ", ");
        rowData.append(usageFlag + ", ");
        rowData.append(to_string(cacheDisabled) + ", ");
        rowData.append(to_string(width) + "x" + to_string(height) + ", ");
        rowData.append(to_string(totalTimeTakenNs / mOutputTimer.size()) + ",\n");

        ofstream out(statsFile, ios::out | ios::app);
        if (out.bad()) {
            ALOGE("Failed to open stats file for writing: %s", statsFile.c_str());
            return;
        }
        out << rowData;
        out.close();
    }
};
