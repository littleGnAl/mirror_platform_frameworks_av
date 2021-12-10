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

#ifndef __BENCHMARK_BUFFERPOOL_ENVIRONMENT_H__
#define __BENCHMARK_BUFFERPOOL_ENVIRONMENT_H__

#include <gtest/gtest.h>

using namespace std;

class BenchmarkBufferpoolEnvironment : public ::testing::Environment {
  public:
    BenchmarkBufferpoolEnvironment()
        : res("/data/local/tmp/"), statsFile("/data/local/tmp/stats.csv") {}

    void setStatsFile(const string module) { statsFile = res + module; }

    const string getStatsFile() const { return statsFile; }

    bool writeStatsHeader();

  private:
    string res;
    string statsFile;
};

/**
 * Writes the stats header to a file
 **/
bool BenchmarkBufferpoolEnvironment::writeStatsHeader() {
    char statsHeader[] =
            "BufferType, Operation, UsageFlag, CacheDisabled, Capacity, AvgTime(ns) \n";
    FILE* fpStats = fopen(statsFile.c_str(), "w");
    if (!fpStats) {
        return false;
    }
    int32_t numBytes = fwrite(statsHeader, sizeof(char), sizeof(statsHeader), fpStats);
    fclose(fpStats);
    if (numBytes != sizeof(statsHeader)) {
        return false;
    }
    return true;
}

#endif // __BENCHMARK_BUFFERPOOL_ENVIRONMENT_H__
