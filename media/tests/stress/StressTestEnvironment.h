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
#ifndef __STRESS_TEST_ENVIRONMENT_H__
#define __STRESS_TEST_ENVIRONMENT_H__

#include <gtest/gtest.h>

#include <getopt.h>
class StressTestEnvironment : public ::testing::Environment {
  public:
    StressTestEnvironment()
            :res("/data/local/tmp/MediaStress/res/") {}

    // Parses the command line argument
    int initFromOptions(int argc, char **argv);

    void setRes(const char *_res) { res = _res; }

    const std::string getRes() const { return res; }

  private:
    std::string res;
};
#endif  // __STRESS_TEST_ENVIRONMENT_H__
