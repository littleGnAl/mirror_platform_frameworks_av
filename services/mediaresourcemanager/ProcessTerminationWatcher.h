/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#ifndef ANDROID_MEDIA_PROCESSTERMINATIONWATCHER_H_
#define ANDROID_MEDIA_PROCESSTERMINATIONWATCHER_H_

#include <set>
#include <mutex>
#include <thread>
#include <vector>
#include <functional>
#include <condition_variable>
#include <utils/StrongPointer.h>

namespace android {

using OnProcessTerminated = std::function<void(const std::vector<int32_t>&)>;
using namespace std::chrono_literals;

struct ProcessInfoInterface;

//
// ProcessTerminationWatcher class
//
// This class implements a callback mechanism to notify the termination of the
// process/applications that are registered with this class.
//
// It uses ActivityManager (through ProcessInfoInterface) to query for the
// process/application state.
//
// The poll duration (how often to check for the process/application state) can
// be configured while creating object of this class.
// The default poll duration is 5 seconds.
//
class ProcessTerminationWatcher {
public:
    ProcessTerminationWatcher(const sp<ProcessInfoInterface>& processInfo,
                              OnProcessTerminated onProcessTerminated,
                              std::chrono::seconds pollDuration = 5s);
    ~ProcessTerminationWatcher();

    void addPid(int32_t pid) {
        std::scoped_lock lock(mLock);
        mPids.emplace(pid);
    }

private:
    ProcessTerminationWatcher() = delete;
    ProcessTerminationWatcher(const ProcessTerminationWatcher&) = delete;
    ProcessTerminationWatcher(ProcessTerminationWatcher&&) = delete;
    ProcessTerminationWatcher& operator=(const ProcessTerminationWatcher&) = delete;
    ProcessTerminationWatcher& operator=(ProcessTerminationWatcher&&) = delete;

    void run();
    void stop();
    void lookForTerminatedProcesses();

private:
    bool mRunning = true;
    std::mutex mLock;
    std::mutex mWaitLock;
    std::thread mThread;
    std::set<int32_t> mPids;
    std::chrono::seconds mPollDuration = 5s;
    std::condition_variable mWaitCondition;
    OnProcessTerminated mOnProcessTerminated;
    sp<ProcessInfoInterface> mProcessInfo;
};

}  // namespace android

#endif  //ANDROID_MEDIA_PROCESSTERMINATIONWATCHER_H_
