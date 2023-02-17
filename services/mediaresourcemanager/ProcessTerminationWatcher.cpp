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


#include <media/stagefright/ProcessInfo.h>
#include "ProcessTerminationWatcher.h"

namespace android {

ProcessTerminationWatcher::ProcessTerminationWatcher(
           const sp<ProcessInfoInterface>& processInfo,
           OnProcessTerminated onProcessTerminated,
           std::chrono::seconds pollDuration):
     mThread([this] { run(); }),
     mPollDuration(pollDuration),
     mOnProcessTerminated(std::move(onProcessTerminated)),
     mProcessInfo(processInfo) {
}

ProcessTerminationWatcher::~ProcessTerminationWatcher() {
    stop();
    if (mThread.joinable()) {
        mThread.join();
    }
}

void ProcessTerminationWatcher::stop() {
    std::scoped_lock lock{mWaitLock};
    mRunning = false;
    mWaitCondition.notify_all();
}

void ProcessTerminationWatcher::run() {
    std::unique_lock lock{mWaitLock};
    while (mRunning) {
        if (mWaitCondition.wait_for(lock, mPollDuration, [this]{return !mRunning;})) {
            // Time to stop/end the thread now.
        } else {
            // Time to monitor the state of all the processes.
            lookForTerminatedProcesses();
        }
    }
}

void ProcessTerminationWatcher::lookForTerminatedProcesses() {
    std::vector<int32_t> pids;
    {
        std::scoped_lock lock{mLock};
        if (mPids.empty()) {
            // No pid to track.
            return;
        }
        std::copy(mPids.begin(), mPids.end(), std::back_inserter(pids));
    }
    std::vector<bool> existent;
    if (mProcessInfo->isProcessExistent(pids, &existent)) {
        std::vector<int32_t> terminatedPids;
        {
            std::scoped_lock lock{mLock};
            for (size_t index = 0; index < existent.size(); index++) {
                if (!existent[index]) {
                    // This process has been terminated already.
                    terminatedPids.push_back(pids[index]);
                    mPids.erase(pids[index]);
                }
            }
        }
        mOnProcessTerminated(terminatedPids);
    }
}

}  // namespace android
