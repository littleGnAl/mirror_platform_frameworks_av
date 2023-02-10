/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "CameraTombstone"
#define ATRACE_TAG ATRACE_TAG_CAMERA

#include "utils/CameraTombstone.h"

#include <utils/Log.h>

namespace android {
namespace camera3 {

void CameraTombstone::dump(pid_t pid) {
    ALOGV("%s: pid = %d", __FUNCTION__, pid);

    base::unique_fd piperead, pipewrite;
    if (!Pipe(&piperead, &pipewrite)) {
        ALOGE("failed to create pipe");
        return;
    }

    std::thread redirect_thread = spawn_redirect_thread(std::move(piperead));
    if (!debuggerd_trigger_dump(pid, kDebuggerdNativeBacktrace, 0, std::move(pipewrite))) {
        redirect_thread.join();
        ALOGE("failed to dump process %d", pid);
    }

    redirect_thread.join();
}

std::thread CameraTombstone::spawn_redirect_thread(base::unique_fd fd) {
    return std::thread([fd{std::move(fd)}]() {
        while (true) {
            char buf[BUFSIZ];
            ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
            if (rc <= 0) {
                return;
            }

            ALOGE("%s", buf);
        }
    });
}

};  // namespace camera3
};  // namespace android
