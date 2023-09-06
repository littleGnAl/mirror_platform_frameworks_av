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

//#define LOG_NDEBUG 0
#define LOG_TAG "C2IgbaWaitableObj"
#include <C2IgbaWaitableObj.h>
#include <poll.h>
#include <utils/Log.h>

C2IgbaWaitableObj::C2IgbaWaitableObj(int pipeFd) : mPipeFd(pipeFd) {
    mValid = (mPipeFd.get() >= 0);
}

bool C2IgbaWaitableObj::valid() const {
    return mValid;
}

int C2IgbaWaitableObj::fd() const {
    return ::dup(mPipeFd.get());
}

::android::base::unique_fd C2IgbaWaitableObj::release() {
    return std::move(mPipeFd);
}

bool C2IgbaWaitableObj::waitEvent(c2_nsecs_t timeoutNs, bool *hangUp, bool *allocatable) {
    if (!mValid) {
        *hangUp = true;
        return true;
    }
    struct pollfd pfd;
    pfd.fd = mPipeFd.get();
    pfd.events = POLLIN;
    pfd.revents = 0;
    struct timespec *tsp = nullptr;
    struct timespec ts;
    if (timeoutNs >= 0) {
        ts.tv_sec = 0;
        ts.tv_nsec = timeoutNs;
        tsp = &ts;
    } else {
        ALOGV("polling igba event indefinitely..");
    }
    int ret = ::ppoll(&pfd, 1, tsp, nullptr);
    if (ret >= 0) {
        if (pfd.revents) {
            if (pfd.revents & ~POLLIN) {
                // Mostly this means the writing end fd was closed.
                *hangUp = true;
                mValid = false;
                ALOGE("C2WaitableObj: pipe fd hungup or error");
                return true;
            }
            *allocatable = true;
            return true;
        }
        // events are not ready
        return true;
    }
    if (errno == EINTR) {
        // retry, polliing was cancelled.
        return false;
    }
    // Treat the error is irrecovorable here.
    ALOGE("C2EventFence: polling error %d", errno);
    *hangUp = true;
    mValid = false;
    return true;
}
