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

C2IgbaWaitableObj::C2IgbaWaitableObj(int statusEventFd, int allocEventFd)
        : mStatusEventFd(statusEventFd), mAllocEventFd(allocEventFd) {
    mValid = (mStatusEventFd.get() >= 0 && mAllocEventFd.get() >= 0);
}

bool C2IgbaWaitableObj::valid() {
    return mValid;
}

bool C2IgbaWaitableObj::waitEvent(c2_nsecs_t timeoutNs, bool *hangUp, bool *allocatable) {
    if (!mValid) {
        *hangUp = true;
        return true;
    }
    struct pollfd fds[2];
    fds[0].fd = mStatusEventFd.get();
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    fds[1].fd = mAllocEventFd.get();
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = timeoutNs;

    int ret = ::ppoll(fds, 2, &ts, nullptr);
    if (ret >= 0) {
        if (fds[0].revents) {
            *hangUp = true;
            mValid = false;
            if (fds[0].revents & ~POLLIN) {
                ALOGE("C2WaitableObj: status eventfd hungup or error");
            }
            return true;
        }
        if (fds[1].revents) {
            if (fds[1].revents & ~POLLIN) {
                *hangUp = true;
                mValid = false;
                ALOGE("C2WaitableObj: alloc eventfd hungup or error");
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
