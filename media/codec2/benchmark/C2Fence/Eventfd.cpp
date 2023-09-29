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

#define LOG_TAG "eventfd_benchmark_test"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <map>

#include "BenchUtils.h"

using android::codec2::benchmark::IpcMessage;
using android::codec2::benchmark::IpcMessageTransferer;
using android::codec2::benchmark::ProfileTimer;

class EventManager {
public:
    EventManager(int numEvent) : mEventNum(numEvent), mCurNum(0),
        mEventFd(::eventfd(numEvent, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)) {
        mValid = (mEventFd >= 0);
    }

    ~EventManager() {
        if (mEventFd >= 0) {
            ::close(mEventFd);
        }
    }

    bool valid() {
        return mValid;
    }
    bool ready(int miliSecs) {
        if (!mValid) {
            return false;
        }
        struct pollfd pfd;
        pfd.fd = mEventFd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (miliSecs < 0) {
            miliSecs = 0;
        }
        int ret = ::poll(&pfd, 1, miliSecs);
        if (ret >= 0) {
            if (pfd.revents) {
                if (pfd.revents & ~POLLIN) {
                    mValid = false;
                    return false;
                }
                return true;
            }
            return false;
        }
        if (errno != EINTR) {
            mValid = false;
        }
        return false;
    }

    int curEvent() {
        return mCurNum;
    }

    bool add() {
        if (!mValid) {
            return false;
        }
        if (mCurNum >= mEventNum) {
            return false;
        }
        int64_t inc = 1;
        int ret = ::write(mEventFd, &inc, 8);
        if (ret <= 0) {
            mValid = false;
            return false;
        }
        ++mCurNum;
        return true;
    }

    bool del() {
        if (!mValid) {
            return false;
        }
        if (mCurNum <= 0) {
            return false;
        }
        int64_t del = 0;
        int ret = ::read(mEventFd, &del, 8);
        if (ret <= 0) {
            mValid = false;
            return false;
        }
        --mCurNum;
        return true;
    }
private:
    bool mValid;
    int mEventNum;
    int mCurNum;
    int mEventFd;
};

namespace {

enum command_t : int32_t {
    COMMAND_ALLOCATE,
    COMMAND_SHUTDOWN,
};

void producer(EventManager &eventManager, IpcMessageTransferer  &transferer) {
    int numAllocated = 0;
    IpcMessage req;
    do {
        if (eventManager.curEvent() == 0) {
            eventManager.add();
        }
        if (!transferer.waitRequest(&req)) {
            break;
        }
        bool shutdown = false;
        bool ret;
        switch (req.command_) {
            case COMMAND_ALLOCATE: {
                ret = eventManager.del();
                if (ret) {
                    ++numAllocated;
                }
                transferer.sendReply(req, ret ? 1 : 0);
            }
            break;
            case COMMAND_SHUTDOWN: {
                transferer.sendReply(req, numAllocated);
                shutdown = true;
            }
            break;
            default: {
                transferer.sendReply(req, -1LL);
            }
        }
        if (shutdown || !eventManager.valid()) {
            break;
        }
    } while (true);
}

bool consumer(EventManager &eventManager, IpcMessageTransferer  &transferer) {
    static constexpr int kNumAllocate = 1000000;
    int numAllocate = 0;
    IpcMessage req;
    IpcMessage ans;
    int seqId = 0;
    bool err = false;
    do {
        do {
            ProfileTimer pf(__PRETTY_FUNCTION__, std::to_string(__LINE__));
            if (eventManager.ready(1000)) {
                break;
            }
        }
        while (eventManager.valid());
        if (!eventManager.valid()) {
            err = true;
            break;
        }
        req.command_ = COMMAND_ALLOCATE;
        req.seqId_ = seqId++;
        req.arg_ = 0;
        if (!transferer.sendRequestAndWait(req, &ans)) {
            err = true;
            break;
        }
        if (ans.arg_ == 0) {
            err = true;
            break;
        }
        numAllocate++;
    } while (numAllocate < kNumAllocate);
    if (!err) {
        req.command_ = COMMAND_SHUTDOWN;
        req.seqId_ = seqId++;
        req.arg_ = 0;
        if (!transferer.sendRequestAndWait(req, &ans)) {
            return false;
        }
    }
    std::cout << "allocated: " << numAllocate << std::endl;
    ProfileTimer::showProfiles();
    return numAllocate >= kNumAllocate;
}

}

int main(int argc, char** argv) {
    (void) argc;
    (void) argv;
    EventManager eventManager(20);
    IpcMessageTransferer transferer;

    if (!eventManager.valid() || !transferer.valid()) {
        ::exit(EXIT_FAILURE);
    }
    pid_t pid = fork();
    if (pid < 0) {
        ::exit(EXIT_FAILURE);
    }

    if (pid == 0) { // child
        producer(eventManager, transferer);
        ::exit(EXIT_SUCCESS);
    } else {
        bool ret = consumer(eventManager, transferer);
        std::cout << "consumer: " << ret << std::endl;;
        if (!ret) {
            ::kill(pid, SIGKILL);
        }
        ::wait(nullptr);
        ::exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
    }
}
