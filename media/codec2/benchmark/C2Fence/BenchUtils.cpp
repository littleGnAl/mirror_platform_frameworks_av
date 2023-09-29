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
#include <unistd.h>

#include "BenchUtils.h"

namespace android::codec2::benchmark {

std::map<std::string, std::pair<int64_t, int64_t>> ProfileTimer::sProfiles;

IpcMessageTransferer::IpcMessageTransferer()
        : mValid(false), mReqPipe{-1, -1}, mAnsPipe{-1, -1} {
    if (::pipe(mReqPipe) < 0 || ::pipe(mAnsPipe) < 0) {
        closePipes();
        return;
    }
    mValid = true;
}

IpcMessageTransferer::~IpcMessageTransferer() {
    closePipes();
}

void IpcMessageTransferer::closePipes() {
    if (mReqPipe[0] >= 0) {
        ::close(mReqPipe[0]);
        mReqPipe[0] = -1;
    }
    if (mReqPipe[1] >= 0) {
        ::close(mReqPipe[1]);
        mReqPipe[1] = -1;
    }
    if (mAnsPipe[0] >= 0) {
        ::close(mAnsPipe[0]);
        mAnsPipe[0] = -1;
    }
    if (mAnsPipe[1] >= 0) {
        ::close(mAnsPipe[1]);
        mAnsPipe[1] = -1;
    }
    mValid = false;
}

bool IpcMessageTransferer::valid() {
    return mValid;
}

// Do I/O in blocking manner and ignore possibility of EINTR.
bool IpcMessageTransferer::sendRequestAndWait(const IpcMessage &request, IpcMessage *reply) {
    if (!mValid) {
        return false;
    }
    int ret = -1;
    ret = ::write(mReqPipe[1], &request, sizeof(IpcMessage));
    if (ret != sizeof(IpcMessage)) {
        return false;
    }
    ret = ::read(mAnsPipe[0], reply, sizeof(IpcMessage));
    if (ret != sizeof(IpcMessage)) {
        return false;
    }
    if (request.command_ != reply->command_ || request.seqId_ != reply->seqId_) {
        return false;
    }
    return true;
}

bool IpcMessageTransferer::waitRequest(IpcMessage *request) {
    if (!mValid) {
        return false;
    }
    int ret = -1;
    ret = ::read(mReqPipe[0], request, sizeof(IpcMessage));
    if (ret != sizeof(IpcMessage)) {
        return false;
    }
    return true;
}

bool IpcMessageTransferer::sendReply(const IpcMessage &request, int64_t reply) {
    if (!mValid) {
        return false;
    }
    IpcMessage ans;
    int ret = -1;
    ans.command_ = request.command_;
    ans.seqId_ = request.seqId_;
    ans.arg_ = reply;
    ret = ::write(mAnsPipe[1], &ans, sizeof(IpcMessage));
    if (ret != sizeof(IpcMessage)) {
        return false;
    }
    return true;
}

}

