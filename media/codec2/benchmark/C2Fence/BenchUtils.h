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

#pragma once
#include <stdint.h>
#include <sys/time.h>

#include <iostream>
#include <string>
#include <map>
#include <utility>

namespace android::codec2::benchmark {

struct IpcMessage {
    int32_t command_;
    int32_t seqId_;
    int64_t arg_;
};

/**
 * Sends/receives a message between producer and consumer via two pairs of
 * file descriptors which are created by pipe().
 * One pair of file descriptors are used for sending requests from consumer to
 * producer. The other pair of file descriptors are used for sending replies
 * from producer to consumer. (Typically used with fork())
 */
class IpcMessageTransferer {
public:
    explicit IpcMessageTransferer();

    ~IpcMessageTransferer();

    bool valid();

    bool sendRequestAndWait(const IpcMessage &request, IpcMessage *reply /* NonNull */);

    bool waitRequest(IpcMessage *request /* NonNull */);

    bool sendReply(const IpcMessage &request, int64_t reply);

private:
    void closePipes();

private:
    bool mValid;
    int mReqPipe[2];
    int mAnsPipe[2];
};

class ProfileTimer {
private:
    static std::map<std::string, std::pair<int64_t, int64_t>> sProfiles;
    bool mStopped;
    struct timeval mTs;
    std::string mName;

public:
    ProfileTimer(std::string func, std::string line) : mStopped(false) {
        mName.append(func);
        mName.append(line);
        ::gettimeofday(&mTs, nullptr);
    }

    void stop() {
        if (mStopped) {
            return;
        }
        struct timeval now;
        struct timeval res;
        ::gettimeofday(&now, nullptr);
        timersub(&now, &mTs, &res);
        int64_t diff = res.tv_sec * 1000000LL + res.tv_usec;
        auto ret = sProfiles.emplace(mName, std::make_pair(1, diff));
        if (ret.second == false) {
            ret.first->second.first += 1;
            ret.first->second.second += diff;
        }
        mStopped = true;
    }

    ~ProfileTimer() {
        stop();
    }

    static void showProfiles() {
        for (auto it = sProfiles.begin(); it != sProfiles.end(); ++it) {
            std::cout << it->first <<
                      ": (" << it->second.first <<  ", " << it->second.second << ")" <<std::endl;
        }
    }
};

} // namespace android::codec2::benchmark
