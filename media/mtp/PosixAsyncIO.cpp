/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <android-base/logging.h>
#include <memory>
#include <pthread.h>
#include <queue>
#include <thread>
#include <unistd.h>

#include "PosixAsyncIO.h"

namespace {

std::thread worker_thread;
std::deque<struct aiocb*> global_work;
bool suspended = true;
int aiocb_refcount = 0;
std::mutex global_lock;
std::condition_variable global_cv;

void work_func(void *) {
    pthread_setname_np(pthread_self(), "AsyncIO work");
    while (true) {
        struct aiocb *aiocbp;
        {
            std::unique_lock<std::mutex> lk(global_lock);
            global_cv.wait(lk, []{return global_work.size() > 0 || suspended;});
            if (suspended)
                return;
            aiocbp = global_work.back();
            global_work.pop_back();
        }
        CHECK(aiocbp->queued);
        int ret;
        if (aiocbp->read) {
            ret = TEMP_FAILURE_RETRY(pread(aiocbp->aio_fildes,
                    aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
        } else {
            ret = TEMP_FAILURE_RETRY(pwrite(aiocbp->aio_fildes,
               aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
        }
        {
            std::unique_lock<std::mutex> lk(aiocbp->lock);
            aiocbp->ret = ret;
            if (aiocbp->ret == -1) {
                aiocbp->error = errno;
            }
            aiocbp->queued = false;
        }
        aiocbp->cv.notify_all();
    }
}

int aio_add(struct aiocb *aiocbp) {
    CHECK(!aiocbp->queued);
    aiocbp->queued = true;
    {
        std::unique_lock<std::mutex> lk(global_lock);
        global_work.push_front(aiocbp);
    }
    global_cv.notify_one();
    return 0;
}

} // end anonymous namespace

aiocb::aiocb() {
    this->ret = 0;
    {
        std::unique_lock<std::mutex> lk(global_lock);
        if (aiocb_refcount == 0) {
            CHECK(global_work.size() == 0);
            CHECK(suspended);
            suspended = false;
            worker_thread = std::thread(work_func, nullptr);
        }
        aiocb_refcount++;
    }
}

aiocb::~aiocb() {
    CHECK(!this->queued);
    {
        std::unique_lock<std::mutex> lk(global_lock);
        CHECK(!suspended);
        if (aiocb_refcount == 1) {
            CHECK(global_work.size() == 0);
            suspended = true;
            lk.unlock();
            global_cv.notify_one();
            worker_thread.join();
            lk.lock();
        }
        aiocb_refcount--;
    }
}

int aio_read(struct aiocb *aiocbp) {
    aiocbp->read = true;
    return aio_add(aiocbp);
}

int aio_write(struct aiocb *aiocbp) {
    aiocbp->read = false;
    return aio_add(aiocbp);
}

int aio_error(const struct aiocb *aiocbp) {
    return aiocbp->error;
}

ssize_t aio_return(struct aiocb *aiocbp) {
    return aiocbp->ret;
}

int aio_suspend(struct aiocb *aiocbp[], int n,
        const struct timespec *) {
    for (int i = 0; i < n; i++) {
        {
            std::unique_lock<std::mutex> lk(aiocbp[i]->lock);
            aiocbp[i]->cv.wait(lk, [aiocbp, i]{return !aiocbp[i]->queued;});
        }
    }
    return 0;
}

void aio_prepare(struct aiocb *aiocbp, void* buf, size_t count, off_t offset) {
    aiocbp->aio_buf = buf;
    aiocbp->aio_offset = offset;
    aiocbp->aio_nbytes = count;
}
