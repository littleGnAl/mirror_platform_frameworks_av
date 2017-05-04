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
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <sys/syscall.h>
#include <unistd.h>

#include "AsyncIO.h"

namespace {

void read_func(struct aiocb *aiocbp) {
    aiocbp->ret = TEMP_FAILURE_RETRY(pread(aiocbp->aio_fildes,
                aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
    if (aiocbp->ret == -1) aiocbp->error = errno;
}

void write_func(struct aiocb *aiocbp) {
    aiocbp->ret = TEMP_FAILURE_RETRY(pwrite(aiocbp->aio_fildes,
                aiocbp->aio_buf, aiocbp->aio_nbytes, aiocbp->aio_offset));
    if (aiocbp->ret == -1) aiocbp->error = errno;
}

} // end anonymous namespace

aiocb::~aiocb() {
    CHECK(!thread.joinable());
}

int aio_read(struct aiocb *aiocbp) {
    aiocbp->thread = std::thread(read_func, aiocbp);
    return 0;
}

int aio_write(struct aiocb *aiocbp) {
    aiocbp->thread = std::thread(write_func, aiocbp);
    return 0;
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
        aiocbp[i]->thread.join();
    }
    return 0;
}

void aio_prepare(struct aiocb *aiocbp, void* buf, size_t count, off_t offset) {
    aiocbp->aio_buf = buf;
    aiocbp->aio_offset = offset;
    aiocbp->aio_nbytes = count;
}

int io_setup(unsigned nr, aio_context_t *ctxp) {
    return syscall(__NR_io_setup, nr, ctxp);
}

int io_destroy(aio_context_t ctx) {
    return syscall(__NR_io_destroy, ctx);
}

int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) {
    return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
                struct io_event *events, struct timespec *timeout) {
    return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}

int io_cancel(aio_context_t ctx, struct iocb *iocbp, struct io_event *result) {
    return syscall(__NR_io_cancel, ctx, iocbp, result);
}

void io_prep_pread(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IOCB_CMD_PREAD;
    iocb->aio_reqprio = 0;
    iocb->aio_buf = reinterpret_cast<unsigned long long>(buf);
    iocb->aio_nbytes = count;
    iocb->aio_offset = offset;
}

void io_prep_pwrite(struct iocb *iocb, int fd, void *buf, size_t count, long long offset)
{
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IOCB_CMD_PWRITE;
    iocb->aio_reqprio = 0;
    iocb->aio_buf = reinterpret_cast<unsigned long long>(buf);
    iocb->aio_nbytes = count;
    iocb->aio_offset = offset;
}
