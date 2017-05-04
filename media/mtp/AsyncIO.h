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

#ifndef _ASYNCIO_H
#define _ASYNCIO_H

#include <linux/aio_abi.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <time.h>
#include <thread>
#include <unistd.h>

/**
 * Provides a subset of POSIX aio operations.
 */

struct aiocb {
    int aio_fildes;
    void *aio_buf;

    off_t aio_offset;
    size_t aio_nbytes;

    // Used internally
    std::thread thread;
    ssize_t ret;
    int error;

    ~aiocb();
};

// Submit a request for IO to be completed
int aio_read(struct aiocb *);
int aio_write(struct aiocb *);

// Suspend current thread until given IO is complete, at which point
// its return value and any errors can be accessed
// All submitted requests must have a corresponding suspend.
// aiocb->aio_buf must refer to valid memory until after the suspend call
int aio_suspend(struct aiocb *[], int, const struct timespec *);
int aio_error(const struct aiocb *);
ssize_t aio_return(struct aiocb *);

// Helper method for setting aiocb members
void aio_prepare(struct aiocb *, void*, size_t, off_t);

/**
 * Provides kernel aio operations.
 */

int io_setup(unsigned nr, aio_context_t *ctxp);
int io_destroy(aio_context_t ctx);
int io_submit(aio_context_t ctx, long nr,  struct iocb **iocbpp);
int io_getevents(aio_context_t ctx, long min_nr, long max_nr,
        struct io_event *events, struct timespec *timeout);
int io_cancel(aio_context_t ctx, struct iocb *, struct io_event *result);
void io_prep(struct iocb *iocb, int fd, void *buf, uint64_t count, int64_t offset, bool read);

#endif // ASYNCIO_H

