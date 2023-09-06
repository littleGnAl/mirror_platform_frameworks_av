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

#include <C2.h>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>

#include <atomic>

/**
 * The class provides waiting mechanism for being ready to allocate from IGBA.
 * The class uses one file descriptor which is created by pipe2() syscall.
 * The file descriptor are used for polling errors and/or being ready to
 * allocate.
 */
class C2IgbaWaitableObj {
public:
    explicit C2IgbaWaitableObj(int pipeFd);

    ~C2IgbaWaitableObj() = default;

    /**
     * Verify the class is valid. This should not be used for polling and/or
     * monitoring since the interface will not update status.
     *
     * @return  {@code true} if valid
     *          {@code false} otherwise.
     */
    bool valid() const;

    /**
     * Waits for hanging up or being ready to allocate until the specified
     * duration. If waiting duration is negative, this will wait indefinitely.
     *
     * @param timeoutNs   timeout in nanoseconds
     * @param hangUp      {@code true} when hanging up happened
     *                    {@code false} otherwise
     * @param allocatable {@code true} when IGBA is being ready to allocate
     *                    {@code false} otherwise.
     *
     * @return  {@code true} when any event occurred
     *          {@code false} otherwise(timeout)
     */
    bool waitEvent(c2_nsecs_t timeoutNs, bool *hangUp, bool *allocatable);

    /**
     * Returns the underlying file descriptor.
     * Note: the returned fd is not dup-ed. careful life-cycle management or
     * dup() is necessary.
     */
    int fd() const;

private:
    DISALLOW_COPY_AND_ASSIGN(C2IgbaWaitableObj);

    mutable std::atomic<bool> mValid;
    ::android::base::unique_fd mPipeFd;
};

