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

#include <android-base/unique_fd.h>
#include <media/stagefright/foundation/ABase.h>

#include <atomic>

/**
 * The class provides waiting mechanism for being ready to allocate from IGBA.
 * Fds created by eventfd() are used for polling errors and/or being ready to
 * allocate.
 */
class C2IgbaWaitableObj {
public:
    explicit C2IgbaWaitableObj(int statusEventFd, int allocEventFd);

    ~C2IgbaWaitableObj() = default;

    /**
     * Waits for hanging up or being ready to allocate until the specified
     * duration.
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

private:
    DISALLOW_EVIL_CONSTRUCTORS(C2IgbaWaitableObj);

    mutable std::atomic<bool> mValid;
    ::android::base::unique_fd mStatusEventFd;
    ::android::base::unique_fd mAllocEventFd;
};

