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

#define LOG_TAG "MediaUtils"
#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <cutils/properties.h>
#include <dlfcn.h>
#include <sys/resource.h>
#include <unistd.h>
#include <utils/Mutex.h>

#include "MediaUtils.h"

extern "C" size_t __cfi_shadow_size();
extern "C" void __scudo_set_rss_limit(size_t, int) __attribute__((weak));

#ifdef __aarch64__

namespace {

android::Mutex gRLimit;

void adjustAddressSpaceLimitBy(ssize_t delta) {
  android::Mutex::Autolock rlimitLock(gRLimit);
  struct rlimit limit;
  getrlimit(RLIMIT_AS, &limit);
  if (limit.rlim_cur == SIZE_MAX) return;
  limit.rlim_cur += delta;
  setrlimit(RLIMIT_AS, &limit);
}

}

// Processes that use limitProcessMemory must also arrange to adjust RLIMIT_AS
// on thread entry and exit in order to accommodate the address space consumed
// by each thread's shadow call stack guard region. This is done by intercepting
// pthread_create and pthread_exit (which is called internally by libc on thread
// termination).
const auto real_pthread_create = reinterpret_cast<int (*)(
        pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg)>(
        dlsym(RTLD_NEXT, "pthread_create"));
const auto real_pthread_exit =
        reinterpret_cast<void (*)(void* retval)>(dlsym(RTLD_NEXT, "pthread_exit"));

extern "C" int pthread_create(pthread_t* thread, const pthread_attr_t* attr,
                              void* (*start_routine)(void*), void* arg) {
    // TODO(pcc): Add an API to bionic to let us access the guard region size and use it here.
    adjustAddressSpaceLimitBy(16*1024*1024);
    return real_pthread_create(thread, attr, start_routine, arg);
}

extern "C" void pthread_exit(void* retval) {
    // TODO(pcc): Add an API to bionic to let us access the guard region size and use it here.
    adjustAddressSpaceLimitBy(-16*1024*1024);
    return real_pthread_exit(retval);
}

#endif

namespace android {

void limitProcessMemory(
    const char *property,
    size_t numberOfBytes,
    size_t percentageOfTotalMem) {

    if (running_with_asan()) {
        ALOGW("Running with (HW)ASan, skip enforcing memory limitations.");
        return;
    }

    long pageSize = sysconf(_SC_PAGESIZE);
    long numPages = sysconf(_SC_PHYS_PAGES);
    size_t maxMem = SIZE_MAX;

    if (pageSize > 0 && numPages > 0) {
        if (size_t(numPages) < SIZE_MAX / size_t(pageSize)) {
            maxMem = size_t(numPages) * size_t(pageSize);
        }
        ALOGV("physMem: %zu", maxMem);
        if (percentageOfTotalMem > 100) {
            ALOGW("requested %zu%% of total memory, using 100%%", percentageOfTotalMem);
            percentageOfTotalMem = 100;
        }
        maxMem = maxMem / 100 * percentageOfTotalMem;
        if (numberOfBytes < maxMem) {
            maxMem = numberOfBytes;
        }
        ALOGV("requested limit: %zu", maxMem);
    } else {
        ALOGW("couldn't determine total RAM");
    }

    int64_t propVal = property_get_int64(property, maxMem);
    if (propVal > 0 && uint64_t(propVal) <= SIZE_MAX) {
        maxMem = propVal;
    }

    // If 64-bit Scudo is in use, enforce the hard RSS limit (in MB).
    if (maxMem != SIZE_MAX && sizeof(void *) == 8 &&
        &__scudo_set_rss_limit != 0) {
      __scudo_set_rss_limit(maxMem >> 20, 1);
      ALOGV("Scudo hard RSS limit set to %zu MB", maxMem >> 20);
      return;
    }

    // Increase by the size of the CFI shadow mapping. Most of the shadow is not
    // backed with physical pages, and it is possible for the result to be
    // higher than total physical memory. This is fine for RLIMIT_AS.
    size_t cfi_size = __cfi_shadow_size();
    if (cfi_size) {
      ALOGV("cfi shadow size: %zu", cfi_size);
      if (maxMem <= SIZE_MAX - cfi_size) {
        maxMem += cfi_size;
      } else {
        maxMem = SIZE_MAX;
      }
    }
    ALOGV("actual limit: %zu", maxMem);

    struct rlimit limit;
    getrlimit(RLIMIT_AS, &limit);
    ALOGV("original limits: %lld/%lld", (long long)limit.rlim_cur, (long long)limit.rlim_max);
    limit.rlim_cur = maxMem;
    setrlimit(RLIMIT_AS, &limit);
    limit.rlim_cur = -1;
    limit.rlim_max = -1;
    getrlimit(RLIMIT_AS, &limit);
    ALOGV("new limits: %lld/%lld", (long long)limit.rlim_cur, (long long)limit.rlim_max);

}

} // namespace android
