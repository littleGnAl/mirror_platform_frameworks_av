/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "DescramblerHalWrapper"

#include "include/IDescramblerHal.h"
#include <aidlcommonsupport/NativeHandle.h>
#include <android/binder_manager.h>
#include <string>

namespace android {
using NativeHandleAidl = ::aidl::android::hardware::common::NativeHandle;
using hardware::cas::native::V1_0::BnHwDescrambler;
using hardware::cas::native::V1_0::BpHwDescrambler;
using ndk::SpAIBinder;
struct JHwRemoteBinder;

IDescramblerHal::IDescramblerHal() {
    mDescramblerAidl = NULL;
    mDescramblerHidl = NULL;
}

IDescramblerHal::~IDescramblerHal() {
    if (mDescramblerAidl != NULL) {
        mDescramblerAidl.reset();
    }
    if (mDescramblerHidl != NULL) {
        mDescramblerHidl.clear();
    }
}

bool IDescramblerHal::init(sp<hardware::IBinder> hwBinder) {
    const std::string aidlService = std::string() + IDescramblerAidl::descriptor + "/default";
    if (AServiceManager_isDeclared(aidlService.c_str())) {
        SpAIBinder binder(AServiceManager_waitForService(aidlService.c_str()));
        mDescramblerAidl = IDescramblerAidl::fromBinder(binder);
    } else {
        if (hwBinder != NULL) {
            mDescramblerHidl =
                    hardware::fromBinder<IDescramblerHidl, BpHwDescrambler, BnHwDescrambler>(
                            hwBinder);
        }
        if (mDescramblerHidl == NULL) {
            // Both HIDL and AIDL descramblers are unavailable.
            return false;
        }
    }
    return true;
}

hardware::Return<void> IDescramblerHal::descramble(
        ScramblingControlHidl scramblingControlHidl, const hidl_vec<SubSampleHidl>& subSamplesHidl,
        SharedBufferHidl& srcBufferHidl, int64_t srcOffset, DestinationBufferHidl& dstBufferHidl,
        int64_t dstOffset, IDescramblerHidl::descramble_cb callback) {
    if (mDescramblerAidl != NULL) {
        int retVal;
        ndk::ScopedAStatus status;
        ScramblingControl scramblingControl;
        switch (scramblingControlHidl) {
            case ScramblingControlHidl::UNSCRAMBLED:
                scramblingControl = ScramblingControl::UNSCRAMBLED;
                break;
            case ScramblingControlHidl::RESERVED:
                scramblingControl = ScramblingControl::RESERVED;
                break;
            case ScramblingControlHidl::EVENKEY:
                scramblingControl = ScramblingControl::EVENKEY;
                break;
            case ScramblingControlHidl::ODDKEY:
                scramblingControl = ScramblingControl::ODDKEY;
                break;
        }
        std::vector<SubSample> subSamples;
        for (int i = 0; i < subSamplesHidl.size(); i++) {
            SubSample subSample;
            SubSampleHidl subSampleHidl = subSamplesHidl[i];
            subSample.numBytesOfClearData = subSampleHidl.numBytesOfClearData;
            subSample.numBytesOfEncryptedData = subSampleHidl.numBytesOfEncryptedData;
            subSamples.push_back(subSample);
        }

        NativeHandleAidl handle = ::android::dupToAidl(srcBufferHidl.heapBase.handle());
        SharedBuffer srcBuffer = {.heapBase.fd = handle.fds[0].dup(),
                                  .heapBase.size = static_cast<int64_t>(srcBufferHidl.size),
                                  .offset = static_cast<int64_t>(srcBufferHidl.offset),
                                  .size = static_cast<int64_t>(srcBufferHidl.size)};
        DestinationBuffer dstBuffer;
        if (dstBufferHidl.type == hardware::cas::native::V1_0::BufferType::SHARED_MEMORY) {
            dstBuffer.set<DestinationBuffer::Tag::nonsecureMemory>(std::move(srcBuffer));
        } else {
            dstBuffer.set<DestinationBuffer::Tag::secureMemory>(
                    std::move(::android::dupToAidl(dstBufferHidl.secureMemory)));
        }

        status = mDescramblerAidl->descramble(scramblingControl, subSamples, srcBuffer, srcOffset,
                                              dstBuffer, dstOffset, &retVal);
        if (status.isOk()) {
            return hardware::Status::ok();
        } else {
            return hardware::Status::fromExceptionCode(static_cast<int>(status.getExceptionCode()));
        }
    } else if (mDescramblerHidl != NULL) {
        return mDescramblerHidl->descramble(scramblingControlHidl, subSamplesHidl, srcBufferHidl,
                                            srcOffset, dstBufferHidl, dstOffset, callback);

    } else {
        // No descrambler configured
        return hardware::Status::fromExceptionCode(hardware::Status::Exception::EX_NULL_POINTER);
    }
}

}  // namespace android
