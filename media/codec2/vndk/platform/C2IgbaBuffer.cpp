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
//#define LOG_NDEBUG 0
#define LOG_TAG "C2IgbaBuffer"
#include <aidl/android/hardware/media/c2/IGraphicBufferAllocator.h>
#include <android/hardware_buffer.h>
#include <utils/Log.h>

#include <C2BlockInternal.h>
#include <C2FenceFactory.h>
#include <C2IgbaBufferPriv.h>
#include <C2IgbaWaitableObj.h>
#include <C2PlatformSupport.h>

using C2IGBA = ::aidl::android::hardware::media::c2::IGraphicBufferAllocator;

namespace {
int32_t static inline ToAidl(uint32_t u) {return static_cast<int32_t>(u);}
int64_t static inline ToAidl(uint64_t u) {return static_cast<int64_t>(u);}
}

struct C2IgbaBlockPoolData : public _C2BlockPoolData {

    C2IgbaBlockPoolData(const AHardwareBuffer *buffer) : mBuffer(buffer) {}

    virtual ~C2IgbaBlockPoolData() override {
        if (mBuffer) {
            AHardwareBuffer_release(const_cast<AHardwareBuffer *>(mBuffer));
        }
    }

    virtual type_t getType() const override {
        return TYPE_AHWBUFFER;
    }
private:
    const AHardwareBuffer *mBuffer;
};

std::shared_ptr<C2GraphicBlock> _C2BlockFactory::CreateGraphicBlock(const AHardwareBuffer *pBuf) {
    // TODO
    C2IgbaBlockPoolData pooldata(pBuf);
    return nullptr;
}

C2IgbaBlockPool::C2IgbaBlockPool(
        const std::shared_ptr<C2IGBA> &igba,
        const local_id_t localId) : mIgba(igba), mLocalId(localId) {
    if (!mIgba) {
        mValid = false;
        return;
    }
    C2IGBA::WaitableFds fds;
    ::ndk::ScopedAStatus status = mIgba->getWaitableFds(&fds);
    if (!status.isOk()) {
        mValid = false;
        return;
    }
    mWaitableObj = std::make_shared<C2IgbaWaitableObj>(
            fds.statusEvent.release(), fds.allocEvent.release());
    if (!mWaitableObj || !mWaitableObj->valid()) {
        mValid = false;
        return;
    }
    mValid = true;
}

C2Allocator::id_t C2IgbaBlockPool::getAllocatorId() const {
  return ::android::C2PlatformAllocatorStore::IGBA;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block) {
    (void) width;
    (void) height;
    (void) format;
    (void) usage;
    (void)block;
    return C2_OMITTED;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block,
        C2Fence *fence) {
    if (!mValid) {
        return C2_BAD_STATE;
    }
    bool hangUp = false;
    bool allocatable = false;
    if (!mWaitableObj->waitEvent(0LL, &hangUp, &allocatable)) {
        return C2_CANCELED;
    }
    if (hangUp) {
        mValid = false;
        return C2_BAD_STATE;
    }
    if (!allocatable) {
        *fence = _C2FenceFactory::CreateEventFence(mWaitableObj);
        return C2_BLOCKING;
    }
    ::android::C2AndroidMemoryUsage memUsage{usage};
    C2IGBA::Description desc{
        ToAidl(width), ToAidl(height), ToAidl(format), ToAidl(memUsage.asGrallocUsage())};
    C2IGBA::Allocation allocation;
    ::ndk::ScopedAStatus status = mIgba->allocate(desc, &allocation);
    if (!status.isOk()) {
        binder_exception_t ex = status.getExceptionCode();
        if (ex == EX_SERVICE_SPECIFIC) {
            c2_status_t err = static_cast<c2_status_t>(status.getServiceSpecificError());
            if (err == C2_BLOCKING) {
                *fence = _C2FenceFactory::CreateEventFence(mWaitableObj);
            }
            return err;
        } else {
            ALOGW("igba::allocate transaction failed: %d", ex);
            return C2_CORRUPTED;
        }
    }

    /* TODO:
    *fence = _C2FenceFactory::CreateSyncFence(allocation.fence.release());
    *block = _C2BlockFactory::CreateGraphicBlock(allocation.buffer.release());
    return C2_OK;
    */
    (void)block;
    return C2_OMITTED;
}

void C2IgbaBlockPool::invalidate() {
    mValid = false;
}


