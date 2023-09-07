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
#include <vndk/hardware_buffer.h>
#include <utils/Log.h>

#include <C2AllocatorGralloc.h>
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

C2IgbaBlockPoolData::C2IgbaBlockPoolData(const AHardwareBuffer *buffer) : mBuffer(buffer) {}

C2IgbaBlockPoolData::~C2IgbaBlockPoolData() {
    if (mBuffer) {
        AHardwareBuffer_release(const_cast<AHardwareBuffer *>(mBuffer));
    }
}

C2IgbaBlockPoolData::type_t C2IgbaBlockPoolData::getType() const {
    return TYPE_AHWBUFFER;
}

void C2IgbaBlockPoolData::getAHardwareBuffer(AHardwareBuffer **pBuf) const {
    *pBuf = const_cast<AHardwareBuffer *>(mBuffer);
    AHardwareBuffer_acquire(*pBuf);
}

std::shared_ptr<C2GraphicBlock> _C2BlockFactory::CreateGraphicBlock(const AHardwareBuffer *pBuf) {
    // TODO
    C2IgbaBlockPoolData pooldata(pBuf);
    return nullptr;
}

bool _C2BlockFactory::GetAHardwareBuffer(
        const std::shared_ptr<const _C2BlockPoolData>& data,
        AHardwareBuffer **pBuf) {
    if (data && data->getType() == _C2BlockPoolData::TYPE_AHWBUFFER) {
        const std::shared_ptr<const C2IgbaBlockPoolData> poolData =
                std::static_pointer_cast<const C2IgbaBlockPoolData>(data);
        poolData->getAHardwareBuffer(pBuf);
        return true;
    }
    return false;
}

C2IgbaBlockPool::C2IgbaBlockPool(
        const std::shared_ptr<C2Allocator> &allocator,
        const std::shared_ptr<C2IGBA> &igba,
        const local_id_t localId) : mAllocator(allocator), mIgba(igba), mLocalId(localId) {
    if (!mIgba) {
        mValid = false;
        return;
    }
    ::ndk::ScopedFileDescriptor fd;
    ::ndk::ScopedAStatus status = mIgba->getWaitableFd(&fd);
    if (!status.isOk()) {
        mValid = false;
        return;
    }
    mWaitableObj = std::make_shared<C2IgbaWaitableObj>(fd.release());
    if (!mWaitableObj || !mWaitableObj->valid()) {
        mValid = false;
        return;
    }
    mValid = true;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block) {
    C2Fence fence;
    c2_status_t ret;
    constexpr static int kMaxTryNum = 2;
    for (int i = 0; i < kMaxTryNum; ++i) {
        ret = fetchGraphicBlock(width, height, format, usage, block, &fence);
        if (ret == C2_OK) {
            // TODO: incorporate C2Fence to C2Block(map api can utilize it).
            if (fence.wait(-1) != C2_OK) {
                //
            }
            return C2_OK;
        }
        if (ret == C2_BLOCKING) {
            if (i == 0) {
                (void)fence.wait(-1);
                continue;
            }
            else {
                return C2_TIMED_OUT;
            }
        }
        return ret;
    }
    return ret;
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
        *fence = _C2FenceFactory::CreatePipeFence(mWaitableObj);
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
                *fence = _C2FenceFactory::CreatePipeFence(mWaitableObj);
            }
            return err;
        } else {
            ALOGW("igba::allocate transaction failed: %d", ex);
            return C2_CORRUPTED;
        }
    }

    AHardwareBuffer_Desc rdesc;
    uint64_t origId = 0;
    *fence = _C2FenceFactory::CreateSyncFence(allocation.fence.release());
    AHardwareBuffer *ahwb = allocation.buffer.release();
    // TODO: unmark after sdk 31 or above is finished.
    // int ret = AHardwareBuffer_getId(ahwb, &origId);
    int ret = -1;
    if (ahwb == nullptr || ret != ::android::OK) {
        ALOGE("Cannot extract a proper AHwb from a successful AIDL call");
        if (ahwb) {
            AHardwareBuffer_release(ahwb);
        }
        return C2_CORRUPTED;
    }
    AHardwareBuffer_describe(ahwb, &rdesc);
    const native_handle_t *handle = AHardwareBuffer_getNativeHandle(ahwb);
    C2Handle *c2Handle = android::WrapNativeCodec2AhwbHandle(
          handle,
          rdesc.width,
          rdesc.height,
          rdesc.format,
          rdesc.usage,
          rdesc.stride,
          origId);
    if (!c2Handle) {
        AHardwareBuffer_release(ahwb);
        return C2_NO_MEMORY;
    }
    std::shared_ptr<C2GraphicAllocation> alloc;
    c2_status_t err = mAllocator->priorGraphicAllocation(c2Handle, &alloc);
    if (err != C2_OK) {
        native_handle_close(c2Handle);
        native_handle_delete(c2Handle);
        AHardwareBuffer_release(ahwb);
        return err;
    }
    std::shared_ptr<C2IgbaBlockPoolData> poolData =
            std::make_shared<C2IgbaBlockPoolData>(ahwb);
    *block = _C2BlockFactory::CreateGraphicBlock(alloc, poolData);
    return C2_OK;
}

void C2IgbaBlockPool::invalidate() {
    mValid = false;
}


