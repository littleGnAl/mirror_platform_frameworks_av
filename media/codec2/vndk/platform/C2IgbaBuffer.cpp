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
// #include <android/hardware_buffer.h>
#include <utils/Log.h>

#include <C2IgbaBufferPriv.h>

C2IgbaBlockPool::C2IgbaBlockPool(
        const std::shared_ptr<C2AidlIGraphicBufferAllocator> &igba,
        const local_id_t localId) : mIgba(igba), mLocalId(localId) {
}

C2Allocator::id_t C2IgbaBlockPool::getAllocatorId() const {
    return 0;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block) {
    (void) width;
    (void) height;
    (void) format;
    (void) usage;
    (void) block;
    return C2_OMITTED;
}

c2_status_t C2IgbaBlockPool::fetchGraphicBlock(
        uint32_t width, uint32_t height, uint32_t format,
        C2MemoryUsage usage, std::shared_ptr<C2GraphicBlock> *block,
        C2Fence *fence) {
    (void) width;
    (void) height;
    (void) format;
    (void) usage;
    (void) block;
    (void) fence;
    return C2_OMITTED;
}

void C2IgbaBlockPool::invalidate() {
    mValid = false;
}


