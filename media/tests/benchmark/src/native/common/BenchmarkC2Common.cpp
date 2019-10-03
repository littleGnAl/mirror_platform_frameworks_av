/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_NDEBUG 0
#define LOG_TAG "BenchmarkC2Common"

#include "BenchmarkC2Common.h"

int32_t BenchmarkC2Common::setupCodec2() {
    ALOGD("In %s", __func__);
    mClient = android::Codec2Client::CreateFromService("software");
    if (!mClient) return -1;

    std::shared_ptr<C2AllocatorStore> store = android::GetCodec2PlatformAllocatorStore();
    if (!store) return -1;

    c2_status_t status = store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator);
    if (status != C2_OK) return status;

    mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, mBlockPoolId++);
    if (!mLinearPool) return -1;

    status = store->fetchAllocator(C2AllocatorStore::DEFAULT_GRAPHIC, &mGraphicAllocator);
    if (status != C2_OK) return status;

    mGraphicPool = std::make_shared<C2PooledBlockPool>(mGraphicAllocator, mBlockPoolId++);
    if (!mGraphicPool) return -1;

    for (int i = 0; i < MAX_INPUT_BUFFERS; ++i) {
        mWorkQueue.emplace_back(new C2Work);
    }
    return status;
}

void BenchmarkC2Common::waitOnInputConsumption() {
    typedef std::unique_lock<std::mutex> ULock;
    uint32_t queueSize;
    uint32_t maxRetry = 0;
    {
        ULock l(mQueueLock);
        queueSize = mWorkQueue.size();
    }
    while ((maxRetry < MAX_RETRY) && (queueSize < MAX_INPUT_BUFFERS)) {
        ULock l(mQueueLock);
        if (queueSize != mWorkQueue.size()) {
            queueSize = mWorkQueue.size();
            maxRetry = 0;
        } else {
            mQueueCondition.wait_for(l, TIME_OUT);
            maxRetry++;
        }
    }
}