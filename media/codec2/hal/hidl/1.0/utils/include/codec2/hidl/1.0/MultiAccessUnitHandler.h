/*
 * Copyright 2023 The Android Open Source Project
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

#ifndef CODEC2_HIDL_V1_0_UTILS_MULTI_ACCESSUNIT_HANDLER_H
#define CODEC2_HIDL_V1_0_UTILS_MULTI_ACCESSUNIT_HANDLER_H

#include <codec2/hidl/1.0/ComponentInterface.h>
#include <codec2/hidl/1.0/types.h>

#include <hidl/Status.h>
#include <hwbinder/IBinder.h>

#include <C2Buffer.h>
#include <C2.h>

#include <set>
#include <memory>
#include <mutex>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

struct MultiAccessUnitHandler {
    MultiAccessUnitHandler(
            const std::shared_ptr<MultiAccessUnitInterface>& intf);

    virtual ~MultiAccessUnitHandler();

    std::shared_ptr<MultiAccessUnitInterface> getInterface();

    bool getStatus();

    void reset();

    c2_status_t preProcessWork(
            std::list<std::unique_ptr<C2Work>> &largeWork,
            std::list<std::list<std::unique_ptr<C2Work>>> *processedWork);

    void postProcessWork(
            std::list<std::unique_ptr<C2Work>> &c2workItems,
            std::list<std::unique_ptr<C2Work>> *processedWork);

    c2_status_t processFlushWork(
            std::list<std::unique_ptr<C2Work>> *c2flushedWorks);

    protected:

    struct MultiAccessUnitInfo {
        // From the input
        // Ordinal from the input frame
        C2WorkOrdinalStruct inOrdinal;
        std::set<uint64_t> mComponentFrameIds;
        // For the output
        // Current block getting filled
        std::shared_ptr<C2LinearBlock> mBlock;
        // Write view of current block
        std::shared_ptr<C2WriteView> mWview;
        // C2Info related to the current mBlock
        std::vector<std::shared_ptr<const C2Info>> mInfos;
        // C2AccessUnitInfos for the curent buffer
        std::vector<C2AccessUnitInfosStruct> mAccessUnitInfos;
        // Current tuning used to to process this input work
        C2LargeFrame::output mLargeFrameTuning;
        // Current output work being processed
        std::unique_ptr<C2Work> mLargeWork;
        static MultiAccessUnitInfo CreateEmptyFrame(
                C2WorkOrdinalStruct& ordinal) {
            MultiAccessUnitInfo info{
                ordinal,
                std::set<uint64_t>(),
                nullptr,
                nullptr,
                std::vector<std::shared_ptr<const C2Info>>(),
                std::vector<C2AccessUnitInfosStruct>(),
                {},
                nullptr
            };
            return info;
        }

        void reset() {
            mBlock.reset();
            mWview.reset();
            mInfos.clear();
            mAccessUnitInfos.clear();
            mLargeWork.reset();
        }
    };

    c2_status_t createLinearBlock(MultiAccessUnitInfo& frame);

    c2_status_t processLargeAudioWorklets(MultiAccessUnitInfo& frame,
                std::unique_ptr<C2Work>& work,
                const std::function <void(std::unique_ptr<C2Work>&)>& addWork);

    c2_status_t finalizeWork(MultiAccessUnitInfo& frame);

    bool mInit;
    std::shared_ptr<MultiAccessUnitInterface> mInterface;

    C2BlockPool::local_id_t mBlockPoolId;
    std::shared_ptr<C2BlockPool> mLinearPool;
    std::shared_ptr<C2Allocator> mLinearAllocator;

    std::atomic_uint64_t mFrameIndex;

    std::mutex mLock;
    std::list<MultiAccessUnitInfo> mFrameHolder;
};

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

#endif  // CODEC2_HIDL_V1_0_UTILS_MULTI_ACCESSUNIT_HANDLER_H
