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
public:
    MultiAccessUnitHandler(
            const std::shared_ptr<MultiAccessUnitInterface>& intf);

    virtual ~MultiAccessUnitHandler();

    static bool isEnabledOnPlatform();

    /*
     * Scatters the incoming linear buffer into access-unit sized buffers
     * based on the acccess-unit info.
     */
    c2_status_t scatter(
            std::list<std::unique_ptr<C2Work>> &c2workItems,
            std::list<std::list<std::unique_ptr<C2Work>>> * const processedWork);

    /*
     * Gathers different access-units into a single buffer based on the scatter list
     * and the configured max and threshold sizes. This also generates the associated
     * access-unit information and attach it with the final result.
     */
    c2_status_t gather(
            std::list<std::unique_ptr<C2Work>> &c2workItems,
            std::list<std::unique_ptr<C2Work>> * const processedWork);

    /*
     * Flushes the codec and generated the list of flushed buffers.
     */
    c2_status_t flush(
            std::list<std::unique_ptr<C2Work>> * const c2flushedWorks);

    /*
     * Gets all the pending buffers under generation in c2workItems.
     */
    c2_status_t error(std::list<std::unique_ptr<C2Work>> * const c2workItems);

    /*
     * Get the interface object of this handler.
     */
    std::shared_ptr<MultiAccessUnitInterface> getInterface();

    /*
     * Gets the status of the object. This really is to make sure that
     * all the allocators are configured properly within the handler.
     */
    bool getStatus();

    /*
     * Resets the structures inside the handler.
     */
    void reset();



    protected:

    struct MultiAccessUnitInfo {
        /*
         * From the input
         * Ordinal of the input frame
         */
        C2WorkOrdinalStruct inOrdinal;

        /*
         * Frame indexes of the scattered buffers
         */
        std::set<uint64_t> mComponentFrameIds;

        /*
         * For the output
         * Current output block.
         */
        std::shared_ptr<C2LinearBlock> mBlock;

        /*
         * Write view of current block
         */
        std::shared_ptr<C2WriteView> mWview;

        /*
         * C2Info related to the current mBlock
         */
        std::vector<std::shared_ptr<const C2Info>> mInfos;

        /*
         * C2AccessUnitInfos for the current buffer
         */
        std::vector<C2AccessUnitInfosStruct> mAccessUnitInfos;

        /*
         * Current tuning used to process this input work
         */
        C2LargeFrame::output mLargeFrameTuning;

        /*
         * Current output C2Work being processed
         */
        std::unique_ptr<C2Work> mLargeWork;

        MultiAccessUnitInfo(C2WorkOrdinalStruct ordinal):inOrdinal(ordinal) {

        }

        /*
         * Resets this frame
         */
        void reset();
    };

    /*
     * Creates a linear block to be used with work
     */
    c2_status_t createLinearBlock(MultiAccessUnitInfo &frame);

    c2_status_t processWorklets(MultiAccessUnitInfo &frame,
                std::unique_ptr<C2Work> &work,
                const std::function <void(std::unique_ptr<C2Work>&)> &addWork);

    c2_status_t finalizeWork(MultiAccessUnitInfo &frame);

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
