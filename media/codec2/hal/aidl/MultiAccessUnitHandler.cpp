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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-MultiAccessUnitHandler"
#include <android-base/logging.h>

#include <com_android_media_codec_flags.h>

#include <codec2/aidl/MultiAccessUnitHandler.h>
#include <android-base/properties.h>

#include <C2BufferPriv.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

namespace aidl {
namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace utils {

using namespace ::android;

class C2MultiAccessUnitBuffer : public C2Buffer {
    public:
        explicit C2MultiAccessUnitBuffer(
                const std::vector<C2ConstLinearBlock> &blocks):
                C2Buffer(blocks) {
        }
};

MultiAccessUnitHandler::MultiAccessUnitHandler(
        const std::shared_ptr<MultiAccessUnitInterface>& intf):
        mInit(false),
        mInterface(intf) {
    std::shared_ptr<C2AllocatorStore> store = GetCodec2PlatformAllocatorStore();
    if(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator) == C2_OK) {
        mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, ++mBlockPoolId);
        mInit = true;
    }
}

MultiAccessUnitHandler::~MultiAccessUnitHandler() {
    std::unique_lock<std::mutex> l(mLock);
    mFrameHolder.clear();
}

bool MultiAccessUnitHandler::isEnabledOnPlatform() {
    bool result = false;;
    if (com::android::media::codec::flags::provider_->large_audio_frame()) {
        result = ::android::base::GetBoolProperty("media.c2.large.audio.frame", true);
    }
    LOG(ERROR) << "MultiAccessUnitHandler " << (result ? "enabled" : "disabled");
    return result;
}

std::shared_ptr<MultiAccessUnitInterface> MultiAccessUnitHandler::getInterface() {
    return mInterface;
}

bool MultiAccessUnitHandler::getStatus() {
    return mInit;
}

void MultiAccessUnitHandler::reset() {
    std::lock_guard<std::mutex> l(mLock);
    mFrameHolder.clear();
}

c2_status_t MultiAccessUnitHandler::flush(
        std::list<std::unique_ptr<C2Work>>* const c2flushedWorks) {
    c2_status_t c2res = C2_OK;
    std::lock_guard<std::mutex> l(mLock);
    for (std::unique_ptr<C2Work>& w : *c2flushedWorks) {
        bool foundFlushedFrame = false;
        for (auto frame = mFrameHolder.begin() ;
                frame != mFrameHolder.end() && !foundFlushedFrame;) {
            auto it = frame->mComponentFrameIds.find(
                    w->input.ordinal.frameIndex.peekull());
            if (it != frame->mComponentFrameIds.end()) {
                LOG(DEBUG) << "Multi access-unit flush Replacing "
                        << w->input.ordinal.frameIndex.peekull()
                        << " with " << frame->inOrdinal.frameIndex.peekull();
                w->input.ordinal.frameIndex = frame->inOrdinal.frameIndex;
                bool removeEntry = w->worklets.empty()
                    || !w->worklets.front()
                    || (w->worklets.back()->output.flags & C2FrameData::FLAG_INCOMPLETE) == 0;
                if (removeEntry) {
                    frame->mComponentFrameIds.erase(it);
                }
                foundFlushedFrame = true;
            }
            if (frame->mComponentFrameIds.empty()) {
                frame = mFrameHolder.erase(frame);
            } else {
                ++frame;
            }
        }
    }
    return c2res;
}

c2_status_t MultiAccessUnitHandler::scatter(
        std::list<std::unique_ptr<C2Work>> &largeWork,
        std::list<std::list<std::unique_ptr<C2Work>>>* const processedWork) {
    LOG(DEBUG) << "Multiple access-unit: scatter process";
    if (processedWork == nullptr) {
        LOG(ERROR) << "MultiAccessUnitHandler provided with no work list";
        return C2_CORRUPTED;
    }
    for (std::unique_ptr<C2Work>& w : largeWork) {
        std::list<std::unique_ptr<C2Work>> sliceWork;
        C2WorkOrdinalStruct inputOrdinal = w->input.ordinal;
        // To hold correspondence and processing bits b/w input and output
        MultiAccessUnitInfo frameInfo(inputOrdinal);
        std::set<uint64_t>& frameSet = frameInfo.mComponentFrameIds;
        uint64_t newFrameIdx = mFrameIndex++;
        // TODO: Do not split buffers if component inherantly supports MultipleFrames.
        // if thats case, only replace frameindex.
        auto cloneInputWork = [&newFrameIdx](std::unique_ptr<C2Work>& inWork) {
            std::unique_ptr<C2Work> newWork(new C2Work);
            newWork->input.flags = inWork->input.flags;
            newWork->input.ordinal = inWork->input.ordinal;
            newWork->input.ordinal.frameIndex = newFrameIdx;
            if (!inWork->input.configUpdate.empty()) {
                //std::vector<std::unique_ptr<C2Param>> configUpdate;
                for (std::unique_ptr<C2Param>& param : inWork->input.configUpdate) {
                    newWork->input.configUpdate.push_back(
                            std::move(C2Param::Copy(*(param.get()))));
                }
            }
            newWork->input.infoBuffers = (inWork->input.infoBuffers);
            if (!inWork->worklets.empty() && inWork->worklets.front() != nullptr) {
                newWork->worklets.emplace_back(new C2Worklet);
                newWork->worklets.back()->component = inWork->worklets.front()->component;
                std::vector<std::unique_ptr<C2Tuning>> tunings;
                for (std::unique_ptr<C2Tuning>& tuning : inWork->worklets.front()->tunings) {
                    tunings.push_back(std::move(
                            std::unique_ptr<C2Tuning>(
                                    static_cast<C2Tuning*>(
                                            C2Param::Copy(*(tuning.get())).release()))));
                }
                newWork->worklets.front()->tunings = std::move(tunings);
            }
            return std::move(newWork);
        };
        if (w->input.buffers.empty()
                || (w->input.buffers.front() == nullptr)
                || (!w->input.buffers.front()->hasInfo(
                        C2AccessUnitInfos::input::PARAM_TYPE))) {
            LOG(DEBUG) << "Empty buffer scatter frames with frameIndex "
                    << inputOrdinal.frameIndex.peekull()
                    << ") -> newFrameIndex " << newFrameIdx
                    <<" : input ts " << inputOrdinal.timestamp.peekull();
            sliceWork.push_back(std::move(cloneInputWork(w)));
            if (!w->input.buffers.empty() && w->input.buffers.front() != nullptr) {
                sliceWork.back()->input.buffers = std::move(w->input.buffers);
            }
            frameSet.insert(newFrameIdx);
            processedWork->push_back(std::move(sliceWork));
        }  else {
            const std::vector<std::shared_ptr<C2Buffer>>& inBuffers = w->input.buffers;
            if (inBuffers.front() == nullptr ||
                    inBuffers.front()->data().linearBlocks().size() == 0) {
                LOG(ERROR) << "ERROR: Work has Large frame info but has no linear blocks.";
                return C2_CORRUPTED;
            }
            const std::vector<C2ConstLinearBlock>& multiAU =
                    inBuffers.front()->data().linearBlocks();
            std::shared_ptr<const C2AccessUnitInfos::input> auInfo =
                    std::static_pointer_cast<const C2AccessUnitInfos::input>(
                    w->input.buffers.front()->getInfo(C2AccessUnitInfos::input::PARAM_TYPE));
            uint32_t offset = 0; uint32_t multiAUSize = multiAU.front().size();
            for (int idx = 0; idx < auInfo->flexCount(); ++idx) {
                std::vector<C2ConstLinearBlock> au;
                const C2AccessUnitInfosStruct &info = auInfo->m.values[idx];
                std::unique_ptr<C2Work> newWork = cloneInputWork(w);
                newWork->input.ordinal.timestamp = info.timestamp;
                au.push_back(multiAU.front().subBlock(offset, info.size));
                newWork->input.buffers.push_back(
                        std::shared_ptr<C2Buffer>(new C2MultiAccessUnitBuffer(au)));
                LOG(DEBUG) << "Frame scatter queuing frames WITH info in ordinal "
                    << inputOrdinal.frameIndex.peekull()
                    << " total offset " << offset << " info.size " << info.size
                    << " : TS " << newWork->input.ordinal.timestamp.peekull();
                // add to worklist
                sliceWork.push_back(std::move(newWork));
                frameSet.insert(newFrameIdx);
                processedWork->push_back(std::move(sliceWork));
                offset += info.size;
                newFrameIdx = mFrameIndex++;
                if (offset > multiAUSize) {
                    LOG(ERROR) << "ERROR: access-unit offset > buffer size"
                            << " current offset " << offset
                            << " buffer size " << multiAUSize;
                    return C2_CORRUPTED;
                }
            }
        }
        if (!processedWork->empty()) {
            {
                frameInfo.mLargeFrameTuning = *(mInterface->get().get());
                std::lock_guard<std::mutex> l(mLock);
                mFrameHolder.push_back(std::move(frameInfo));
            }
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHandler::gather(
        std::list<std::unique_ptr<C2Work>> &c2workItems,
        std::list<std::unique_ptr<C2Work>>* const processedWork) {
    LOG(DEBUG) << "Multi access-unit gather process";
    if (processedWork == nullptr) {
        LOG(DEBUG) << "Nothing provided for processed work";
        return C2_CORRUPTED;
    }
    //std::list<std::unique_ptr<C2Work>> outWork;
    auto addOutWork = [&processedWork](std::unique_ptr<C2Work>& work) {
        processedWork->push_back(std::move(work));
    };
    // TODO: Do not do any gatering if the Multi access-unit configuration
    // has maxSize or thresholdSize as zero.
    {
        std::lock_guard<std::mutex> l(mLock);
        for (auto& work : c2workItems) {
            LOG(DEBUG) << "FrameHolder Size: " << mFrameHolder.size();
            uint64_t thisFrameIndex = work->input.ordinal.frameIndex.peekull();
            bool removeEntry = work->worklets.empty()
                    || !work->worklets.front()
                    || (work->worklets.back()->output.flags
                        & C2FrameData::FLAG_INCOMPLETE) == 0;
            bool foundFrame = false;
            for (auto frame = mFrameHolder.begin();
                    frame != mFrameHolder.end() && !foundFrame; frame++) {
                auto it = frame->mComponentFrameIds.find(thisFrameIndex);
                if (it != frame->mComponentFrameIds.end()) {
                    foundFrame = true;
                    LOG(DEBUG) << "onWorkDone ( in with o/p " << thisFrameIndex
                            << " worklstsSze " << work->worklets.size()
                            << ") -> " << frame->inOrdinal.frameIndex.peekull()
                            << " Flags: " << work->worklets.front()->output.flags;

                    if (removeEntry) {
                        LOG(DEBUG) << "Removing entry: " << thisFrameIndex
                                << " -> " << frame->inOrdinal.frameIndex.peekull();
                        frame->mComponentFrameIds.erase(it);
                    }
                    if (work->result != C2_OK ||
                            (frame->mLargeFrameTuning.thresholdSize == 0 ||
                            frame->mLargeFrameTuning.maxSize == 0)) {
                        if (frame->mLargeWork) {
                            finalizeWork(*frame);
                            addOutWork(frame->mLargeWork);
                        }
                        c2_status_t workResult = work->result;
                        frame->mLargeWork = std::move(work);
                        frame->mLargeWork->input.ordinal.frameIndex =
                                frame->inOrdinal.frameIndex;
                        finalizeWork(*frame);
                        addOutWork(frame->mLargeWork);
                        if (workResult != C2_OK) {
                            mFrameHolder.erase(frame);
                        }
                        continue;
                    }
                    if (C2_OK != processWorklets(*frame, work, addOutWork)) {
                        LOG(ERROR) << "Error while processing work";
                    }
                    if (frame->mComponentFrameIds.empty()) {
                        LOG(DEBUG) << "This frame is finished ID " << thisFrameIndex;
                        if (frame->mLargeWork) {
                            finalizeWork(*frame);
                            addOutWork(frame->mLargeWork);
                        }
                        mFrameHolder.erase(frame);
                    }
                } else {
                    LOG(DEBUG) << "Received an out-of-order output " << thisFrameIndex;
                }
            }
            if (!foundFrame) {
                LOG(ERROR) <<" Error: Frame Holder reports no frame " << thisFrameIndex;
            }
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHandler::error(
        std::list<std::unique_ptr<C2Work>> * const worklist) {
    if (worklist == nullptr) {
        LOG(ERROR) << "Provided null worklist for error";
        return C2_OK;
    }
    std::unique_lock<std::mutex> l(mLock);
    for (auto frame = mFrameHolder.begin(); frame != mFrameHolder.end(); frame++) {
        if (frame->mLargeWork) {
            finalizeWork(*frame);
            worklist->push_back(std::move(frame->mLargeWork));
            frame->reset();
        }
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHandler::createLinearBlock(MultiAccessUnitInfo &frame) {
    if (!mInit) {
        LOG(ERROR) << "Large buffer allocator failed";
        return C2_NO_MEMORY;
    }
    C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
    uint32_t maxOutSize = frame.mLargeFrameTuning.maxSize;
    c2_status_t err = mLinearPool->fetchLinearBlock(maxOutSize, usage, &frame.mBlock);
    if (err != C2_OK) {
        LOG(ERROR) << "Error allocating Multi access-unit Buffer";
        return err;
    }
    frame.mWview = std::make_shared<C2WriteView>(frame.mBlock->map().get());
    return C2_OK;
}

/*
 * For every work from the component, we try to do aggregation of work here.
*/
c2_status_t MultiAccessUnitHandler::processWorklets(MultiAccessUnitInfo &frame,
        std::unique_ptr<C2Work>& work,
        const std::function <void(std::unique_ptr<C2Work>&)>& addWork) {
    uint32_t maxOutSize = frame.mLargeFrameTuning.maxSize;
    uint32_t thresholdSize = frame.mLargeFrameTuning.thresholdSize;
    LOG(DEBUG) << "maxOutSize " << maxOutSize << " threshold " << thresholdSize;
    // This will allocate work, worklet, c2Block
    auto allocateWork = [&](MultiAccessUnitInfo &frame, bool allocateWorket = false) {
        c2_status_t ret = C2_OK;
        if (frame.mLargeWork == nullptr) {
            frame.mLargeWork.reset(new C2Work);
            frame.mLargeWork->input.ordinal.frameIndex = frame.inOrdinal.frameIndex;
        }
        if (allocateWorket) {
            if (frame.mLargeWork->worklets.size() == 0) {
                frame.mLargeWork->worklets.emplace_back(new C2Worklet);
                // worklet always has buffers ?
                ret = createLinearBlock(frame);
            }
        }
        return ret;
    };
    if (work->worklets.empty() || !work->worklets.front()) {
        LOG(DEBUG) << "Worklet is empty, sending processed work";
        if (frame.mLargeWork) {
            finalizeWork(frame);
            addWork(frame.mLargeWork);
        }
        frame.mLargeWork = std::move(work);
        frame.mLargeWork->input.ordinal = frame.inOrdinal;
        frame.mLargeWork->workletsProcessed = work->workletsProcessed;
        frame.mLargeWork->result = work->result;
        frame.mLargeWork->worklets.clear();
        finalizeWork(frame);
        addWork(frame.mLargeWork);
        return C2_OK;
    }
    // we will only have one worklet.
    bool foundEndOfStream = false;
    for (auto worklet = work->worklets.begin();
             worklet != work->worklets.end() && (*worklet) != nullptr; ++worklet) {
        c2_status_t c2ret = allocateWork(frame, true);
        if (c2ret != C2_OK) {
            if (frame.mLargeWork) {
                frame.mLargeWork->result = c2ret;
                finalizeWork(frame);
                addWork(frame.mLargeWork);
                frame.reset();
            }
            return c2ret;
        }
        std::optional<uint32_t> bufferIndex;
        uint32_t flagsForNoCopy = C2FrameData::FLAG_DISCARD_FRAME | C2FrameData::FLAG_CORRUPT;
        if (flagsForNoCopy & (*worklet)->output.flags) {
            if (frame.mLargeWork) {
                frame.reset();
                frame.mLargeWork = std::move(work);
                frame.mLargeWork->input.ordinal.frameIndex = frame.inOrdinal.frameIndex;
                finalizeWork(frame);
                addWork(frame.mLargeWork);
            }
            return C2_OK;
        }
        LOG(DEBUG) << "This worklet has " << (*worklet)->output.buffers.size() << " buffers"
                << " ts: " << (*worklet)->output.ordinal.timestamp.peekull();
        for (int bufIdx = 0; bufIdx < (*worklet)->output.buffers.size();
                bufferIndex ? bufIdx = bufferIndex.value() : ++bufIdx) {
            bufferIndex.reset();
            std::shared_ptr<C2Buffer>& buffer = (*worklet)->output.buffers[bufIdx];
            const std::vector<C2ConstLinearBlock>& blocks = buffer->data().linearBlocks();
            if (blocks.size() > 0 && thresholdSize > 0) {
                if (blocks.front().size() > frame.mWview->size()) {
                    LOG(ERROR) << "Output buffer too small for audio AU, configured with "
                            << maxOutSize << " block size: "
                            << blocks.front().size() << "alloc size "
                            << frame.mWview->size();
                    // send if we have any until now and then send error.
                    frame.mLargeWork->result = C2_NO_MEMORY;
                    frame.mLargeWork->worklets.clear();
                    finalizeWork(frame);
                    addWork(frame.mLargeWork);
                    frame.reset();
                    return C2_NO_MEMORY;
                }
                if ((frame.mWview->offset() + blocks.front().size()) > frame.mWview->size()) {
                    LOG(DEBUG) << "Large frame hitting bufer size for next frame alloc"
                            << frame.mWview->offset()
                            << "block size " << blocks.front().size();
                    frame.mLargeWork->result = C2_OK;
                    // update flags and send the buffer
                    finalizeWork(frame);
                    addWork(frame.mLargeWork);
                    frame.reset();
                    allocateWork(frame, true);
                    bufferIndex = bufIdx;
                    continue;
                }
                C2ReadView rView = blocks.front().map().get();
                if (rView.error()) {
                    LOG(ERROR) << "Buffer read view error";
                    // assign flag corrupted.
                    frame.mLargeWork->result = rView.error();
                    frame.mLargeWork->worklets.clear();
                    finalizeWork(frame);
                    addWork(frame.mLargeWork);
                    frame.reset();
                    return C2_NO_MEMORY;
                }
                memcpy(frame.mWview->data(), rView.data(), blocks.front().size());
                frame.mWview->setOffset(frame.mWview->offset() + blocks.front().size());
                // TODO: copy output frameindex? No take the index from inOrdinal
                frame.mAccessUnitInfos.emplace_back(
                        (*worklet)->output.flags,
                        blocks.front().size(),
                        (*worklet)->output.ordinal.timestamp.peekull());
                LOG(DEBUG) << "Copied: current offset  " << frame.mWview->offset()
                        << "Copied size " << blocks.front().size();
            } else {
                frame.mBlock.reset();
                frame.mWview.reset();
                frame.mLargeWork->worklets.front()->output.ordinal = (*worklet)->output.ordinal;
                frame.mLargeWork->worklets.front()->output.ordinal.frameIndex =
                        frame.inOrdinal.frameIndex;
                frame.mLargeWork->worklets.front()->output.flags =
                        (*worklet)->output.flags;
                frame.mLargeWork->worklets.front()->output.buffers.push_back(
                        std::move(buffer));
            }
            if (buffer) {
                frame.mInfos.insert(frame.mInfos.end(),
                        buffer->info().begin(), buffer->info().end());
            }
        }
        foundEndOfStream |= (*worklet)->output.flags & C2FrameData::FLAG_END_OF_STREAM;
        C2FrameData& outputFramedata = frame.mLargeWork->worklets.front()->output;
        for (auto& configUpdate : (*worklet)->output.configUpdate) {
            outputFramedata.configUpdate.push_back(std::move(configUpdate));
        }
        outputFramedata.infoBuffers.insert(outputFramedata.infoBuffers.begin(),
                (*worklet)->output.infoBuffers.begin(),
                (*worklet)->output.infoBuffers.end());
        if ((*worklet)->output.flags & C2FrameData::FLAG_CODEC_CONFIG) {
            // TODO: handle this here?
            LOG(DEBUG) << "Output worklet has CSD data";
            frame.mLargeWork->result = C2_OK;
            finalizeWork(frame);
            addWork(frame.mLargeWork);
            frame.reset();
        }
    }
    if ((frame.mWview && (frame.mWview->offset() >= thresholdSize)) || foundEndOfStream) {
        LOG(DEBUG) << "Sending Large frame due to threshold, with size "
                << frame.mWview->size() << " offset " << frame.mWview->offset()
                << " EOS " << foundEndOfStream;
                //TODO: remove this??
        C2FrameData &outputFramedata = frame.mLargeWork->worklets.front()->output;
        if (foundEndOfStream) {
            outputFramedata.flags = C2FrameData::FLAG_END_OF_STREAM;
        }
        frame.mLargeWork->result = C2_OK;
        finalizeWork(frame);
        addWork(frame.mLargeWork);
        frame.reset();
    }
    return C2_OK;
}

c2_status_t MultiAccessUnitHandler::finalizeWork(MultiAccessUnitInfo& frame) {
    if (frame.mLargeWork == nullptr) {
        return C2_OK;
    }
    //prepare input ordinal
    frame.mLargeWork->input.ordinal = frame.inOrdinal;
    // remove this
    uint32_t orFlags = 0, andFlags = 0;
    int64_t timeStampUs = frame.inOrdinal.timestamp.peekull();
    if (!frame.mAccessUnitInfos.empty()) {
        timeStampUs = frame.mAccessUnitInfos.front().timestamp;
    } else if (!frame.mLargeWork->worklets.empty()) {
        std::unique_ptr<C2Worklet> &worklet = frame.mLargeWork->worklets.front();
        if (worklet) {
            timeStampUs = worklet->output.ordinal.timestamp.peekull();
        }
    }
    LOG(DEBUG) << "finalizing work with input Idx "
            << frame.mLargeWork->input.ordinal.frameIndex.peekull()
            << " timestamp " << timeStampUs;
    // These flags are from the original worklets
    for (int i = 0; i < frame.mAccessUnitInfos.size() ; i++) {
        orFlags |= frame.mAccessUnitInfos[i].flags;
        andFlags &= frame.mAccessUnitInfos[i].flags;
    }
    orFlags &= ~(C2FrameData::FLAG_INCOMPLETE);
    if (!frame.mComponentFrameIds.empty()) {
        orFlags |= C2FrameData::FLAG_INCOMPLETE;
    }
    uint32_t omitFlags = C2FrameData::FLAG_DISCARD_FRAME;
    if (!(andFlags & omitFlags)) {
        orFlags &= ~(omitFlags);
    }
    // update worklet if present
    if (!frame.mLargeWork->worklets.empty() &&
            frame.mLargeWork->worklets.front() != nullptr) {
        frame.mLargeWork->workletsProcessed = 1;
        C2FrameData& outFrameData = frame.mLargeWork->worklets.front()->output;
        //TODO: may not be right.
        outFrameData.ordinal.frameIndex = frame.inOrdinal.frameIndex.peekull();
        outFrameData.ordinal.timestamp = timeStampUs;
        // These flags can be from the large frame handler. when the buffer is greater
        // than threshold etc.
        orFlags |= outFrameData.flags;
        // update buffers
        if (frame.mBlock && (frame.mWview->offset() > 0)) {
            size_t size = frame.mWview->offset();
            LOG(DEBUG) << "Finalize : Large frame size set as " << size
                    << " timestamp as " << timeStampUs
                    << "frameIndex " << outFrameData.ordinal.frameIndex.peekull();
            frame.mWview->setOffset(0);
            std::shared_ptr<C2Buffer> c2Buffer = C2Buffer::CreateLinearBuffer(
                    frame.mBlock->share(0, size, ::C2Fence()));
            if (frame.mAccessUnitInfos.size() > 0) {
                std::shared_ptr<C2AccessUnitInfos::output> largeFrame =
                        C2AccessUnitInfos::output::AllocShared(
                        frame.mAccessUnitInfos.size(), 0u, frame.mAccessUnitInfos);
                // All accessunit infos for this work is processed.
                frame.mInfos.push_back(largeFrame);
                frame.mAccessUnitInfos.clear();
            }
            for (auto &info : frame.mInfos) {
                c2Buffer->setInfo(std::const_pointer_cast<C2Info>(info));
            }
            frame.mLargeWork->worklets.front()->output.buffers.push_back(std::move(c2Buffer));
            frame.mBlock.reset();
            frame.mWview.reset();
        }
    }
    LOG(DEBUG) << "Multi access-unitflag setting as " << orFlags;
    return C2_OK;
}

// MultiAccessUnitInfo structure
void MultiAccessUnitHandler::MultiAccessUnitInfo::reset() {
    mBlock.reset();
    mWview.reset();
    mInfos.clear();
    mAccessUnitInfos.clear();
    mLargeWork.reset();
}

}  // namespace utils
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
}  // aidl