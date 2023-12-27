/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "Codec2-Component"
#include <android-base/logging.h>

#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.0/InputBufferManager.h>

#ifndef __ANDROID_APEX__
#include <FilterWrapper.h>
#endif

#include <hidl/HidlBinderSupport.h>
#include <utils/Timers.h>

#include <C2BufferPriv.h>
#include <C2BqBufferPriv.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

// ComponentListener wrapper
struct Component::Listener : public C2Component::Listener {

    Listener(const sp<Component>& component) :
        mComponent(component),
        mListener(component->mListener) {
    }

    virtual void onError_nb(
            std::weak_ptr<C2Component> /* c2component */,
            uint32_t errorCode) override {
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            Return<void> transStatus = listener->onError(Status::OK, errorCode);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onError_nb -- "
                           << "transaction failed.";
            }
        }
    }

    virtual void onTripped_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            hidl_vec<SettingResult> settingResults(c2settingResult.size());
            size_t ix = 0;
            for (const std::shared_ptr<C2SettingResult> &c2result :
                    c2settingResult) {
                if (c2result) {
                    if (!objcpy(&settingResults[ix++], *c2result)) {
                        break;
                    }
                }
            }
            settingResults.resize(ix);
            Return<void> transStatus = listener->onTripped(settingResults);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onTripped_nb -- "
                           << "transaction failed.";
            }
        }
    }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> /* c2component */,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        for (const std::unique_ptr<C2Work>& work : c2workItems) {
            if (work) {
                if (work->worklets.empty()
                        || !work->worklets.back()
                        || (work->worklets.back()->output.flags &
                            C2FrameData::FLAG_INCOMPLETE) == 0) {
                    InputBufferManager::
                            unregisterFrameData(mListener, work->input);
                }
            }
        }

        sp<IComponentListener> listener = mListener.promote();
        if (listener) {
            WorkBundle workBundle;

            sp<Component> strongComponent = mComponent.promote();
            beginTransferBufferQueueBlocks(c2workItems, true);
            if (!objcpy(&workBundle, c2workItems, strongComponent ?
                    &strongComponent->mBufferPoolSender : nullptr)) {
                LOG(ERROR) << "Component::Listener::onWorkDone_nb -- "
                           << "received corrupted work items.";
                endTransferBufferQueueBlocks(c2workItems, false, true);
                return;
            }
            Return<void> transStatus = listener->onWorkDone(workBundle);
            if (!transStatus.isOk()) {
                LOG(ERROR) << "Component::Listener::onWorkDone_nb -- "
                           << "transaction failed.";
                endTransferBufferQueueBlocks(c2workItems, false, true);
                return;
            }
            endTransferBufferQueueBlocks(c2workItems, true, true);
        }
    }

protected:
    wp<Component> mComponent;
    wp<IComponentListener> mListener;
};

//Large frame handler
struct LargeBufferHandler : public Component::Listener {
    LargeBufferHandler(const sp<Component>& component,
            const std::shared_ptr<LargeBufferInterface>& intf):Listener(component),
            mInit(false),
            mInterface(intf) {
        std::shared_ptr<C2AllocatorStore> store = GetCodec2PlatformAllocatorStore();
        if(store->fetchAllocator(C2AllocatorStore::DEFAULT_LINEAR, &mLinearAllocator) == C2_OK) {
            mLinearPool = std::make_shared<C2PooledBlockPool>(mLinearAllocator, ++mBlockPoolId);
            mInit = true;
        }
    }

    ~LargeBufferHandler() {
        LOG(ERROR) << "Destroying handler for large frame";
    }

    std::shared_ptr<LargeBufferInterface> getInterface() {
        return mInterface;
    }

    bool getStatus() {
        return mInit;
    }

    void reset() {
        std::lock_guard<std::mutex> l(mLock);
        mFrameHolder.clear();
    }

    c2_status_t flush(const std::shared_ptr<C2Component>& component,
            C2Component::flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* c2flushedWorks) {
        c2_status_t c2res = component->flush_sm(
                mode,
                c2flushedWorks);

        std::lock_guard<std::mutex> l(mLock);
        LOG(ERROR) << "Flush started";
        for (std::unique_ptr<C2Work>& w : *c2flushedWorks) {
            bool foundFlushedFrame = false;
            for (auto frame = mFrameHolder.begin() ;
                    frame != mFrameHolder.end() && !foundFlushedFrame;) {
                auto it = frame->mComponentFrameIds.find(
                        w->input.ordinal.frameIndex.peekull());
                if (it != frame->mComponentFrameIds.end()) {
                    LOG(ERROR) << "Flush Replacing " << w->input.ordinal.frameIndex.peekull()
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
        LOG(ERROR) << "Flush finished";
        return c2res;
    }

    c2_status_t queue(std::list<std::unique_ptr<C2Work>>& largeWork, 
            const std::shared_ptr<C2Component>& component) {
        c2_status_t err = C2_OK;
        LOG(ERROR) << "Going through scatter stack";
        class C2MultiAccesUnitBuffer : public C2Buffer {
        public:
            explicit C2MultiAccesUnitBuffer(const std::vector<C2ConstLinearBlock> &blocks):
                    C2Buffer(blocks) {
            }
        };
        std::list<std::list<std::unique_ptr<C2Work>>> auList;
        for (std::unique_ptr<C2Work>& w : largeWork) {
            std::list<std::unique_ptr<C2Work>> sliceWork;
            C2WorkOrdinalStruct inputOrdinal = w->input.ordinal;
            LargeFrameAttribs frameInfo = LargeFrameAttribs::CreateEmptyFrame(inputOrdinal);
            std::set<uint64_t>& frameSet = frameInfo.mComponentFrameIds;
            uint64_t newFrameIdx = ++mFrameIndex;    
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
                    // std::vector<std::unique_ptr<C2Tuning>> tunings;
                    // for (std::unique_ptr<C2Tuning>& tuning : inWork->worklets.front()->tunings) {
                    //     tunings.push_back(std::move(C2Param::Copy(*(tuning.get()))));
                    // }
                    // newWork->worklets.front()->tunings = std::move(tunings);
                }
                return std::move(newWork);
            };
            // TODO: Do not split buffers if component inherantly supports MultipleFrames.
            // replace only frameindex.

            if (w->input.buffers.empty() || w->input.buffers.front() == nullptr) {
                LOG(ERROR) << "Empty buffer scatter queue frames with id "
                        << inputOrdinal.frameIndex.peeku() 
                        << ") -> " << newFrameIdx
                        <<" : TS " << inputOrdinal.timestamp.peekull();
                sliceWork.push_back(std::move(cloneInputWork(w)));
                frameSet.insert(newFrameIdx);
                auList.push_back(std::move(sliceWork));
            }  else {
                const std::shared_ptr<C2Buffer>& buffer =  w->input.buffers.front();
                if (!buffer->hasInfo(C2AccessUnitInfos::input::PARAM_TYPE)
                    || buffer->data().linearBlocks().empty()) {
                    LOG(ERROR) << "Frame scatter queuing frames no info "
                            << inputOrdinal.frameIndex.peeku() 
                        << ") -> " << newFrameIdx
                        <<" : TS " << inputOrdinal.timestamp.peekull();
                    std::unique_ptr<C2Work> newWork = cloneInputWork(w);
                    newWork->input.buffers = std::move(w->input.buffers);
                    sliceWork.push_back(std::move(newWork));
                    frameSet.insert(newFrameIdx);
                    auList.push_back(std::move(sliceWork));
                } else {
                    const std::vector<std::shared_ptr<C2Buffer>>& inBuffers = w->input.buffers; 
                    if (inBuffers.size() > 1 || inBuffers.front()->data().linearBlocks().size() > 1) {
                        LOG(ERROR) << "Input has multiple streams: " << inBuffers.size()
                                << "linearBlocks: " << inBuffers.front()->data().linearBlocks().size(); 
                    }    
                    const std::vector<C2ConstLinearBlock>& multiAU =
                            inBuffers.front()->data().linearBlocks();
                    std::shared_ptr<const C2AccessUnitInfos::input> auInfo =
                            std::static_pointer_cast<const C2AccessUnitInfos::input>(
                            w->input.buffers.front()->getInfo(C2AccessUnitInfos::input::PARAM_TYPE));
                    uint32_t offset = 0; uint32_t multiAUSize = multiAU.front().size();
                    for (int idx = 0; idx < auInfo->flexCount(); ++idx) {
                        std::vector<C2ConstLinearBlock> au;
                        const C2AccessUnitInfosStruct& info = auInfo->m.values[idx];
                        newFrameIdx = ++mFrameIndex;
                        std::unique_ptr<C2Work> newWork = cloneInputWork(w);
                        newWork->input.ordinal.timestamp = info.timestamp;
                        au.push_back(multiAU.front().subBlock(offset, info.size));
                        offset += info.size;
                        newWork->input.buffers.push_back(
                                std::shared_ptr<C2Buffer>(new C2MultiAccesUnitBuffer(au)));
                        // queue work
                        sliceWork.push_back(std::move(newWork));
                        frameSet.insert(newFrameIdx);
                        auList.push_back(std::move(sliceWork));
                        LOG(ERROR) << "Buffer Info attachment detected Id " << idx 
                                << " ofset: " << offset
                                << " size " << info.size;
                        if (offset > multiAUSize) {
                            LOG(ERROR) << "Multi AU: bufferinfo offset > size; offset " << offset;
                        }
                    }
                }
            }
            if (!auList.empty()) {
                {
                    frameInfo.mLargeFrameTuning = *(mInterface->get().get());
                    std::lock_guard<std::mutex> l(mLock);
                    mFrameHolder.push_back(std::move(frameInfo));
                }
                int idx = 0;
                for (std::list<std::unique_ptr<C2Work>>& worklist : auList) {
                    LOG(ERROR) << "Queing to the component " << idx++ ;
                    err = component->queue_nb(&worklist);
                    if (err != C2_OK) { return err; }
                }

            }     
        }  
        return C2_OK;
    }

    void onError_nb(
            std::weak_ptr<C2Component> c2component ,
            uint32_t errorCode) override {
        LOG(ERROR) << "Large Frame listener onError_nb";
        Listener::onError_nb(c2component, errorCode);

     }

     virtual void onTripped_nb(
            std::weak_ptr<C2Component> c2component,
            std::vector<std::shared_ptr<C2SettingResult>> c2settingResult
            ) override {
        LOG(ERROR) << "Large Frame listener onTripped_nb";
        Listener::onTripped_nb(c2component, c2settingResult);
     }

    virtual void onWorkDone_nb(
            std::weak_ptr<C2Component> c2component,
            std::list<std::unique_ptr<C2Work>> c2workItems) override {
        LOG(ERROR) << "Large Frame listener onWorkDone_nb";
        std::list<std::unique_ptr<C2Work>> outWork;
        auto addOutWork = [&outWork](std::unique_ptr<C2Work>& work) {
            outWork.push_back(std::move(work));
        };
        LOG(ERROR) << "Going through gather stack";
        // TODO: Do not do any gatering if the Largeframe configuration
        // has maxSize or thresholdSize as zero.
        {
            std::lock_guard<std::mutex> l(mLock);
            for (auto& work : c2workItems) {
                LOG(ERROR) << "FrameHolder Size: " << mFrameHolder.size();
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
                        LOG(ERROR) << "onWorkDone came ( in with o/p " << thisFrameIndex
                                << " worklstsSze " << work->worklets.size()
                                << ") -> " << frame->inOrdinal.frameIndex.peekull()
                                << " Flags: " << work->worklets.front()->output.flags;

                        if (removeEntry) {
                            LOG(ERROR) << "Removing entry: " << thisFrameIndex
                                    << " -> " << frame->inOrdinal.frameIndex.peekull();
                            frame->mComponentFrameIds.erase(it);
                        }
                        if (frame->mLargeWork) {
                            if (frame->mLargeWork->input.ordinal.frameIndex !=
                                    frame->inOrdinal.frameIndex) {
                                LOG(ERROR) << "Wierd! mLargeWork " 
                                           << frame->mLargeWork->input.ordinal.frameIndex.peekull()
                                           << " is different from frame " 
                                           << frame->inOrdinal.frameIndex.peekull();
                                finalizeWork(*frame);
                                addOutWork(frame->mLargeWork);
                            }
                        }
                        if (!frame->mLargeWork) {
                            frame->mLargeWork.reset(new C2Work);
                            frame->mLargeWork->input.ordinal.frameIndex = frame->inOrdinal.frameIndex;
                        }
                        if (C2_OK != processLargeAudioWorklets(*frame, work, addOutWork)) {
                            LOG(ERROR) << "Error while processing large audio work";
                        }
                        if (frame->mComponentFrameIds.empty()) {
                            LOG(ERROR) << "This frame is finished ID " << thisFrameIndex;
                            mFrameHolder.erase(frame);
                        }
                        foundFrame = true;
                    } else {
                        LOG(ERROR) << "Received an out-of-order output " << thisFrameIndex;
                    }
                }
                if (!foundFrame) {
                    LOG(ERROR) <<" Error: Frame Holder reports no frame " << thisFrameIndex;
                }

            }
        }
            
        if (outWork.size() > 0) {
            // we have some work to be send out.
            LOG(ERROR) << "We got some work to send out";
            Listener::onWorkDone_nb(c2component, std::move(outWork));
        }
    }

    protected:
        struct LargeFrameAttribs {
            // from the input
            C2WorkOrdinalStruct inOrdinal;
            std::set<uint64_t> mComponentFrameIds;
            //for the output
            std::shared_ptr<C2LinearBlock> mBlock;
            std::shared_ptr<C2WriteView> mWview;
            std::vector<std::shared_ptr<const C2Info>> mInfos;
            std::vector<C2AccessUnitInfosStruct> mAccessUnitInfos;
            C2LargeFrame::output mLargeFrameTuning;
            std::unique_ptr<C2Work> mLargeWork;
            static LargeFrameAttribs CreateEmptyFrame(C2WorkOrdinalStruct& ordinal) {
                LargeFrameAttribs largeFrame{
                    ordinal,
                    std::set<uint64_t>(),
                    nullptr,
                    nullptr,
                    std::vector<std::shared_ptr<const C2Info>>(),
                    std::vector<C2AccessUnitInfosStruct>(),
                    {},
                    nullptr
                };
                return largeFrame;
            }
            void reset() {
                mBlock.reset();
                mWview.reset();
                mInfos.clear();
                mAccessUnitInfos.clear();
                mLargeWork.reset();
            }
        };

        c2_status_t createLinearBlock(LargeFrameAttribs& frame) {
            if (!mInit) {
                LOG(ERROR) << "Large buffer allocator failed";
                return C2_NO_MEMORY;
            }
            C2MemoryUsage usage = { C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE };
            uint32_t maxOutSize = frame.mLargeFrameTuning.maxSize;
            c2_status_t err = mLinearPool->fetchLinearBlock(maxOutSize, usage, &frame.mBlock);
            if (err != C2_OK) {
                LOG(ERROR) << "Error allocating largeFrames";
                return err;
            }
            frame.mWview = std::make_shared<C2WriteView>(frame.mBlock->map().get());
            return C2_OK;
        }

        /*
         * For every work from the component, we try to do aggregration of work here.
        */
        c2_status_t processLargeAudioWorklets(LargeFrameAttribs& frame,
                std::unique_ptr<C2Work>& work,
                const std::function <void(std::unique_ptr<C2Work>&)>& addWork) {
            uint32_t maxOutSize = frame.mLargeFrameTuning.maxSize;
            uint32_t thresholdSize = frame.mLargeFrameTuning.thresholdSize;
            // This will allocate work, worklet, c2Block
            auto allocateWork = [&](LargeFrameAttribs& frame, bool allocateWorket = false) {
                if (frame.mLargeWork == nullptr) {
                    frame.mLargeWork.reset(new C2Work);
                    frame.mLargeWork->input.ordinal.frameIndex = frame.inOrdinal.frameIndex;
                } else {
                    LOG(ERROR) << "Calling allocateWork with an already valid work";
                }
                if (allocateWorket) {
                    if (frame.mLargeWork->worklets.size() == 0) {
                        frame.mLargeWork->worklets.emplace_back(new C2Worklet);
                        // worklet always has buffers
                        createLinearBlock(frame);
                    } else {
                        LOG(ERROR) << "Workets are already at size " <<
                                frame.mLargeWork->worklets.size();
                    }
                }
            };

            if (work->worklets.empty() || !work->worklets.front()) {
                LOG(ERROR) << "Worklet is empty, sending processed work";
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
                     worklet != work->worklets.end() && (*worklet) != nullptr; ) {
                allocateWork(frame, true);
                // we assume only 1 worklet
                if (frame.mLargeWork->worklets.size() == 0) {
                    frame.mLargeWork->worklets.emplace_back(new C2Worklet);
                    createLinearBlock(frame);
                } else {
                    LOG(ERROR) << "Out worklet size already at " << frame.mLargeWork->worklets.size();
                }
                std::optional<uint32_t> bufferIndex;
                uint32_t flagsForNoCopy = 0;//C2FrameData::FLAG_DISCARD_FRAME | C2FrameData::FLAG_CORRUPT;
                if (!((*worklet)->output.flags & flagsForNoCopy)) {
                    LOG(ERROR) << "This worklet has " << (*worklet)->output.buffers.size() << " buffers";
                    for (int bufIdx = 0; bufIdx < (*worklet)->output.buffers.size();
                            bufferIndex ? bufIdx = bufferIndex.value() : ++bufIdx) {
                        LOG(ERROR)<< "Processing this worklet for buffer index " << bufIdx;
                        C2FrameData& outputFramedata = frame.mLargeWork->worklets.back()->output;
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
                            if ((frame.mWview->offset()
                                    + blocks.front().size()) > frame.mWview->size()) {
                                LOG(ERROR) << "Large frame hitting bufer size for next frame alloc"
                                        << frame.mWview->offset()
                                        << "block size " << blocks.front().size(); 
                                outputFramedata.flags = C2FrameData::FLAG_INCOMPLETE;
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
                        } else {
                            frame.mBlock.reset();
                            frame.mLargeWork->worklets.front()->output.flags =
                                    (*worklet)->output.flags;
                            LOG(ERROR) << "Copying all blocks";
                            frame.mLargeWork->worklets.front()->output.buffers.push_back(
                                    std::move(buffer));
                            LOG(ERROR) << "Copy all blocks -- done";
                                
                        }
                        LOG(ERROR) << "Copy infos buffer ";
                        if (buffer) {
                            frame.mInfos.insert(frame.mInfos.end(),
                                    buffer->info().begin(), buffer->info().end());
                        }
                        LOG(ERROR) << "Copy infos -- done";
                    }
                    foundEndOfStream |= (*worklet)->output.flags & C2FrameData::FLAG_END_OF_STREAM;   
                    C2FrameData& outputFramedata = frame.mLargeWork->worklets.front()->output;
                    // may have some configurations when flagged with DISCARD
                    for (auto& configUpdate : (*worklet)->output.configUpdate) {
                        outputFramedata.configUpdate.push_back(std::move(configUpdate));
                    }
                    outputFramedata.infoBuffers.insert(outputFramedata.infoBuffers.begin(),
                            (*worklet)->output.infoBuffers.begin(),
                            (*worklet)->output.infoBuffers.end());
                }
                if ((*worklet)->output.flags & C2FrameData::FLAG_CODEC_CONFIG) {
                    // if any before send it.
                    // TODO: handle this here?
                    LOG(ERROR) << "Output worklet has CSD data";
                    frame.mLargeWork->result = C2_OK;    
                    finalizeWork(frame);
                    addWork(frame.mLargeWork);
                    frame.reset();
                    allocateWork(frame, true);
                }
                // iter increment;
                worklet++;
            }
            if (frame.mWview->offset() >= thresholdSize || foundEndOfStream) {
                LOG(ERROR) << "Sending Large frame due to threshold, with size "
                        << frame.mWview->offset()
                        << "EOS " << foundEndOfStream;
                        //TODO: remove this??
                C2FrameData &outputFramedata = frame.mLargeWork->worklets.back()->output;
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

        c2_status_t finalizeWork(LargeFrameAttribs& frame) {
            if (frame.mLargeWork == nullptr) {
                LOG(ERROR) << "Nothing to finalize now.";
                return C2_OK;
            }
            //prepare input ordinal
            frame.mLargeWork->input.ordinal = frame.inOrdinal;
            // remove this
            uint32_t orFlags = 0, andFlags = 0;
            int64_t timeStampUs = frame.inOrdinal.timestamp.peekull();
            if (!frame.mAccessUnitInfos.empty()) {
                timeStampUs = frame.mAccessUnitInfos.front().timestamp;
            }
            LOG(ERROR) << "finalizing work with input Idx " 
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
                //TODO: remove this
                // outFrameData.flags = (C2FrameData::flags_t)orFlags;

                // update buffers
                if (frame.mBlock && (frame.mBlock->offset() > 0)) {
                    size_t size = frame.mBlock->offset();
                    LOG(ERROR) << "Large frame size set as " << size 
                            << " timestamp as " << timeStampUs
                            << "frameIndex " << outFrameData.ordinal.frameIndex.peekull();
                    frame.mWview->setOffset(0);
                    std::shared_ptr<C2Buffer> c2Buffer = C2Buffer::CreateLinearBuffer(
                            frame.mBlock->share(0, size, ::C2Fence()));
                    if (frame.mAccessUnitInfos.size() > 0) {
                        std::shared_ptr<C2AccessUnitInfos::output> largeFrame =
                                C2AccessUnitInfos::output::AllocShared(
                                frame.mAccessUnitInfos.size(), 0u, frame.mAccessUnitInfos);
                        c2Buffer->setInfo(largeFrame);
                    }
                    frame.mLargeWork->worklets.front()->output.buffers.push_back(std::move(c2Buffer)); 
                    frame.mBlock.reset();                       
                }
            }
            LOG(ERROR) << "Large frame work flag setting as " << orFlags;
            return C2_OK;
        }
        //debug 
        void getBlockInfo(std::string anchor, const std::shared_ptr<C2LinearBlock>& block) {
            if (block) {
                LOG(ERROR) << anchor.c_str() << " Allocated a block-ptr  " << block.get()
                        << " size: " << block->size()
                        << " offset: " << block->offset();
            }
        }
        bool mInit;
        std::shared_ptr<LargeBufferInterface> mInterface;

        C2BlockPool::local_id_t mBlockPoolId;
        std::shared_ptr<C2BlockPool> mLinearPool;
        std::shared_ptr<C2Allocator> mLinearAllocator;

        std::atomic_uint64_t mFrameIndex;

        std::mutex mLock;
        std::list<LargeFrameAttribs> mFrameHolder;
};

// Component::Sink
struct Component::Sink : public IInputSink {
    std::shared_ptr<Component> mComponent;
    sp<IConfigurable> mConfigurable;

    virtual Return<Status> queue(const WorkBundle& workBundle) override {
        return mComponent->queue(workBundle);
    }

    virtual Return<sp<IConfigurable>> getConfigurable() override {
        return mConfigurable;
    }

    Sink(const std::shared_ptr<Component>& component);
    virtual ~Sink() override;

    // Process-wide map: Component::Sink -> C2Component.
    static std::mutex sSink2ComponentMutex;
    static std::map<IInputSink*, std::weak_ptr<C2Component>> sSink2Component;

    static std::shared_ptr<C2Component> findLocalComponent(
            const sp<IInputSink>& sink);
};

std::mutex
        Component::Sink::sSink2ComponentMutex{};
std::map<IInputSink*, std::weak_ptr<C2Component>>
        Component::Sink::sSink2Component{};

Component::Sink::Sink(const std::shared_ptr<Component>& component)
        : mComponent{component},
          mConfigurable{[&component]() -> sp<IConfigurable> {
              Return<sp<IComponentInterface>> ret1 = component->getInterface();
              if (!ret1.isOk()) {
                  LOG(ERROR) << "Sink::Sink -- component's transaction failed.";
                  return nullptr;
              }
              Return<sp<IConfigurable>> ret2 =
                      static_cast<sp<IComponentInterface>>(ret1)->
                      getConfigurable();
              if (!ret2.isOk()) {
                  LOG(ERROR) << "Sink::Sink -- interface's transaction failed.";
                  return nullptr;
              }
              return static_cast<sp<IConfigurable>>(ret2);
          }()} {
    std::lock_guard<std::mutex> lock(sSink2ComponentMutex);
    sSink2Component.emplace(this, component->mComponent);
}

Component::Sink::~Sink() {
    std::lock_guard<std::mutex> lock(sSink2ComponentMutex);
    sSink2Component.erase(this);
}

std::shared_ptr<C2Component> Component::Sink::findLocalComponent(
        const sp<IInputSink>& sink) {
    std::lock_guard<std::mutex> lock(sSink2ComponentMutex);
    auto i = sSink2Component.find(sink.get());
    if (i == sSink2Component.end()) {
        return nullptr;
    }
    return i->second.lock();
}

// Component
Component::Component(
        const std::shared_ptr<C2Component>& component,
        const sp<IComponentListener>& listener,
        const sp<ComponentStore>& store,
        const sp<::android::hardware::media::bufferpool::V2_0::
        IClientManager>& clientPoolManager)
      : mComponent{component},
        mInterface{new ComponentInterface(component->intf(),
                                          store->getParameterCache())},
        mListener{listener},
        mStore{store},
        mBufferPoolSender{clientPoolManager} {
    // Retrieve supported parameters from store
    // TODO: We could cache this per component/interface type
    mInit = mInterface->status();
}

c2_status_t Component::status() const {
    return mInit;
}

void Component::onDeathReceived() {
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mClientDied = true;
        for (auto it = mBlockPools.begin(); it != mBlockPools.end(); ++it) {
            if (it->second->getAllocatorId() == C2PlatformAllocatorStore::BUFFERQUEUE) {
                std::shared_ptr<C2BufferQueueBlockPool> bqPool =
                        std::static_pointer_cast<C2BufferQueueBlockPool>(it->second);
                bqPool->invalidate();
            }
        }
    }
    release();
}

// Methods from ::android::hardware::media::c2::V1_0::IComponent
Return<Status> Component::queue(const WorkBundle& workBundle) {
    std::list<std::unique_ptr<C2Work>> c2works;
    LOG(ERROR) << "HIDL1.0 queue";
    if (!objcpy(&c2works, workBundle)) {
        return Status::CORRUPTED;
    }

    // Register input buffers.
    for (const std::unique_ptr<C2Work>& work : c2works) {
        if (work) {
            InputBufferManager::
                    registerFrameData(mListener, work->input);
        }
    }

    return static_cast<Status>(mComponent->queue_nb(&c2works));
}

Return<void> Component::flush(flush_cb _hidl_cb) {
    std::list<std::unique_ptr<C2Work>> c2flushedWorks;
    c2_status_t c2res = mComponent->flush_sm(
            C2Component::FLUSH_COMPONENT,
            &c2flushedWorks);

    // Unregister input buffers.
    for (const std::unique_ptr<C2Work>& work : c2flushedWorks) {
        if (work) {
            if (work->worklets.empty()
                    || !work->worklets.back()
                    || (work->worklets.back()->output.flags &
                        C2FrameData::FLAG_INCOMPLETE) == 0) {
                InputBufferManager::
                        unregisterFrameData(mListener, work->input);
            }
        }
    }

    WorkBundle flushedWorkBundle;
    Status res = static_cast<Status>(c2res);
    beginTransferBufferQueueBlocks(c2flushedWorks, true);
    if (c2res == C2_OK) {
        if (!objcpy(&flushedWorkBundle, c2flushedWorks, &mBufferPoolSender)) {
            res = Status::CORRUPTED;
        }
    }
    _hidl_cb(res, flushedWorkBundle);
    endTransferBufferQueueBlocks(c2flushedWorks, true, true);
    return Void();
}

Return<Status> Component::drain(bool withEos) {
    return static_cast<Status>(mComponent->drain_nb(withEos ?
            C2Component::DRAIN_COMPONENT_WITH_EOS :
            C2Component::DRAIN_COMPONENT_NO_EOS));
}

Return<Status> Component::setOutputSurface(
        uint64_t blockPoolId,
        const sp<HGraphicBufferProducer2>& surface) {
    std::shared_ptr<C2BlockPool> pool;
    GetCodec2BlockPool(blockPoolId, mComponent, &pool);
    if (pool && pool->getAllocatorId() == C2PlatformAllocatorStore::BUFFERQUEUE) {
        std::shared_ptr<C2BufferQueueBlockPool> bqPool =
                std::static_pointer_cast<C2BufferQueueBlockPool>(pool);
        C2BufferQueueBlockPool::OnRenderCallback cb =
            [this](uint64_t producer, int32_t slot, int64_t nsecs) {
                // TODO: batch this
                hidl_vec<IComponentListener::RenderedFrame> rendered;
                rendered.resize(1);
                rendered[0] = { producer, slot, nsecs };
                (void)mListener->onFramesRendered(rendered).isOk();
        };
        if (bqPool) {
            bqPool->setRenderCallback(cb);
            bqPool->configureProducer(surface);
        }
    }
    return Status::OK;
}

Return<void> Component::connectToInputSurface(
        const sp<IInputSurface>& inputSurface,
        connectToInputSurface_cb _hidl_cb) {
    Status status;
    sp<IInputSurfaceConnection> connection;
    auto transStatus = inputSurface->connect(
            asInputSink(),
            [&status, &connection](
                    Status s, const sp<IInputSurfaceConnection>& c) {
                status = s;
                connection = c;
            }
        );
    _hidl_cb(status, connection);
    return Void();
}

Return<void> Component::connectToOmxInputSurface(
        const sp<HGraphicBufferProducer1>& producer,
        const sp<::android::hardware::media::omx::V1_0::
        IGraphicBufferSource>& source,
        connectToOmxInputSurface_cb _hidl_cb) {
    (void)producer;
    (void)source;
    (void)_hidl_cb;
    return Void();
}

Return<Status> Component::disconnectFromInputSurface() {
    // TODO implement
    return Status::OK;
}

namespace /* unnamed */ {

struct BlockPoolIntf : public ConfigurableC2Intf {
    BlockPoolIntf(const std::shared_ptr<C2BlockPool>& pool)
          : ConfigurableC2Intf{
                "C2BlockPool:" +
                    (pool ? std::to_string(pool->getLocalId()) : "null"),
                0},
            mPool{pool} {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        (void)params;
        (void)mayBlock;
        (void)failures;
        return C2_OK;
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        (void)indices;
        (void)mayBlock;
        (void)params;
        return C2_OK;
    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        (void)params;
        return C2_OK;
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        (void)fields;
        (void)mayBlock;
        return C2_OK;
    }

protected:
    std::shared_ptr<C2BlockPool> mPool;
};

} // unnamed namespace

Return<void> Component::createBlockPool(
        uint32_t allocatorId,
        createBlockPool_cb _hidl_cb) {
    std::shared_ptr<C2BlockPool> blockPool;
#ifdef __ANDROID_APEX__
    c2_status_t status = CreateCodec2BlockPool(
            static_cast<C2PlatformAllocatorStore::id_t>(allocatorId),
            mComponent,
            &blockPool);
#else
    c2_status_t status = ComponentStore::GetFilterWrapper()->createBlockPool(
            static_cast<C2PlatformAllocatorStore::id_t>(allocatorId),
            mComponent,
            &blockPool);
#endif
    if (status != C2_OK) {
        blockPool = nullptr;
    }
    if (blockPool) {
        bool emplaced = false;
        {
            mBlockPoolsMutex.lock();
            if (!mClientDied) {
                mBlockPools.emplace(blockPool->getLocalId(), blockPool);
                emplaced = true;
            }
            mBlockPoolsMutex.unlock();
        }
        if (!emplaced) {
            blockPool.reset();
            status = C2_BAD_STATE;
        }
    } else if (status == C2_OK) {
        status = C2_CORRUPTED;
    }

    _hidl_cb(static_cast<Status>(status),
            blockPool ? blockPool->getLocalId() : 0,
            new CachedConfigurable(
            std::make_unique<BlockPoolIntf>(blockPool)));
    return Void();
}

Return<Status> Component::destroyBlockPool(uint64_t blockPoolId) {
    std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
    return mBlockPools.erase(blockPoolId) == 1 ?
            Status::OK : Status::CORRUPTED;
}

Return<Status> Component::start() {
    return static_cast<Status>(mComponent->start());
}

Return<Status> Component::stop() {
    InputBufferManager::unregisterFrameData(mListener);
    return static_cast<Status>(mComponent->stop());
}

Return<Status> Component::reset() {
    Status status = static_cast<Status>(mComponent->reset());
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    InputBufferManager::unregisterFrameData(mListener);
    return status;
}

Return<Status> Component::release() {
    Status status = static_cast<Status>(mComponent->release());
    {
        std::lock_guard<std::mutex> lock(mBlockPoolsMutex);
        mBlockPools.clear();
    }
    InputBufferManager::unregisterFrameData(mListener);
    return status;
}

Return<sp<IComponentInterface>> Component::getInterface() {
    return sp<IComponentInterface>(mInterface);
}

Return<sp<IInputSink>> Component::asInputSink() {
    std::lock_guard<std::mutex> lock(mSinkMutex);
    if (!mSink) {
        mSink = new Sink(shared_from_this());
    }
    return {mSink};
}

std::shared_ptr<C2Component> Component::findLocalComponent(
        const sp<IInputSink>& sink) {
    return Component::Sink::findLocalComponent(sink);
}

void Component::initListener(const sp<Component>& self) {
    std::shared_ptr<C2Component::Listener> c2listener =
            std::make_shared<Listener>(self);
    c2_status_t res = mComponent->setListener_vb(c2listener, C2_DONT_BLOCK);
    if (res != C2_OK) {
        mInit = res;
    }

    struct ListenerDeathRecipient : public HwDeathRecipient {
        ListenerDeathRecipient(const wp<Component>& comp)
            : mComponent{comp} {
        }

        virtual void serviceDied(
                uint64_t /* cookie */,
                const wp<::android::hidl::base::V1_0::IBase>& /* who */
                ) override {
            auto strongComponent = mComponent.promote();
            if (strongComponent) {
                LOG(INFO) << "Client died ! notify and release the component !!";
                strongComponent->onDeathReceived();
            } else {
                LOG(ERROR) << "Client died ! no component to release !!";
            }
        }

        wp<Component> mComponent;
    };

    mDeathRecipient = new ListenerDeathRecipient(self);
    Return<bool> transStatus = mListener->linkToDeath(
            mDeathRecipient, 0);
    if (!transStatus.isOk()) {
        LOG(ERROR) << "Listener linkToDeath() transaction failed.";
    }
    if (!static_cast<bool>(transStatus)) {
        LOG(DEBUG) << "Listener linkToDeath() call failed.";
    }
}

Component::~Component() {
    InputBufferManager::unregisterFrameData(mListener);
    mStore->reportComponentDeath(this);
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

