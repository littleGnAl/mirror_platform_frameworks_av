/*
 * Copyright (C) 2022 The Android Open Source Project
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
#define LOG_TAG "GraphicsTracker_test"
#include <unistd.h>

#include <android/hardware_buffer.h>
#include <codec2/aidl/GraphicsTracker.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <gui/BufferQueue.h>
#include <gui/IConsumerListener.h>
#include <gui/Surface.h>
#include <private/android/AHardwareBufferHelpers.h>

#include <C2BlockInternal.h>
#include <C2FenceFactory.h>

#include <atomic>
#include <memory>
#include <iostream>
#include <thread>

using ::aidl::android::hardware::media::c2::implementation::GraphicsTracker;
using ::android::BufferItem;
using ::android::BufferQueue;
using ::android::Fence;
using ::android::GraphicBuffer;
using ::android::IGraphicBufferProducer;
using ::android::IGraphicBufferConsumer;
using ::android::sp;
using ::android::wp;

namespace {
struct BqStatistics {
    std::atomic<int> mDequeued;
    std::atomic<int> mQueued;
    std::atomic<int> mBlocked;
    std::atomic<int> mDropped;
    std::atomic<int> mDiscarded;
    std::atomic<int> mReleased;

    void log() {
        ALOGD("Dequeued: %d, Queued: %d, Blocked: %d, "
              "Dropped: %d, Discarded %d, Released %d",
              (int)mDequeued, (int)mQueued, (int)mBlocked,
              (int)mDropped, (int)mDiscarded, (int)mReleased);
    }
};

struct DummyConsumerListener : public android::BnConsumerListener {
    void onFrameAvailable(const BufferItem& /* item */) override {}
    void onBuffersReleased() override {}
    void onSidebandStreamChanged() override {}
};

struct TestConsumerListener : public android::BnConsumerListener {
    TestConsumerListener(const sp<IGraphicBufferConsumer> &consumer)
            : BnConsumerListener(), mConsumer(consumer) {}
    void onFrameAvailable(const BufferItem&) override {
        constexpr static int kRenderDelayUs = 1000000/30; // 30fps
        BufferItem buffer;
        // consume buffer
        sp<IGraphicBufferConsumer> consumer = mConsumer.promote();
        if (consumer != nullptr && consumer->acquireBuffer(&buffer, 0) == android::NO_ERROR) {
            ::usleep(kRenderDelayUs);
            consumer->releaseBuffer(buffer.mSlot, buffer.mFrameNumber,
                                    EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, buffer.mFence);
        }
    }
    void onBuffersReleased() override {}
    void onSidebandStreamChanged() override {}

    wp<IGraphicBufferConsumer> mConsumer;
};

struct TestProducerListener : public android::BnProducerListener {
    TestProducerListener(std::shared_ptr<GraphicsTracker> tracker,
                         std::shared_ptr<BqStatistics> &stat,
                         uint32_t generation) : BnProducerListener(),
        mTracker(tracker), mStat(stat), mGeneration(generation) {}
    virtual void onBufferReleased() override {
        mStat->mReleased++;
        auto tracker = mTracker.lock();
        if (tracker) {
            tracker->onReleased(mGeneration);
        }
    }
    virtual bool needsReleaseNotify() override { return true; }
    virtual void onBuffersDiscarded(const std::vector<int32_t>&) override {}

    std::weak_ptr<GraphicsTracker> mTracker;
    std::shared_ptr<BqStatistics> mStat;
    uint32_t mGeneration;
};

struct FrameQueue {
    struct Frame {
        AHardwareBuffer *buffer_;
        sp<Fence> fence_;

        Frame() : buffer_{nullptr}, fence_{nullptr} {}
        Frame(AHardwareBuffer *buffer, sp<Fence> fence)
                : buffer_(buffer), fence_(fence) {}
        ~Frame() {
            if (buffer_) {
                AHardwareBuffer_release(buffer_);
            }
        }
    };

    bool mStopped;
    std::queue<std::shared_ptr<Frame>> mQueue;
    std::mutex mMutex;
    std::condition_variable mCond;

    FrameQueue() : mStopped{false} {}

    bool queueItem(AHardwareBuffer *buffer, sp<Fence> fence) {
        std::shared_ptr<Frame> frame = std::make_shared<Frame>(buffer, fence);
        if (!frame) {
            return false;
        }
        std::unique_lock<std::mutex> l(mMutex);
        mQueue.emplace(frame);
        l.unlock();
        mCond.notify_all();
        return true;
    }

    void stop() {
        bool stopped = false;
        std::unique_lock<std::mutex> l(mMutex);
        if (!mStopped) {
            mStopped = true;
            stopped = true;
        }
        l.unlock();
        if (stopped) {
            mCond.notify_all();
        }
    }

    bool waitItem(std::shared_ptr<Frame> *frame) {
        while(true) {
            std::unique_lock<std::mutex> l(mMutex);
            if (mStopped) {
                return false;
            }
            if (!mQueue.empty()) {
                *frame = mQueue.front();
                mQueue.pop();
                return true;
            }
            mCond.wait(l);
        }
    }
};

} // namespace anonymous

void queueBuffer(
        std::shared_ptr<GraphicsTracker> tracker,
        FrameQueue *queue,
        std::shared_ptr<BqStatistics> stat) {
    while (true) {
        std::shared_ptr<FrameQueue::Frame> frame;
        if (!queue->waitItem(&frame)) {
            break;
        }
        uint64_t bid;
        if (AHardwareBuffer_getId(frame->buffer_, &bid) !=
                android::NO_ERROR) {
            break;
        }
        android::status_t ret = frame->fence_->wait(-1);
        if (ret != android::NO_ERROR) {
            tracker->deallocate(bid, frame->fence_);
            stat->mDiscarded++;
            continue;
        }

        std::shared_ptr<C2GraphicBlock> blk =
                _C2BlockFactory::CreateGraphicBlock(frame->buffer_);
        if (!blk) {
            tracker->deallocate(bid, Fence::NO_FENCE);
            stat->mDiscarded++;
            continue;
        }
        IGraphicBufferProducer::QueueBufferInput input(
                0, false,
                HAL_DATASPACE_UNKNOWN, android::Rect(0, 0, 1, 1),
                NATIVE_WINDOW_SCALING_MODE_FREEZE, 0, Fence::NO_FENCE);
        IGraphicBufferProducer::QueueBufferOutput output{};
        c2_status_t res = tracker->render(
                blk->share(C2Rect(1, 1), C2Fence()),
                input, &output);
        if (res != C2_OK) {
            tracker->deallocate(bid, Fence::NO_FENCE);
            stat->mDiscarded++;
            continue;
        }
        if (output.bufferReplaced) {
            stat->mDropped++;
        }
        stat->mQueued++;
    }
}

class GraphicsTrackerTest : public ::testing::Test {
};

TEST_F(GraphicsTrackerTest, AllocateTest) {
    constexpr uint32_t kGeneration = 1;
    constexpr int kMaxDequeueCount = 10;

    std::shared_ptr<GraphicsTracker> tracker =
            GraphicsTracker::CreateGraphicsTracker(kMaxDequeueCount);
    ASSERT_TRUE(bool(tracker));

    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    std::shared_ptr<BqStatistics> bqStat = std::make_shared<BqStatistics>();

    BufferQueue::createBufferQueue(&producer, &consumer);
    consumer->consumerConnect(new DummyConsumerListener(), true);
    consumer->setMaxAcquiredBufferCount(1);
    IGraphicBufferProducer::QueueBufferOutput qbo{};
    producer->connect(new TestProducerListener(tracker, bqStat, kGeneration),
                      NATIVE_WINDOW_API_MEDIA, true, &qbo);
    producer->setDequeueTimeout(0);
    producer->setGenerationNumber(kGeneration);

    c2_status_t ret = C2_OK;
    ret = tracker->configureGraphics(producer, kGeneration);
    ASSERT_TRUE(ret == C2_OK);
    ASSERT_TRUE(tracker->getCurDequeueable() == kMaxDequeueCount);

    AHardwareBuffer *buf;
    sp<Fence> fence;
    uint64_t bid;
    std::vector<uint64_t> bids;

    // Allocate and dequeueable test
    for (int i = 0; i < kMaxDequeueCount; ++i) {
        ret = tracker->allocate( 0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
        ASSERT_TRUE(ret == C2_OK);
        bqStat->mDequeued++;
        ASSERT_TRUE(tracker->getCurDequeueable() == (kMaxDequeueCount - (i + 1)));
        ASSERT_TRUE(AHardwareBuffer_getId(buf, &bid) == ::android::NO_ERROR);
        bids.push_back(bid);
        ALOGD("alloced : bufferId: %llu", (unsigned long long)bid);
        AHardwareBuffer_release(buf);
    }

    // Blocked allocate test
    ret = tracker->allocate( 0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
    ALOGD("alloc : err(%d, %d)", ret, C2_BLOCKING);
    ASSERT_TRUE(ret == C2_BLOCKING);
    bqStat->mBlocked++;

    // Deallocate and dequeueable test
    for (int i = 0; i < kMaxDequeueCount; ++i) {
        ALOGD("dealloc : bufferId: %llu", (unsigned long long)bids[0]);
        ret = tracker->deallocate(bids[i], Fence::NO_FENCE);
        ASSERT_TRUE(ret == C2_OK);
        ASSERT_TRUE(tracker->getCurDequeueable() == (i + 1));
        bqStat->mDiscarded++;
    }

    // Buffer drop test
    FrameQueue frameQueue;
    std::thread queueThread(queueBuffer, tracker, &frameQueue, bqStat);

    ret = tracker->allocate( 0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
    ASSERT_TRUE(ret == C2_OK);
    bqStat->mDequeued++;
    ASSERT_TRUE(tracker->getCurDequeueable() == (kMaxDequeueCount - 1));
    ASSERT_TRUE(frameQueue.queueItem(buf, fence));

    ret = tracker->allocate( 0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
    ASSERT_TRUE(ret == C2_OK);
    bqStat->mDequeued++;
    ASSERT_TRUE(tracker->getCurDequeueable() == (kMaxDequeueCount - 2));
    ASSERT_TRUE(frameQueue.queueItem(buf, fence));

    ::usleep(1000000);
    frameQueue.stop();
    if (queueThread.joinable()) {
        queueThread.join();
    }

    ASSERT_TRUE(tracker->getCurDequeueable() == (kMaxDequeueCount - 1));

    // Buffer release test
    BufferItem item;
    ASSERT_TRUE(consumer->acquireBuffer(&item, 0) == android::NO_ERROR);
    ASSERT_TRUE(consumer->releaseBuffer(
            item.mSlot, item.mFrameNumber,
            EGL_NO_DISPLAY, EGL_NO_SYNC_KHR, item.mFence) == android::NO_ERROR);
    ASSERT_TRUE(consumer->acquireBuffer(&item, 0) != android::NO_ERROR);
    ::usleep(10000); // Since IProducerListner is async, wait a little bit
                     // here.

    ASSERT_TRUE(tracker->getCurDequeueable() == kMaxDequeueCount);
    ASSERT_TRUE(bqStat->mReleased == 1);
    ASSERT_TRUE(bqStat->mDropped == 1);
    bqStat->log();
}

TEST_F(GraphicsTrackerTest, RenderTest) {
    constexpr uint32_t kGeneration = 1;
    constexpr int kMaxDequeueCount = 10;
    constexpr int kNumAlloc = 20;

    std::shared_ptr<GraphicsTracker> tracker =
            GraphicsTracker::CreateGraphicsTracker(kMaxDequeueCount);
    ASSERT_TRUE(bool(tracker));

    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    std::shared_ptr<BqStatistics> bqStat = std::make_shared<BqStatistics>();

    BufferQueue::createBufferQueue(&producer, &consumer);
    consumer->consumerConnect(new TestConsumerListener(consumer), false);
    IGraphicBufferProducer::QueueBufferOutput qbo{};
    producer->connect(new TestProducerListener(tracker, bqStat, kGeneration),
                      NATIVE_WINDOW_API_MEDIA, false, &qbo);
    producer->setDequeueTimeout(0);
    producer->setGenerationNumber(kGeneration);
    c2_status_t ret = C2_OK;
    ret = tracker->configureGraphics(producer, kGeneration);
    ASSERT_TRUE(ret == C2_OK);

    ret = tracker->configureMaxDequeueCount(kMaxDequeueCount);
    ASSERT_TRUE(ret == C2_OK);

    int waitFd = -1;
    ret = tracker->getWaitableFd(&waitFd);
    ASSERT_TRUE(ret == C2_OK);
    C2Fence waitFence = _C2FenceFactory::CreatePipeFence(waitFd);


    FrameQueue frameQueue;
    std::thread queueThread(queueBuffer, tracker, &frameQueue, bqStat);

    int numAlloc = 0;

    while (numAlloc < kNumAlloc) {
        AHardwareBuffer *buf;
        sp<Fence> fence;
        ret = tracker->allocate(
                0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
        if (ret == C2_BLOCKING) {
            bqStat->mBlocked++;
            c2_status_t waitRes = waitFence.wait(3000000000);
            if (waitRes == C2_TIMED_OUT || waitRes == C2_OK) {
                continue;
            }
            ALOGE("alloc wait failed: c2_err(%d)", waitRes);
            break;
        }
        if (ret != C2_OK) {
            ALOGE("alloc error: c2_err(%d)", ret);
            break;
        }
        bqStat->mDequeued++;
        if (!frameQueue.queueItem(buf, fence)) {
            ALOGE("queue to render failed");
            break;
        }
        ++numAlloc;
    }

    ::usleep(1000000);
    frameQueue.stop();

    if (queueThread.joinable()) {
        queueThread.join();
    }
    ASSERT_TRUE(numAlloc == kNumAlloc && numAlloc == bqStat->mDequeued);
    ASSERT_TRUE(bqStat->mDequeued == bqStat->mQueued);
    ASSERT_TRUE(bqStat->mDequeued == (bqStat->mReleased + bqStat->mDropped));
    bqStat->log();
}
