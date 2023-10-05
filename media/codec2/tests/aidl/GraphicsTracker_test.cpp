#include <unistd.h>

#include <codec2/aidl/GraphicsTracker.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
// #include <gtest/gtest.h>
#include <gui/BufferQueue.h>
#include <gui/IConsumerListener.h>
#include <gui/Surface.h>

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
    std::atomic<int> mReleased;

    void show() {
        std::cout << "Dequeued: " << mDequeued << std::endl;
        std::cout << "Queued: " << mQueued << std::endl;
        std::cout << "Blocked: " << mBlocked << std::endl;
        std::cout << "Dropped: " << mDropped << std::endl;
        std::cout << "Released: " << mReleased << std::endl;
    }
};

struct TestConsumerListener : public android::BnConsumerListener {
    TestConsumerListener(const sp<IGraphicBufferConsumer> &consumer)
            : BnConsumerListener(), mConsumer(consumer) {}
    void onFrameAvailable(const BufferItem&) override {
        BufferItem buffer;
        // consume buffer
        sp<IGraphicBufferConsumer> consumer = mConsumer.promote();
        if (consumer != nullptr && consumer->acquireBuffer(&buffer, 0) == android::NO_ERROR) {
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
        int slot_;
        sp<GraphicBuffer> buffer_;

        Frame() : slot_{-1}, buffer_{nullptr} {}
        Frame(int slot, sp<GraphicBuffer> &buffer)
                : slot_(slot), buffer_(buffer) {}
    };

    bool mStopped;
    std::queue<Frame> mQueue;
    std::mutex mMutex;
    std::condition_variable mCond;

    FrameQueue() : mStopped{false} {}

    void queueItem(int slot, sp<GraphicBuffer> &buffer) {
        std::unique_lock<std::mutex> l(mMutex);
        mQueue.emplace(slot, buffer);
        l.unlock();
        mCond.notify_all();
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

    bool waitItem(Frame *frame) {
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
        const sp<IGraphicBufferProducer> &producer,
        FrameQueue *queue,
        std::shared_ptr<BqStatistics> stat) {
    FrameQueue::Frame frame;
    while(queue->waitItem(&frame)) {
        IGraphicBufferProducer::QueueBufferInput input(
                0, false,
                HAL_DATASPACE_UNKNOWN, android::Rect(0, 0, 1, 1),
                NATIVE_WINDOW_SCALING_MODE_FREEZE, 0, Fence::NO_FENCE);
        IGraphicBufferProducer::QueueBufferOutput output{};

        android::status_t ret = producer->queueBuffer(
                frame.slot_, input, &output);
        if (ret != android::NO_ERROR) {
            std::cout << "queueBuffer() failed" << std::endl;
            continue;
        }
        stat->mQueued++;
        if (output.bufferReplaced) {
            stat->mDropped++;
            std::cout << "buffer might be dropped" << std::endl;
        }
    }
}

int main() {
    auto tracker = GraphicsTracker::CreateGraphicsTracker(10);

    if (tracker) {
        std::cout << "GraphicsTracker created" << std::endl;
    } else {
        std::cout << "GraphicsTracker creation failed" << std::endl;
    }
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    std::shared_ptr<BqStatistics> bqStat = std::make_shared<BqStatistics>();
    uint32_t generation = 0;
    int maxDequeueCount = 10;

    BufferQueue::createBufferQueue(&producer, &consumer);
    // android::ProcessState::self()->startThreadPool();
    // android::IPCThreadState::self()->joinThreadPool();

    consumer->consumerConnect(new TestConsumerListener(consumer), false);
    IGraphicBufferProducer::QueueBufferOutput qbo{};

    producer->connect(new TestProducerListener(tracker, bqStat, generation),
                      NATIVE_WINDOW_API_MEDIA, false, &qbo);
    producer->setDequeueTimeout(0);

    /*
    producer->setGenerationNumber(0);
    producer->setMaxDequeuedBufferCount(10);
    */
    c2_status_t ret = C2_OK;
    ret = tracker->configureGraphics(producer, generation);
    std::cout << "configure graphics: " << ret << std::endl;
    /*
    ret = tracker->configureMaxDequeueCount(maxDequeueCount);
    std::cout << "configure max dequeue count: " << ret << std::endl;

    AHardwareBuffer *buf;
    sp<Fence> fence;

    ret = tracker->allocate(
            0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN, &buf, &fence);
    std::cout << "allocate: " << ret << std::endl;
    */

    /*
    sp<GraphicBuffer> cache[100] = {};
    FrameQueue frameQueue;


    std::thread queueThread{queueBuffer, producer, &frameQueue, bqStat};

    int slot;
    sp<Fence> fence;
    sp<GraphicBuffer> buffer;
    int numAlloc = 0;
    while (numAlloc < 100) {
        android::status_t ret = producer->dequeueBuffer(
                &slot, &fence, 0, 0, 0, GRALLOC_USAGE_SW_WRITE_OFTEN,
                nullptr, nullptr);
        bool realloc = false;
        if (ret & IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION) {
            ret &= ~(IGraphicBufferProducer::BUFFER_NEEDS_REALLOCATION);
            realloc = true;
        }
        if (ret == android::WOULD_BLOCK || ret == android::TIMED_OUT ||
            ret == android::INVALID_OPERATION) {
            bqStat->mBlocked++;
            continue;
        }
        if (ret != android::NO_ERROR) {
            std::cout << ret << " dequeue failed" << std::endl;
            break;
        }
        bqStat->mDequeued++;
        if (realloc) {
            ret = producer->requestBuffer(slot, &buffer);
            if (ret != android::NO_ERROR) {
                std::cout << ret << " request failed" << std::endl;
                break;
            }
            cache[slot] = buffer;
        }
        frameQueue.queueItem(slot, cache[slot]);
        numAlloc++;
    }
    ::usleep(1000000);
    frameQueue.stop();

    if (queueThread.joinable()) {
        queueThread.join();
    }
    std::cout << numAlloc << " allocated." << std::endl;
    bqStat->show();
    */
}
