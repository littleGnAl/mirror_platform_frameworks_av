/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <future>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <media/stagefright/CodecBase.h>
#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaCodecListWriter.h>
#include <media/MediaCodecInfo.h>

#include "StagefrightTestHelper.h"

namespace android {

class MockBufferChannel : public BufferChannelBase {
public:
    ~MockBufferChannel() override = default;

    MOCK_METHOD(void, setCrypto, (const sp<ICrypto> &crypto), (override));
    MOCK_METHOD(void, setDescrambler, (const sp<IDescrambler> &descrambler), (override));
    MOCK_METHOD(status_t, queueInputBuffer, (const sp<MediaCodecBuffer> &buffer), (override));
    MOCK_METHOD(status_t, queueSecureInputBuffer,
            (const sp<MediaCodecBuffer> &buffer,
             bool secure,
             const uint8_t *key,
             const uint8_t *iv,
             CryptoPlugin::Mode mode,
             CryptoPlugin::Pattern pattern,
             const CryptoPlugin::SubSample *subSamples,
             size_t numSubSamples,
             AString *errorDetailMsg),
            (override));
    MOCK_METHOD(status_t, attachBuffer,
            (const std::shared_ptr<C2Buffer> &c2Buffer, const sp<MediaCodecBuffer> &buffer),
            (override));
    MOCK_METHOD(status_t, attachEncryptedBuffer,
            (const sp<hardware::HidlMemory> &memory,
             bool secure,
             const uint8_t *key,
             const uint8_t *iv,
             CryptoPlugin::Mode mode,
             CryptoPlugin::Pattern pattern,
             size_t offset,
             const CryptoPlugin::SubSample *subSamples,
             size_t numSubSamples,
             const sp<MediaCodecBuffer> &buffer),
            (override));
    MOCK_METHOD(status_t, renderOutputBuffer,
            (const sp<MediaCodecBuffer> &buffer, int64_t timestampNs),
            (override));
    MOCK_METHOD(status_t, discardBuffer, (const sp<MediaCodecBuffer> &buffer), (override));
    MOCK_METHOD(void, getInputBufferArray, (Vector<sp<MediaCodecBuffer>> *array), (override));
    MOCK_METHOD(void, getOutputBufferArray, (Vector<sp<MediaCodecBuffer>> *array), (override));
};

class MockCodec : public CodecBase {
public:
    MockCodec(std::function<void(const std::shared_ptr<MockBufferChannel> &)> mock) {
        mMockBufferChannel = std::make_shared<MockBufferChannel>();
        mock(mMockBufferChannel);
    }
    ~MockCodec() override = default;

    MOCK_METHOD(void, initiateAllocateComponent, (const sp<AMessage> &msg), (override));
    MOCK_METHOD(void, initiateConfigureComponent, (const sp<AMessage> &msg), (override));
    MOCK_METHOD(void, initiateCreateInputSurface, (), (override));
    MOCK_METHOD(void, initiateSetInputSurface, (const sp<PersistentSurface> &surface), (override));
    MOCK_METHOD(void, initiateStart, (), (override));
    MOCK_METHOD(void, initiateShutdown, (bool keepComponentAllocated), (override));
    MOCK_METHOD(void, onMessageReceived, (const sp<AMessage> &msg), (override));
    MOCK_METHOD(status_t, setSurface, (const sp<Surface> &surface), (override));
    MOCK_METHOD(void, signalFlush, (), (override));
    MOCK_METHOD(void, signalResume, (), (override));
    MOCK_METHOD(void, signalRequestIDRFrame, (), (override));
    MOCK_METHOD(void, signalSetParameters, (const sp<AMessage> &msg), (override));
    MOCK_METHOD(void, signalEndOfInputStream, (), (override));

    std::shared_ptr<BufferChannelBase> getBufferChannel() override {
        return mMockBufferChannel;
    }

    const std::unique_ptr<CodecCallback> &callback() {
        return mCallback;
    }

    std::shared_ptr<MockBufferChannel> mMockBufferChannel;
};

class Counter {
public:
    Counter() = default;
    explicit Counter(int32_t initCount) : mCount(initCount) {}
    ~Counter() = default;

    int32_t advance() {
        std::unique_lock<std::mutex> lock(mMutex);
        ++mCount;
        mCondition.notify_all();
        return mCount;
    }

    template <typename Rep, typename Period, typename ...Args>
    int32_t waitFor(const std::chrono::duration<Rep, Period> &duration, Args... values) {
        std::initializer_list<int32_t> list = {values...};
        std::unique_lock<std::mutex> lock(mMutex);
        mCondition.wait_for(
                lock,
                duration,
                [&list, this]{
                    return std::find(list.begin(), list.end(), mCount) != list.end();
                });
        return mCount;
    }

    template <typename ...Args>
    int32_t wait(Args... values) {
        std::initializer_list<int32_t> list = {values...};
        std::unique_lock<std::mutex> lock(mMutex);
        mCondition.wait(
                lock,
                [&list, this]{
                    return std::find(list.begin(), list.end(), mCount) != list.end();
                });
        return mCount;
    }

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    int32_t mCount = 0;
};

}  // namespace android

using namespace android;
using ::testing::_;

TEST(MediaCodecTest, ReclaimReleaseRace) {
    static const AString kCodecName{"test.codec"};
    static const AString kCodecOwner{"nobody"};
    static const AString kMediaType{"video/x-test"};

    enum {
        kInit,
        kShutdownFromReclaimReceived,
        kReleaseCalled,
    };
    Counter counter{kInit};
    sp<MockCodec> mockCodec;
    std::function<sp<CodecBase>(const AString &name, const char *owner)> getCodecBase =
        [&mockCodec, &counter](const AString &, const char *) {
            mockCodec = new MockCodec([](const std::shared_ptr<MockBufferChannel> &) {
                // No mock setup, as we don't expect any buffer operations
                // in this scenario.
            });
            ON_CALL(*mockCodec, initiateAllocateComponent(_))
                .WillByDefault([mockCodec](const sp<AMessage> &) {
                    mockCodec->callback()->onComponentAllocated(kCodecName.c_str());
                });
            ON_CALL(*mockCodec, initiateShutdown(_))
                .WillByDefault([mockCodec, &counter](bool) {
                    int32_t stage = counter.wait(kInit, kReleaseCalled);
                    if (stage == kInit) {
                        counter.advance();
                    } else if (stage == kReleaseCalled) {
                        mockCodec->callback()->onReleaseCompleted();
                    }
                });
            return mockCodec;
        };

    std::shared_ptr<MediaCodecListWriter> listWriter =
        StagefrightTestHelper::CreateCodecListWriter();
    std::unique_ptr<MediaCodecInfoWriter> infoWriter = listWriter->addMediaCodecInfo();
    infoWriter->setName(kCodecName.c_str());
    infoWriter->setOwner(kCodecOwner.c_str());
    infoWriter->addMediaType(kMediaType.c_str());
    std::vector<sp<MediaCodecInfo>> codecInfos;
    StagefrightTestHelper::WriteCodecInfos(listWriter, &codecInfos);
    std::function<sp<MediaCodecInfo>(const AString &, status_t *)> getCodecInfo =
        [codecInfos](const AString &name, status_t *err) -> sp<MediaCodecInfo> {
            auto it = std::find_if(
                    codecInfos.begin(), codecInfos.end(),
                    [&name](const sp<MediaCodecInfo> &info) {
                        return name.equalsIgnoreCase(info->getCodecName());
                    });
            *err = (it == codecInfos.end()) ? NAME_NOT_FOUND : OK;
            return (it == codecInfos.end()) ? nullptr : *it;
        };

    sp<ALooper> looper{new ALooper};
    looper->start();
    sp<MediaCodec> codec = StagefrightTestHelper::CreateCodec(
            kCodecName, looper, getCodecBase, getCodecInfo);
    ASSERT_NE(nullptr, codec) << "Codec must not be null";
    ASSERT_NE(nullptr, mockCodec) << "MockCodec must not be null";
    std::promise<void> reclaimCompleted;
    std::promise<void> releaseCompleted;
    Counter threadExitCounter;
    std::thread([codec, &reclaimCompleted]{
        StagefrightTestHelper::Reclaim(codec, true /* force */);
        reclaimCompleted.set_value();
    }).detach();
    std::thread([codec, &counter, &releaseCompleted]{
        (void)counter.wait(kShutdownFromReclaimReceived);
        counter.advance();
        codec->release();
        releaseCompleted.set_value();
    }).detach();
    std::thread([mockCodec, &counter]{
        (void)counter.wait(kReleaseCalled);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        mockCodec->callback()->onReleaseCompleted();
    }).detach();
    EXPECT_EQ(std::future_status::ready, reclaimCompleted.get_future().wait_for(std::chrono::seconds(5)))
            << "reclaim timed out";
    EXPECT_EQ(std::future_status::ready, releaseCompleted.get_future().wait_for(std::chrono::seconds(5)))
            << "release timed out";
    looper->stop();
}
