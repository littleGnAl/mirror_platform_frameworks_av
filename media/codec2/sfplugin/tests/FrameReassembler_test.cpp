/*
 * Copyright 2020 The Android Open Source Project
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

#include "FrameReassembler.h"

#include <gtest/gtest.h>

#include <C2PlatformSupport.h>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

static size_t BytesPerSample(C2Config::pcm_encoding_t encoding) {
    return encoding == PCM_8 ? 1
         : encoding == PCM_16 ? 2
         : encoding == PCM_FLOAT ? 4 : 0;
}

static uint64_t Diff(c2_cntr64_t a, c2_cntr64_t b) {
    return (a > b ? a - b : b - a).peeku();
}

static size_t SmallestMultipleNoSmallerThan(size_t a, size_t b) {
    return (b + a - 1) / a * a;
}

class FrameReassemblerTest : public ::testing::Test {
public:
    static const C2MemoryUsage kUsage;
    static constexpr size_t kDefaultFrameSize = 1024;
    static constexpr size_t kDefaultSampleRate = 48000;
    static constexpr size_t kChannelCountMono = 1;
    static constexpr size_t kChannelCountStereo = 2;
    static constexpr uint64_t kTimestampToleranceUs = 100;
    static constexpr std::initializer_list<C2Config::pcm_encoding_t> kEncodings = {
        C2Config::PCM_16, C2Config::PCM_8, C2Config::PCM_FLOAT,
    };

    FrameReassemblerTest() {
        mInitStatus = GetCodec2BlockPool(C2BlockPool::BASIC_LINEAR, nullptr, &mPool);
    }

    status_t initStatus() const { return mInitStatus; }

    void testPushSameSize(
            size_t encoderFrameSize,
            size_t sampleRate,
            size_t channelCount,
            C2Config::pcm_encoding_t encoding,
            size_t inputFrameSizeInBytes,
            size_t count,
            size_t expectedOutputSize) {
        FrameReassembler frameReassembler;
        frameReassembler.init(
                mPool,
                kUsage,
                encoderFrameSize,
                sampleRate,
                channelCount,
                encoding);

        ASSERT_TRUE(frameReassembler) << "FrameReassembler init failed";

        size_t inputIndex = 0, outputIndex = 0;
        size_t expectCount = 0;
        for (size_t i = 0; i < count; ++i) {
            sp<MediaCodecBuffer> buffer = new MediaCodecBuffer(
                    new AMessage, new ABuffer(inputFrameSizeInBytes));
            buffer->setRange(0, inputFrameSizeInBytes);
            buffer->meta()->setInt64(
                    "timeUs",
                    inputIndex * 1000000 / sampleRate / channelCount / BytesPerSample(encoding));
            if (i == count - 1) {
                buffer->meta()->setInt32("eos", 1);
            }
            for (size_t j = 0; j < inputFrameSizeInBytes; ++j, ++inputIndex) {
                buffer->base()[j] = (inputIndex & 0xFF);
            }
            std::list<std::unique_ptr<C2Work>> items;
            ASSERT_EQ(C2_OK, frameReassembler.process(buffer, &items));
            while (!items.empty()) {
                std::unique_ptr<C2Work> work = std::move(*items.begin());
                items.erase(items.begin());
                // Verify timestamp
                uint64_t expectedTimeUs =
                    outputIndex * 1000000 / sampleRate / channelCount / BytesPerSample(encoding);
                EXPECT_GE(
                        kTimestampToleranceUs,
                        Diff(expectedTimeUs, work->input.ordinal.timestamp))
                    << "expected timestamp: " << expectedTimeUs
                    << " actual timestamp: " << work->input.ordinal.timestamp.peeku()
                    << " output index: " << outputIndex;

                // Verify buffer
                ASSERT_EQ(1u, work->input.buffers.size());
                std::shared_ptr<C2Buffer> buffer = work->input.buffers.front();
                ASSERT_EQ(C2BufferData::LINEAR, buffer->data().type());
                ASSERT_EQ(1u, buffer->data().linearBlocks().size());
                C2ReadView view = buffer->data().linearBlocks().front().map().get();
                ASSERT_EQ(C2_OK, view.error());
                ASSERT_EQ(encoderFrameSize * BytesPerSample(encoding), view.capacity());
                for (size_t j = 0; j < view.capacity(); ++j, ++outputIndex) {
                    ASSERT_TRUE(outputIndex < inputIndex
                             || inputIndex == inputFrameSizeInBytes * count);
                    uint8_t expected = outputIndex < inputIndex ? (outputIndex & 0xFF) : 0;
                    if (expectCount < 10) {
                        ++expectCount;
                        EXPECT_EQ(expected, view.data()[j]) << "output index = " << outputIndex;
                    }
                }
            }
        }

        ASSERT_EQ(inputFrameSizeInBytes * count, inputIndex);
        size_t encoderFrameSizeInBytes =
            encoderFrameSize * channelCount * BytesPerSample(encoding);
        ASSERT_EQ(0, outputIndex % encoderFrameSizeInBytes)
            << "output size must be multiple of frame size: output size = " << outputIndex
            << " frame size = " << encoderFrameSizeInBytes;
        ASSERT_EQ(expectedOutputSize, outputIndex)
            << "output size must be smallest multiple of frame size, "
            << "equal to or larger than input size. output size = " << outputIndex
            << " input size = " << inputIndex << " frame size = " << encoderFrameSizeInBytes;
    }

private:
    status_t mInitStatus;
    std::shared_ptr<C2BlockPool> mPool;
};

const C2MemoryUsage FrameReassemblerTest::kUsage{C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

// Push frames with exactly the same size as the encoder requested.
TEST_F(FrameReassemblerTest, PushExactFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t inputFrameSize = kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding);
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                inputFrameSize,
                10 /* count */,
                inputFrameSize * 10 /* expected output size */);
    }
}

// Push frames with half the size that the encoder requested.
TEST_F(FrameReassemblerTest, PushHalfFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t inputFrameSize =
            kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding) / 2;
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                inputFrameSize,
                10 /* count */,
                inputFrameSize * 10 /* expected output size */);
    }
}

// Push frames with twice the size that the encoder requested.
TEST_F(FrameReassemblerTest, PushDoubleFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t inputFrameSize =
            kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding) * 2;
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                inputFrameSize,
                10 /* count */,
                inputFrameSize * 10 /* expected output size */);
    }
}

// Push frames near the requested size.
TEST_F(FrameReassemblerTest, PushNearFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t inputFrameSize =
            (kDefaultFrameSize - 5) * kChannelCountMono * BytesPerSample(encoding);
        size_t encoderFrameSizeInBytes =
            kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding);
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                inputFrameSize,
                10 /* count */,
                // expected output size
                SmallestMultipleNoSmallerThan(
                    encoderFrameSizeInBytes, inputFrameSize * 10));
        inputFrameSize =
            (kDefaultFrameSize + 5) * kChannelCountMono * BytesPerSample(encoding);
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                inputFrameSize,
                10 /* count */,
                // expected output size
                SmallestMultipleNoSmallerThan(
                    encoderFrameSizeInBytes, inputFrameSize * 10));
    }
}

// Push single-byte frames
TEST_F(FrameReassemblerTest, PushSingleByte) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t encoderFrameSizeInBytes =
            kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding);
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                1 /* input frame size */,
                100000 /* count */,
                // expected output size
                SmallestMultipleNoSmallerThan(encoderFrameSizeInBytes, 100000));
    }
}

// Push one big chunk.
TEST_F(FrameReassemblerTest, PushBigChunk) {
    ASSERT_EQ(OK, initStatus());
    for (C2Config::pcm_encoding_t encoding : kEncodings) {
        size_t encoderFrameSizeInBytes =
            kDefaultFrameSize * kChannelCountMono * BytesPerSample(encoding);
        testPushSameSize(
                kDefaultFrameSize,
                kDefaultSampleRate,
                kChannelCountMono,
                encoding,
                100000 /* input frame size */,
                1 /* count */,
                // expected output size
                SmallestMultipleNoSmallerThan(encoderFrameSizeInBytes, 100000));
    }
}

} // namespace android
