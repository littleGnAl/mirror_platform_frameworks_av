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

//#define LOG_NDEBUG 0
#define LOG_TAG "WebmFrameThreadUnitTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include "WebmFrameThreadUtility.h"

static constexpr int32_t kNumFramesToWrite = 32;
static constexpr int32_t kSyncFrameInterval = 10;
static constexpr uint64_t kDefaultTimeCodeScaleUs = 1000000; /* 1sec */

#define OUTPUT_FILE_NAME "/data/local/tmp/webmFrameThreadOutput.webm"

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    const char *mime;
    int32_t firstParam;
    int32_t secondParam;
    bool isAudio;
} kInputData[] = {
        {MEDIA_MIMETYPE_AUDIO_OPUS, 48000, 6, true},
        {MEDIA_MIMETYPE_AUDIO_VORBIS, 44100, 1, true},
        {MEDIA_MIMETYPE_VIDEO_VP9, 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_VP8, 1920, 1080, false},
};

class WebmFrameThreadUnitTest : public ::testing::TestWithParam<int32_t> {
  public:
    WebmFrameThreadUnitTest()
        : mSource(nullptr), mSinkThread(nullptr), mAudioThread(nullptr), mVideoThread(nullptr) {}

    ~WebmFrameThreadUnitTest() {
        if (mSource) mSource.clear();
        if (mSinkThread) mSinkThread.clear();
        if (mAudioThread) mAudioThread.clear();
        if (mVideoThread) mVideoThread.clear();
    }

    virtual void SetUp() override {
        mSegmentDataStart = 0;
        mFd = open(OUTPUT_FILE_NAME, O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        ASSERT_GE(mFd, 0) << "Failed to open output file " << OUTPUT_FILE_NAME;
    }

    virtual void TearDown() override {
        if (mFd >= 0) close(mFd);
        mStreamsInOrder.clear();
        mVSink.clear();
        mASink.clear();
    }

    void addTrack(bool isAudio, int32_t index);
    void writeFileData(int32_t inputFrameId, int32_t range);

    int32_t mFd;
    uint64_t mSegmentDataStart;

    sp<MediaAdapter> mSource;
    sp<WebmFrameSinkThread> mSinkThread;
    sp<WebmFrameSourceThread> mAudioThread;
    sp<WebmFrameSourceThread> mVideoThread;

    Vector<sp<WebmElement>> mStreamsInOrder;
    LinkedBlockingQueue<const sp<WebmFrame>> mVSink;
    LinkedBlockingQueue<const sp<WebmFrame>> mASink;
};

void WebmFrameThreadUnitTest::addTrack(bool isAudio, int32_t index) {
    ASSERT_LT(index, sizeof(kInputData) / sizeof(kInputData[0]))
            << "Invalid index for loopup table";

    sp<AMessage> format = new AMessage;
    format->setString("mime", kInputData[index].mime);
    if (!isAudio) {
        format->setInt32("width", kInputData[index].firstParam);
        format->setInt32("height", kInputData[index].secondParam);
    } else {
        format->setInt32("sample-rate", kInputData[index].firstParam);
        format->setInt32("channel-count", kInputData[index].secondParam);
        writeAudioHeaderData(format, kInputData[index].mime);
    }

    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);

    mSource = new MediaAdapter(trackMeta);
    ASSERT_NE(mSource, nullptr) << "Unable to create source";

    sp<WebmElement> trackEntry;
    if (!isAudio) {
        trackEntry = videoTrack(mSource->getFormat());
    } else {
        trackEntry = audioTrack(mSource->getFormat());
    }
    ASSERT_NE(trackEntry, nullptr) << "No source added";
    mStreamsInOrder.push_back(trackEntry);
}

// Write dummy data to a file
void WebmFrameThreadUnitTest::writeFileData(int32_t inputFrameId, int32_t range) {
    int32_t size = 128;
    char data[size];
    memset(data, 0xFF, size);
    int32_t status = OK;
    do {
        sp<ABuffer> buffer = new ABuffer((void *)data, size);
        ASSERT_NE(buffer.get(), nullptr) << "ABuffer returned nullptr";

        // Released in MediaAdapter::signalBufferReturned().
        MediaBuffer *mediaBuffer = new MediaBuffer(buffer);
        mediaBuffer->add_ref();
        mediaBuffer->set_range(buffer->offset(), buffer->size());

        MetaDataBase &sampleMetaData = mediaBuffer->meta_data();
        sampleMetaData.setInt64(kKeyTime, inputFrameId * kDefaultTimeCodeScaleUs);

        if (inputFrameId % kSyncFrameInterval == 0) {
            sampleMetaData.setInt32(kKeyIsSyncFrame, true);
        }

        // This pushBuffer will wait until the mediaBuffer is consumed.
        status = mSource->pushBuffer(mediaBuffer);
        ASSERT_EQ(status, OK);
        inputFrameId++;
    } while (inputFrameId < range);
}

TEST_P(WebmFrameThreadUnitTest, WriteTest) {
    List<sp<WebmElement>> cuePoints;
    mSinkThread = new WebmFrameSinkThread(mFd, mSegmentDataStart, mVSink, mASink, cuePoints);
    ASSERT_NE(mSinkThread, nullptr) << "Failed to create Sink Thread";

    int32_t index = GetParam();
    bool isAudio = kInputData[index].isAudio;
    ASSERT_NO_FATAL_FAILURE(addTrack(isAudio, index));

    if (!isAudio) {
        mVideoThread = new WebmFrameMediaSourceThread(mSource, kVideoType, mVSink,
                                                      kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        mAudioThread = new WebmFrameEmptySourceThread(kAudioType, mASink);
    } else {
        mAudioThread = new WebmFrameMediaSourceThread(mSource, kAudioType, mASink,
                                                      kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        mVideoThread = new WebmFrameEmptySourceThread(kVideoType, mVSink);
    }
    ASSERT_NE(mVideoThread, nullptr) << "Failed to create Video Thread";
    ASSERT_NE(mAudioThread, nullptr) << "Failed to create Audio Thread";

    status_t status = mAudioThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Audio Thread";
    status = mVideoThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Video Thread";
    status = mSinkThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Sink Thread";

    ASSERT_NO_FATAL_FAILURE(writeFileData(0, kNumFramesToWrite));

    mSource->stop();
    status = mAudioThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Audio Thread";
    status = mVideoThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Video Thread";
    status = mSinkThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Sink Thread";
}

TEST_P(WebmFrameThreadUnitTest, PauseTest) {
    List<sp<WebmElement>> cuePoints;
    mSinkThread = new WebmFrameSinkThread(mFd, mSegmentDataStart, mVSink, mASink, cuePoints);
    ASSERT_NE(mSinkThread, nullptr) << "Failed to create Sink Thread";

    int32_t index = GetParam();
    bool isAudio = kInputData[index].isAudio;
    ASSERT_NO_FATAL_FAILURE(addTrack(isAudio, index));

    if (!isAudio) {
        mVideoThread = new WebmFrameMediaSourceThread(mSource, kVideoType, mVSink,
                                                      kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        mAudioThread = new WebmFrameEmptySourceThread(kAudioType, mASink);
    } else {
        mAudioThread = new WebmFrameMediaSourceThread(mSource, kAudioType, mASink,
                                                      kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        mVideoThread = new WebmFrameEmptySourceThread(kVideoType, mVSink);
    }
    ASSERT_NE(mVideoThread, nullptr) << "Failed to create Video Thread";
    ASSERT_NE(mAudioThread, nullptr) << "Failed to create Audio Thread";

    status_t status = mAudioThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Audio Thread";
    status = mVideoThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Video Thread";
    status = mSinkThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Sink Thread";

    int32_t offset = 0;
    ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
    offset += kNumFramesToWrite;

    for (int idx = 0; idx < 5; idx++) {
        // pause the threads
        status = mAudioThread->pause();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to pause Audio Thread";
        status = mVideoThread->pause();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to pause Video Thread";

        // Under pause state, no write should happen
        ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
        offset += kNumFramesToWrite;

        status = mAudioThread->resume();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to resume Audio Thread";
        status = mVideoThread->resume();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to resume Video Thread";

        ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
        offset += kNumFramesToWrite;
    }

    mSource->stop();
    status = mAudioThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Audio Thread";
    status = mVideoThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Video Thread";
    status = mSinkThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Sink Thread";
}

INSTANTIATE_TEST_SUITE_P(WebmFrameThreadUnitTestAll, WebmFrameThreadUnitTest,
                         ::testing::Values(0, 1, 2, 3));

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
