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
#define LOG_TAG "Mpeg2tsUnitTest"

#include <utils/Log.h>

#include <stdint.h>
#include <sys/stat.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataBase.h>
#include <media/stagefright/foundation/AUtils.h>

#include "mpeg2ts/ATSParser.h"
#include "mpeg2ts/AnotherPacketSource.h"

#include "Mpeg2tsUnitTestEnvironment.h"

constexpr size_t kTSPacketSize = 188;
constexpr uint16_t kPIDMask = 0x1FFF;
// Max value of PID which is also used for Null packets
constexpr uint16_t kPIDMaxValue = 8191;
constexpr uint8_t kTSSyncByte = 0x47;
constexpr uint8_t kVideoPresent = 0x01;
constexpr uint8_t kAudioPresent = 0x02;
constexpr uint8_t kMetaDataPresent = 0x04;

static Mpeg2tsUnitTestEnvironment *gEnv = nullptr;

using namespace android;

class Mpeg2tsUnitTest
    : public ::testing ::TestWithParam<
              tuple</*fileName*/ string, /*sourceType*/ char, /*numSource*/ uint16_t>> {
  public:
    Mpeg2tsUnitTest()
        : mInputBuffer(nullptr), mSource(nullptr), mFpInput(nullptr), mParser(nullptr) {}

    ~Mpeg2tsUnitTest() {
        if (mInputBuffer) free(mInputBuffer);
        if (mFpInput) fclose(mFpInput);
    }

    void SetUp() override {
        mOffset = 0;
        mNumDataSource = 0;
        tuple<string, char, uint16_t> params = GetParam();
        char sourceType = get<1>(params);
        /* mSourceType = 0b x x x x x M A V
                                     /  |  \
                            metaData  audio  video */
        mMediaType = (sourceType & 0x07);
        mNumDataSource = get<2>(params);
        string inputFile = gEnv->getRes() + get<0>(params);
        mFpInput = fopen(inputFile.c_str(), "rb");
        ASSERT_NE(mFpInput, nullptr) << "Failed to open file: " << inputFile;

        struct stat buf;
        stat(inputFile.c_str(), &buf);
        long fileSize = buf.st_size;
        mTotalPackets = fileSize / kTSPacketSize;
        int32_t fd = fileno(mFpInput);
        mSource = new FileSource(dup(fd), 0, buf.st_size);
        ASSERT_NE(mSource, nullptr) << "Failed to get the data source!";

        mParser = new ATSParser();
        ASSERT_NE(mParser, nullptr) << "Unable to create ATS parser!";
        mInputBuffer = (uint8_t *)malloc(kTSPacketSize);
        ASSERT_NE(mInputBuffer, nullptr) << "Failed to allocate memory for TS packet!";
    }

    uint64_t mOffset;
    uint64_t mTotalPackets;
    uint16_t mNumDataSource;

    int8_t mMediaType;
    char mHeader;

    uint8_t *mInputBuffer;
    string mInputFile;
    sp<DataSource> mSource;
    FILE *mFpInput;
    ATSParser *mParser;
};

TEST_P(Mpeg2tsUnitTest, MediaInfoTest) {
    bool videoFound = false;
    bool audioFound = false;
    bool metaDataFound = false;

    int16_t totalDataSource = 0;
    int32_t val32 = 0;
    uint8_t numDataSource = 0;
    uint8_t packet[kTSPacketSize];
    ssize_t numBytesRead = -1;
    Vector<off64_t> syncOffsetPoints;

    ATSParser::SourceType currentPacketMediaType;
    static const ATSParser::SourceType mediaType[] = {ATSParser::VIDEO, ATSParser::AUDIO,
                                                      ATSParser::META, ATSParser::NUM_SOURCE_TYPES};
    const uint32_t nMediaTypes = sizeof(mediaType) / sizeof(mediaType[0]);

    while ((numBytesRead = mSource->readAt(mOffset, packet, kTSPacketSize)) == kTSPacketSize) {
        ASSERT_TRUE(packet[0] == kTSSyncByte) << "Sync byte error!";

        ATSParser::SyncEvent event(mOffset);
        status_t err = mParser->feedTSPacket(packet, kTSPacketSize, &event);
        ASSERT_EQ(err, (status_t)OK) << "Unable to feed TS packet!";

        mOffset += numBytesRead;
        int i;
        for (i = 0; i < nMediaTypes; i++) {
            if (mParser->hasSource(mediaType[i])) {
                currentPacketMediaType = mediaType[i];
                break;
            }
        }
        if (i == nMediaTypes) {
            // pid is 13 bits
            int16_t pid = (packet[1] + (packet[2] << 8)) & kPIDMask;
            ASSERT_TRUE(pid >= 0 && pid <= kPIDMaxValue) << "Invalid PID: " << pid;
        }

        // if the packet is not a sync packet
        if (!event.hasReturnedData()) {
            sp<AnotherPacketSource> packetSource = mParser->getSource(currentPacketMediaType);
            // The library returns packetSource only if the media type is: Video/Audio/MetaData
            if (packetSource != nullptr) {
                err = packetSource->start();
                ASSERT_EQ(err, (status_t)OK) << "Error returned while starting!";
                sp<MetaData> format = packetSource->getFormat();
                ASSERT_NE(format, nullptr) << "Unable to get the format of the packet!";

                err = packetSource->stop();
                ASSERT_EQ(err, (status_t)OK) << "Error returned while stopping!";
            }
        } else {
            currentPacketMediaType = event.getType();
            sp<AnotherPacketSource> syncPacketSource = event.getMediaSource();
            err = syncPacketSource->start();
            ASSERT_EQ(err, (status_t)OK) << "Error returned while starting!";

            syncOffsetPoints.push(event.getOffset());
            sp<MetaData> format = syncPacketSource->getFormat();
            ASSERT_NE(format, nullptr) << "Unable to get the format of the source packet!";

            MediaBufferBase *buf;
            syncPacketSource->read(&buf, nullptr);
            MetaDataBase &inMeta = buf->meta_data();
            bool status = inMeta.findInt32(kKeyIsSyncFrame, &val32);
            ASSERT_EQ(status, true) << "Sync frame key is not set";

            status = inMeta.findInt32(kKeyCryptoMode, &val32);
            ASSERT_EQ(status, false) << "Invalid packet, found scrambled packets!";

            err = syncPacketSource->stop();
            ASSERT_EQ(err, (status_t)OK) << "Error returned while stopping!";
        }

        switch (currentPacketMediaType) {
            case ATSParser::VIDEO:
                ALOGV("Video Returned");
                videoFound = true;
                break;
            case ATSParser::AUDIO:
                ALOGV("Audio Returned");
                audioFound = true;
                break;
            case ATSParser::META:
                ALOGV("MetaData Returned");
                metaDataFound = true;
                break;
            case ATSParser::NUM_SOURCE_TYPES:
                ALOGV("NUM_SOURCE_TYPES Returned");
                numDataSource = 3;
                break;
            default:
                ALOGV("Unknown data returned");
                break;
        }
    }

    ASSERT_EQ(numBytesRead, 0) << "Invalid file size";
    mParser->signalEOS(ERROR_END_OF_STREAM);

    ASSERT_EQ(videoFound, bool(mMediaType & kVideoPresent)) << "No Video packets found!";
    ASSERT_EQ(audioFound, bool(mMediaType & kAudioPresent)) << "No Audio packets found!";
    ASSERT_EQ(metaDataFound, bool(mMediaType & kMetaDataPresent)) << "No meta data found!";

    ASSERT_LT(syncOffsetPoints.size(), mTotalPackets)
            << "Sync packets must not be equal to total number of packets";

    if (videoFound || audioFound) {
        ASSERT_GT(syncOffsetPoints.size(), 0) << "No sync points found for audio/video";
    }

    if (videoFound) totalDataSource += 1;
    if (audioFound) totalDataSource += 1;
    if (metaDataFound) totalDataSource += 1;

    ASSERT_TRUE(totalDataSource == mNumDataSource)
            << "Expected " << mNumDataSource << " data sources, found " << totalDataSource;
    if (numDataSource == 3) {
        ASSERT_EQ(numDataSource, mNumDataSource)
                << "Expected " << mNumDataSource << " data sources, found " << totalDataSource;
    }
}

INSTANTIATE_TEST_SUITE_P(
        infoTest, Mpeg2tsUnitTest,
        ::testing::Values(make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts", 0x01, 1),
                          make_tuple("segment000001.ts", 0x03, 2),
                          make_tuple("bbb_44100hz_2ch_128kbps_mp3_5mins.ts", 0x02, 1)));

int32_t main(int argc, char **argv) {
    gEnv = new Mpeg2tsUnitTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    uint8_t status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Mpeg2tsUnit Test Result = %d\n", status);
    }
    return status;
}
