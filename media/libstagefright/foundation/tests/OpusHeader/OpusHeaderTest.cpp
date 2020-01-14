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
#define LOG_TAG "OpusHeaderTest"
#include <utils/Log.h>

#include <fstream>
#include <stdio.h>
#include <string.h>

#include <media/stagefright/foundation/OpusHeader.h>

#include "OpusHeaderTestEnvironment.h"

using namespace android;

#define OUTPUT_FILE_NAME "/data/local/tmp/OpusOutput"

// Opus in WebM is a well-known, yet under-documented, format. The codec private data
// of the track is an Opus Ogg header (https://tools.ietf.org/html/rfc7845#section-5.1)

// channel mapping offset in opus header
constexpr size_t kOpusHeaderStreamMapOffset = 21;
constexpr uint32_t kSampleRate = 48000;
constexpr uint32_t kSeekPrerollNs = 80000000;

static OpusHeaderTestEnvironment *gEnv = nullptr;

class OpusHeaderTest {
  public:
    OpusHeaderTest() : mInputBuffer(nullptr) {}

    ~OpusHeaderTest() {
        if (mEleStream.is_open()) mEleStream.close();
        if (mInputBuffer) {
            free(mInputBuffer);
            mInputBuffer = nullptr;
        }
    }
    ifstream mEleStream;
    uint8_t *mInputBuffer;
};

class OpusHeaderParseTest : public OpusHeaderTest,
                            public ::testing::TestWithParam<tuple<string, int32_t, bool>> {};

class OpusHeaderWriteTest : public OpusHeaderTest,
                            public ::testing::TestWithParam<pair<int32_t, int32_t>> {};

TEST_P(OpusHeaderWriteTest, WriteTest) {
    OpusHeader opusHeader;
    memset(&opusHeader, 0, sizeof(opusHeader));
    int32_t channels = GetParam().first;
    opusHeader.channels = channels;
    opusHeader.num_streams = channels;
    opusHeader.channel_mapping = ((channels > 8) ? 255 : (channels > 2));
    int32_t skipSamples = GetParam().second;
    opusHeader.skip_samples = skipSamples;
    // Codec delay in ns
    uint64_t codecDelay = skipSamples * 1000000000ll / kSampleRate;
    uint8_t headerData[100];
    int32_t headerSize = WriteOpusHeaders(opusHeader, kSampleRate, headerData, sizeof(headerData),
                                          codecDelay, kSeekPrerollNs);
    ASSERT_GT(headerSize, 0) << "failed to generate Opus header";

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, ofstream::binary);
    ASSERT_TRUE(ostrm.is_open()) << "Failed to open " << OUTPUT_FILE_NAME;

    ostrm.write(reinterpret_cast<char *>(headerData), sizeof(headerData));
    ostrm.close();

    size_t opusHeadSize = 0;
    size_t codecDelayBufSize = 0;
    size_t seekPreRollBufSize = 0;
    void *opusHeadBuf = nullptr;
    void *codecDelayBuf = nullptr;
    void *seekPreRollBuf = nullptr;
    bool status = GetOpusHeaderBuffers(headerData, headerSize, &opusHeadBuf, &opusHeadSize,
                                       &codecDelayBuf, &codecDelayBufSize, &seekPreRollBuf,
                                       &seekPreRollBufSize);
    ASSERT_TRUE(status) << "Encountered error in GetOpusHeaderBuffers";

    OpusHeader header;
    status = ParseOpusHeader((uint8_t *)opusHeadBuf, opusHeadSize, &header);
    ASSERT_TRUE(status) << "Encountered error while Parsing Opus Header.";

    ASSERT_EQ(header.channels, channels)
            << "Mismatch between no of channels written and no of channels got after parsing";

    ASSERT_EQ(header.skip_samples, skipSamples) << "Mismatch between no of skipSamples written "
                                                   "and no of skipSamples got after parsing";
}

TEST_P(OpusHeaderParseTest, ParseTest) {
    tuple<string /* InputFileName */, int32_t /* ChannelCount */, bool /* isValid */> params =
            GetParam();
    string inputFileName = gEnv->getRes() + get<0>(params);
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << get<0>(params);

    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    size_t fileSize = buf.st_size;
    mInputBuffer = (uint8_t *)malloc(fileSize);
    ASSERT_NE(mInputBuffer, nullptr) << "Insufficient %d bytes memory" << fileSize;

    mEleStream.read(reinterpret_cast<char *>(mInputBuffer), fileSize);
    ASSERT_EQ(mEleStream.gcount(), fileSize) << "mEleStream.gcount() != bytesCount";

    OpusHeader header;
    size_t opusHeadSize = 0;
    size_t codecDelayBufSize = 0;
    size_t seekPreRollBufSize = 0;
    void *opusHeadBuf = nullptr;
    void *codecDelayBuf = nullptr;
    void *seekPreRollBuf = nullptr;
    bool status = GetOpusHeaderBuffers(mInputBuffer, fileSize, &opusHeadBuf, &opusHeadSize,
                                       &codecDelayBuf, &codecDelayBufSize, &seekPreRollBuf,
                                       &seekPreRollBufSize);
    bool isValid = get<2>(params);
    if (!status) {
        ASSERT_FALSE(isValid) << "GetOpusHeaderBuffers failed";
        return;
    }
    status = ParseOpusHeader((uint8_t *)opusHeadBuf, opusHeadSize, &header);
    if (!isValid) {
        ASSERT_FALSE(status) << "Parse opus header didn't fail for invalid input";
    } else {
        ASSERT_TRUE(status) << "ParseOpusHeader failed";

        ASSERT_LE(header.num_coupled, header.num_streams)
                << "No of coupled streams are greater than no of streams";

        int32_t channels = get<1>(params);
        ASSERT_EQ(header.channels, channels) << "Parser returned invalid channel count";

        if (header.channel_mapping) {
            uint8_t mappedChannelNo;
            for (int32_t channelNumber = 0; channelNumber < channels; channelNumber++) {
                mappedChannelNo = *(reinterpret_cast<uint8_t *>(opusHeadBuf) +
                                    kOpusHeaderStreamMapOffset + channelNumber);
                ASSERT_LT(mappedChannelNo, channels)
                        << "Channel Mapping is greater than channel count.";
            }
        }
    }
}

INSTANTIATE_TEST_SUITE_P(OpusHeaderTestAll, OpusHeaderWriteTest,
                         ::testing::Values(make_pair(1, 312), make_pair(2, 312), make_pair(5, 312),
                                           make_pair(6, 312), make_pair(1, 0), make_pair(2, 0),
                                           make_pair(5, 0), make_pair(6, 0), make_pair(1, 624),
                                           make_pair(2, 624), make_pair(5, 624),
                                           make_pair(6, 624)));

INSTANTIATE_TEST_SUITE_P(
        OpusHeaderTestAll, OpusHeaderParseTest,
        ::testing::Values(make_tuple("2ch_valid_size83B.opus", 2, true),
                          make_tuple("3ch_valid_size88B.opus", 3, true),
                          make_tuple("5ch_valid.opus", 5, true),
                          make_tuple("6ch_valid.opus", 6, true),
                          make_tuple("1ch_valid.opus", 1, true),
                          make_tuple("2ch_valid.opus", 2, true),
                          make_tuple("3ch_invalid_size.opus", 3, false),
                          make_tuple("3ch_invalid_streams.opus", 3, false),
                          make_tuple("5ch_invalid_channelmapping.opus", 5, false),
                          make_tuple("5ch_invalid_coupledstreams.opus", 5, false),
                          make_tuple("6ch_invalid_channelmapping.opus", 6, false),
                          make_tuple("9ch_invalid_channels.opus", 9, false),
                          make_tuple("2ch_invalid_header.opus", 2, false),
                          make_tuple("2ch_invalid_headerlength_16.opus", 2, false),
                          make_tuple("2ch_invalid_headerlength_256.opus", 2, false),
                          make_tuple("2ch_invalid_size.opus", 2, false),
                          make_tuple("3ch_invalid_channelmapping_0.opus", 3, false),
                          make_tuple("3ch_invalid_coupledstreams.opus", 3, false),
                          make_tuple("3ch_invalid_headerlength.opus", 3, false)));

int main(int argc, char **argv) {
    gEnv = new OpusHeaderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Opus Header Test Result = %d\n", status);
    }
    return status;
}
