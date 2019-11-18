/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "FlacDecoderTest"

#include <utils/Log.h>
#include <fstream>

#include "FLACDecoder.h"

#include "FlacDecoderTestEnvironment.h"

#define OUTPUT_FILE_NAME "/data/local/tmp/FlacDecoderOutput.raw"
#define CODEC_CONFIG_FLAG 32

constexpr uint32_t kMaxCount = 10;
constexpr int32_t kMaxBlockSize = 4096;

using namespace android;

struct FrameInfo {
    int32_t bytesCount;
    uint32_t flags;
    int64_t timestamp;
};

static FlacDecoderTestEnvironment *gEnv = nullptr;

class FLACDecoderTest : public ::testing::TestWithParam<tuple<string, string, bool>> {
  public:
    virtual void SetUp() override {
        mFLACDecoder = FLACDecoder::Create();
        if (!mFLACDecoder) {
            ALOGE("initDecoder: failed to create FLACDecoder");
            return;
        }
        mHasStreamInfo = false;
        mInputBufferCount = 0;
    }

    virtual void TearDown() override {
        if (mEleStream.is_open()) mEleStream.close();
        if (mFLACDecoder) delete mFLACDecoder;
        mFLACDecoder = nullptr;
    }

    void getInfo(string infoFileName, vector<FrameInfo> &Info);

    int32_t processFlacDecoder(vector<FrameInfo> Info, int32_t offset, int32_t range,
                               bool outputFloat, ofstream &ostrm);

    FLACDecoder *mFLACDecoder;
    FLAC__StreamMetadata_StreamInfo mStreamInfo;

    bool mHasStreamInfo;
    int32_t mInputBufferCount;
    ifstream mEleStream;
};

void FLACDecoderTest::getInfo(string infoFileName, vector<FrameInfo> &Info) {
    ifstream eleInfo;
    eleInfo.open(infoFileName);
    ASSERT_EQ(eleInfo.is_open(), true);
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    uint32_t timestamp = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        eleInfo >> timestamp;
        Info.push_back({bytesCount, flags, timestamp});
    }
    if (eleInfo.is_open()) eleInfo.close();
}

int32_t FLACDecoderTest::processFlacDecoder(vector<FrameInfo> Info, int32_t offset, int32_t range,
                                            bool outputFloat, ofstream &ostrm) {
    memset(&mStreamInfo, 0, sizeof(mStreamInfo));

    int32_t frameID = offset;
    if (range + offset > Info.size() || range < 0 || offset > Info.size() - 1 || offset < 0)
        return -1;

    while (1) {
        if (frameID == Info.size() || frameID == (offset + range)) break;
        int64_t flags = (Info)[frameID].flags;
        int32_t size = (Info)[frameID].bytesCount;
        char *data = (char *)malloc(size);
        if (data == nullptr) return -1;

        mEleStream.read(data, size);
        if (mEleStream.gcount() != size) return -1;

        if (flags == CODEC_CONFIG_FLAG && mInputBufferCount == 0) {
            status_t decoderErr = mFLACDecoder->parseMetadata((uint8_t *)data, size);
            if (decoderErr != OK && decoderErr != WOULD_BLOCK) {
                ALOGE("FLACDecoder parseMetaData returns error %d", decoderErr);
                return decoderErr;
            }
            if (decoderErr == WOULD_BLOCK) {
                ALOGV("process: parseMetadata is Blocking, Continue %d", decoderErr);
            } else {
                mStreamInfo = mFLACDecoder->getStreamInfo();
                if (mStreamInfo.sample_rate && mStreamInfo.max_blocksize && mStreamInfo.channels) {
                    mHasStreamInfo = true;
                }
                ALOGD("decoder configuration : %d Hz, %d channels, %d samples,"
                      " %d block size",
                      mStreamInfo.sample_rate, mStreamInfo.channels,
                      (int32_t)mStreamInfo.total_samples, mStreamInfo.max_blocksize);
            }
        } else {
            const size_t sampleSize = outputFloat ? sizeof(float) : sizeof(short);
            size_t outSize = mHasStreamInfo
                                     ? mStreamInfo.max_blocksize * mStreamInfo.channels * sampleSize
                                     : kMaxBlockSize * FLACDecoder::kMaxChannels * sampleSize;

            void *out_buf = malloc(outSize);
            if (out_buf == nullptr) return -1;
            status_t decoderErr = mFLACDecoder->decodeOneFrame((uint8_t *)data, size, out_buf,
                                                               &outSize, outputFloat);
            if (decoderErr != OK) {
                ALOGE("decodeOneFrame returns error %d", decoderErr);
                return decoderErr;
            }
            ostrm.write(reinterpret_cast<char *>(out_buf), outSize);
            free(out_buf);
        }
        mInputBufferCount++;
        frameID++;
        free(data);
    }
    ALOGV("frameID=%d", frameID);
    return 0;
}

TEST_F(FLACDecoderTest, CreateDeleteTest) {
    for (int32_t i = 0; i < kMaxCount; i++) {
        mFLACDecoder = FLACDecoder::Create();
        ASSERT_NE(mFLACDecoder, nullptr) << "FLACDecoder Creation Failed";
        if (mFLACDecoder) delete mFLACDecoder;
        mFLACDecoder = nullptr;
    }
}

TEST_P(FLACDecoderTest, FlushTest) {
    tuple<string /* InputFileName */, string /* InfoFileName */, bool /* outputfloat */> params =
            GetParam();

    string inputFileName = gEnv->getRes() + get<0>(params);
    string infoFileName = gEnv->getRes() + get<1>(params);
    bool outputFloat = get<2>(params);

    vector<FrameInfo> Info;
    getInfo(infoFileName, Info);

    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true);

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, std::ofstream::binary);
    ASSERT_EQ(ostrm.is_open(), true);

    int32_t status = processFlacDecoder(Info, 0, Info.size() / 3, outputFloat, ostrm);
    ASSERT_EQ(status, 0) << "Test Failed. Decode returned error = " << status << endl;
    mFLACDecoder->flush();
    mHasStreamInfo = false;
    status = processFlacDecoder(Info, (Info.size() / 3), Info.size() - (Info.size() / 3),
                                outputFloat, ostrm);
    ostrm.close();
    Info.clear();
    ASSERT_EQ(status, 0) << "Test Failed. Decode returned error = " << status << endl;
}

TEST_P(FLACDecoderTest, DecodeTest) {
    tuple<string /* InputFileName */, string /* InfoFileName */, bool /* outputfloat */> params =
            GetParam();

    string inputFileName = gEnv->getRes() + get<0>(params);
    string infoFileName = gEnv->getRes() + get<1>(params);
    bool outputFloat = get<2>(params);

    vector<FrameInfo> Info;
    getInfo(infoFileName, Info);

    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true);

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, std::ofstream::binary);
    ASSERT_EQ(ostrm.is_open(), true);

    int32_t status = processFlacDecoder(Info, 0, Info.size(), outputFloat, ostrm);
    ostrm.close();
    Info.clear();
    ASSERT_EQ(status, 0) << "Test Failed. Decode returned error = " << status << endl;
}

// TODO: Add remaining tests
INSTANTIATE_TEST_SUITE_P(
        FLACDecoderTestAll, FLACDecoderTest,
        ::testing::Values(make_tuple("bbb_flac_stereo_680kbps_48000hz.flac",
                                     "bbb_flac_stereo_680kbps_48000hz.info", true),
                          make_tuple("bbb_flac_stereo_680kbps_48000hz.flac",
                                     "bbb_flac_stereo_680kbps_48000hz.info", false),
                          make_tuple("bbb_flac_stereo_600kbps_44100hz.flac",
                                     "bbb_flac_stereo_600kbps_44100hz.info", true),
                          make_tuple("bbb_flac_stereo_600kbps_44100hz.flac",
                                     "bbb_flac_stereo_600kbps_44100hz.info", false)));

int main(int argc, char **argv) {
    gEnv = new FlacDecoderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Flac Decoder Test Result = %d\n", status);
    }
    return status;
}
