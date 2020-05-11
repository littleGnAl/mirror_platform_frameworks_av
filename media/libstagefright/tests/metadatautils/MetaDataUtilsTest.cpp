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
#define LOG_TAG "MetaDataUtilsTest"
#include <utils/Log.h>

#include <fstream>

#include <ESDS.h>
#include <media/NdkMediaFormat.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataBase.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/stagefright/foundation/ABitReader.h>

#include "MetaDataUtilsTestEnvironment.h"

constexpr uint8_t kSpsMask = 0x1f;
constexpr uint8_t kSpsStartCode = 0x07;
constexpr uint8_t kAdtsCsdSize = 7;
constexpr int32_t kSamplingFreq[] = {96000, 88200, 64000, 48000, 44100, 32000,
                                     24000, 22050, 16000, 12000, 11025, 8000};

static MetaDataUtilsTestEnvironment *gEnv = nullptr;

using namespace android;

class MetaDataUtils {
  public:
    bool SetUpMetaDataUtils(string fileName, string infoFileName) {
        string inputFile = gEnv->getRes() + fileName;
        mInputFileStream.open(inputFile, ifstream::in);
        if (!mInputFileStream.is_open()) {
            ALOGE("Failed to open data file: %s\n", inputFile.c_str());
            return false;
        }

        string infoFile = gEnv->getRes() + infoFileName;
        mInfoFileStream.open(infoFile, ifstream::in);
        if (!mInfoFileStream.is_open()) {
            ALOGE("Failed to open info file: %s\n", infoFile.c_str());
            return false;
        }
        return true;
    }

    ~MetaDataUtils() {
        if (mInputFileStream.is_open()) mInputFileStream.close();
        if (mInfoFileStream.is_open()) mInfoFileStream.close();
    }

    ifstream mInputFileStream;
    ifstream mInfoFileStream;
};

class AvcCSDTest
    : public MetaDataUtils,
      public ::testing::TestWithParam<tuple<string /*fileName*/, string /*infoFileName*/,
                                            size_t /*avcWidth*/, size_t /*avcHeight*/>> {
  public:
    virtual void SetUp() override {
        tuple<string, string, size_t, size_t> params = GetParam();
        string fileName = get<0>(params);
        string infoFileName = get<1>(params);
        bool status = MetaDataUtils::SetUpMetaDataUtils(fileName, infoFileName);
        ASSERT_TRUE(status) << "Failed to open files";

        mFrameWidth = get<2>(params);
        mFrameHeight = get<3>(params);
    }

    size_t mFrameWidth;
    size_t mFrameHeight;
};

class AacCSDTest
    : public ::testing::TestWithParam<tuple<uint32_t /*profile*/, uint32_t /*samplingFreqIndex*/,
                                            uint32_t /*channelConfig*/>> {
  public:
    virtual void SetUp() override {
        tuple<uint32_t, uint32_t, uint32_t> params = GetParam();
        mAacProfile = get<0>(params);
        mAacSamplingFreqIndex = get<1>(params);
        mAacChannelConfig = get<2>(params);
    }

    uint32_t mAacProfile;
    uint32_t mAacSamplingFreqIndex;
    uint32_t mAacChannelConfig;
};

class AacADTSTest
    : public ::testing::TestWithParam<
              tuple<string /*adtsFile*/, uint32_t /*channelCount*/, uint32_t /*sampleRate*/>> {};

class VorbisTest : public MetaDataUtils,
                   public ::testing::TestWithParam<pair<string /*fileName*/, string /*infoFile*/>> {
  public:
    virtual void SetUp() override {
        string inputMediaFile = GetParam().first;
        string inputInfoFile = GetParam().second;
        bool status = MetaDataUtils::SetUpMetaDataUtils(inputMediaFile, inputInfoFile);
        ASSERT_TRUE(status) << "Failed to open files";
    }
};

TEST_P(AvcCSDTest, AvcCSDValidationTest) {
    int32_t avcWidth = -1;
    int32_t avcHeight = -1;
    int32_t accessUnitLength = 0;
    string line;
    string type;
    size_t chunkLength;
    while (getline(mInfoFileStream, line)) {
        istringstream stringLine(line);
        stringLine >> type >> chunkLength;
        ASSERT_GT(chunkLength, 0) << "Length of the data chunk must be greater than zero";

        if (type.compare("SPS") && type.compare("PPS")) continue;

        accessUnitLength += chunkLength;

        if (!type.compare("SPS")) {
            const uint8_t *data = new uint8_t[chunkLength];
            ASSERT_NE(data, nullptr) << "Failed to create a data buffer of size: " << chunkLength;

            mInputFileStream.read((char *)data, chunkLength);
            ASSERT_EQ(mInputFileStream.gcount(), chunkLength)
                    << "Failed to read complete file, bytes read: " << mInputFileStream.gcount();

            // A valid startcode consists of at least two 0x00 bytes followed by 0x01.
            int32_t offset = 0;
            for (; offset + 2 < chunkLength; ++offset) {
                if (data[offset + 2] == 0x01 && data[offset + 1] == 0x00 && data[offset] == 0x00) {
                    break;
                }
            }
            offset += 3;
            ASSERT_LE(offset, chunkLength) << "NAL unit offset must not exceed the chunk length";

            uint8_t *nalUnit = (uint8_t *)(data + offset);
            size_t nalUnitLength = chunkLength - offset;

            // Check if it's an SPS
            ASSERT_TRUE(nalUnitLength > 0 && (nalUnit[0] & kSpsMask) == kSpsStartCode)
                    << "Failed to get SPS";

            ASSERT_GE(nalUnitLength, 4) << "SPS size must be greater than or equal to 4";

            delete[] data;
        }
    }
    const uint8_t *accessUnitData = new uint8_t[accessUnitLength];
    ASSERT_NE(accessUnitData, nullptr) << "Failed to create a buffer of size: " << accessUnitLength;

    mInputFileStream.seekg(0, ios::beg);
    mInputFileStream.read((char *)accessUnitData, accessUnitLength);
    ASSERT_EQ(mInputFileStream.gcount(), accessUnitLength)
            << "Failed to read complete file, bytes read: " << mInputFileStream.gcount();

    AMediaFormat *csdData = AMediaFormat_new();
    ASSERT_NE(csdData, nullptr) << "Failed to create AMedia format";

    bool status = MakeAVCCodecSpecificData(csdData, accessUnitData, accessUnitLength);
    ASSERT_TRUE(status) << "Failed to make AVC CSD from AMediaFormat";

    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_WIDTH, &avcWidth);
    ASSERT_TRUE(status) << "Failed to get avc width";

    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_HEIGHT, &avcHeight);
    ASSERT_TRUE(status) << "Failed to get avc height";

    const char *mimeType;
    status = AMediaFormat_getString(csdData, AMEDIAFORMAT_KEY_MIME, &mimeType);
    ASSERT_TRUE(status) << "Failed to get the mime type";

    ASSERT_EQ(avcWidth, mFrameWidth);

    ASSERT_EQ(avcHeight, mFrameHeight);

    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_VIDEO_AVC);

    int32_t width = -1;
    int32_t height = -1;
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create MetaData Base";

    status = MakeAVCCodecSpecificData(*metaData, accessUnitData, accessUnitLength);
    ASSERT_TRUE(status) << "Failed to make AVC CSD from MetaDataBase";

    status = metaData->findInt32(kKeyWidth, &width);
    ASSERT_TRUE(status) << "Failed to find the width";

    ASSERT_EQ(avcWidth, width) << "AVC width in AMediaFomat and MetaDataBase do not match";

    status = metaData->findInt32(kKeyHeight, &height);
    ASSERT_TRUE(status) << "Failed to find the height";

    ASSERT_EQ(avcHeight, height) << "AVC height in AMediaFomat and MetaDataBase do not match";

    void *csdAMediaFormatBuffer = nullptr;
    size_t csdAMediaFormatSize;
    status = AMediaFormat_getBuffer(csdData, AMEDIAFORMAT_KEY_CSD_AVC, &csdAMediaFormatBuffer,
                                    &csdAMediaFormatSize);
    ASSERT_TRUE(status) << "Failed to get the CSD from AMediaFormat";

    ASSERT_NE(csdAMediaFormatBuffer, nullptr) << "Invalid CSD from AMediaFormat";

    const void *csdMetaDataBaseBuffer = nullptr;
    size_t csdMetaDataBaseSize = 0;
    uint32_t mediaType;
    status = metaData->findData(kKeyAVCC, &mediaType, &csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_TRUE(status) << "Failed to get the CSD from MetaDataBase";
    ASSERT_NE(csdMetaDataBaseBuffer, nullptr) << "Invalid CSD from MetaDataBase";

    int32_t result = memcmp(csdAMediaFormatBuffer, csdMetaDataBaseBuffer, csdAMediaFormatSize);
    ASSERT_EQ(result, 0) << "CSD from AMediaFormat and MetaDataBase do not match";

    delete[] accessUnitData;
    delete metaData;
    AMediaFormat_delete(csdData);
}

TEST_P(AacCSDTest, AacCSDValidationTest) {
    int32_t channelCount = -1;
    int32_t sampleRate = -1;

    AMediaFormat *csdData = AMediaFormat_new();
    ASSERT_NE(csdData, nullptr) << "Failed to create AMedia format";

    bool status = MakeAACCodecSpecificData(csdData, mAacProfile, mAacSamplingFreqIndex,
                                           mAacChannelConfig);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from AMediaFormat";

    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate);
    ASSERT_TRUE(status) << "Failed to get sample rate";

    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &channelCount);
    ASSERT_TRUE(status) << "Failed to get channel count";

    const char *mimeType;
    status = AMediaFormat_getString(csdData, AMEDIAFORMAT_KEY_MIME, &mimeType);
    ASSERT_TRUE(status) << "Failed to get the mime type";

    ASSERT_EQ(kSamplingFreq[mAacSamplingFreqIndex], sampleRate);

    ASSERT_EQ(channelCount, mAacChannelConfig);

    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);

    int32_t numChannels = -1;
    int32_t sampleFreq = -1;

    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create MetaData Base";

    status = MakeAACCodecSpecificData(*metaData, mAacProfile, mAacSamplingFreqIndex,
                                      mAacChannelConfig);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from MetaDataBase";

    status = metaData->findInt32(kKeySampleRate, &sampleFreq);
    ASSERT_TRUE(status) << "Failed to get sampling rate";

    status = metaData->findInt32(kKeyChannelCount, &numChannels);
    ASSERT_TRUE(status) << "Failed to get channel count";

    status = metaData->findCString(kKeyMIMEType, &mimeType);
    ASSERT_TRUE(status) << "Failed to get mime type";

    ASSERT_EQ(sampleRate, sampleFreq);

    ASSERT_EQ(channelCount, numChannels);

    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);

    void *csdAMediaFormatBuffer = nullptr;
    size_t csdAMediaFormatSize;
    status = AMediaFormat_getBuffer(csdData, AMEDIAFORMAT_KEY_CSD_0, &csdAMediaFormatBuffer,
                                    &csdAMediaFormatSize);
    ASSERT_TRUE(status) << "Failed to get the AMediaFormat CSD";
    ASSERT_NE(csdAMediaFormatBuffer, nullptr) << "Invalid CSD found";

    const void *csdMetaDataBaseBuffer;
    size_t csdMetaDataBaseSize = 0;
    uint32_t mediaType;
    status = metaData->findData(kKeyESDS, &mediaType, &csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_TRUE(status) << "Failed to get the ESDS data from MetaDataBase";

    ESDS esds(csdMetaDataBaseBuffer, csdMetaDataBaseSize);
    status_t result = esds.getCodecSpecificInfo(&csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_EQ(result, (status_t)OK) << "Failed to get CSD from ESDS data";
    ASSERT_NE(csdMetaDataBaseBuffer, nullptr) << "Invalid CSD found";

    ASSERT_EQ(csdAMediaFormatSize, csdMetaDataBaseSize)
            << "CSD size do not match between AMediaFormat type and MetaDataBase type";

    int32_t memcmpResult =
            memcmp(csdAMediaFormatBuffer, csdMetaDataBaseBuffer, csdAMediaFormatSize);
    ASSERT_EQ(memcmpResult, 0) << "AMediaFormat and MetaDataBase CSDs do not match";

    AMediaFormat_delete(csdData);
    delete metaData;
}

TEST_P(AacADTSTest, AacADTSValidationTest) {
    tuple<string, uint32_t, uint32_t> params = GetParam();
    string fileName = gEnv->getRes() + get<0>(params);
    int32_t aacChannelCount = get<1>(params);
    int32_t aacSampleRate = get<2>(params);

    FILE *filePtr = fopen(fileName.c_str(), "r");
    ASSERT_NE(filePtr, nullptr) << "Failed to open file: " << fileName;

    const uint8_t *data = new uint8_t[kAdtsCsdSize];
    ASSERT_NE(data, nullptr) << "Failed to allocate a memory of size: " << kAdtsCsdSize;

    int32_t numBytes = fread((void *)data, sizeof(uint8_t), kAdtsCsdSize, filePtr);
    ASSERT_EQ(numBytes, kAdtsCsdSize) << "Failed to read complete file, bytes read: " << numBytes;

    fclose(filePtr);

    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    bool status = MakeAACCodecSpecificData(*metaData, data, kAdtsCsdSize);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from MetaDataBase";

    delete[] data;
    int32_t sampleRate = -1;
    int32_t channelCount = -1;

    status = metaData->findInt32(kKeySampleRate, &sampleRate);
    ASSERT_TRUE(status) << "Failed to get sampling rate";
    ASSERT_GT(sampleRate, 0) << "Sample rate must be greater than zero";

    status = metaData->findInt32(kKeyChannelCount, &channelCount);
    ASSERT_TRUE(status) << "Failed to get channel count";
    ASSERT_GT(channelCount, 0) << "Number of channels must be greater than zero";

    const char *mimeType;
    status = metaData->findCString(kKeyMIMEType, &mimeType);
    ASSERT_TRUE(status) << "Failed to get mime type";
    ASSERT_NE(mimeType, nullptr) << "Invalid mime type";

    delete metaData;
    ASSERT_EQ(aacSampleRate, sampleRate);

    ASSERT_EQ(aacChannelCount, channelCount);

    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);
}

TEST_P(VorbisTest, VorbisCommentTest) {
    string line;
    string tag;
    string key;
    string value;
    size_t commentLength;
    bool status;

    while (getline(mInfoFileStream, line)) {
        istringstream stringLine(line);
        stringLine >> tag >> key >> value >> commentLength;
        ASSERT_GT(commentLength, 0) << "Vorbis comment size must be greater than 0";

        string comment;
        string dataLine;

        getline(mInputFileStream, dataLine);
        istringstream dataStringLine(dataLine);
        dataStringLine >> comment;

        char *buffer = strndup(comment.c_str(), commentLength);
        ASSERT_NE(buffer, nullptr) << "Failed to allocate buffer of size: " << commentLength;

        AMediaFormat *fileMeta = AMediaFormat_new();
        ASSERT_NE(fileMeta, nullptr) << "Failed to create AMedia format";

        parseVorbisComment(fileMeta, buffer, commentLength);
        free(buffer);

        if (!tag.compare("ANDROID_HAPTIC")) {
            int32_t numChannelExpected = stoi(value);
            int32_t numChannelFound = -1;
            status = AMediaFormat_getInt32(fileMeta, key.c_str(), &numChannelFound);
            ASSERT_TRUE(status) << "Failed to get the channel count";
            ASSERT_EQ(numChannelExpected, numChannelFound);
        } else if (!tag.compare("ANDROID_LOOP")) {
            int32_t loopExpected = !value.compare("true");
            int32_t loopFound = -1;

            status = AMediaFormat_getInt32(fileMeta, "loop", &loopFound);
            ASSERT_TRUE(status) << "Failed to get the loop count";
            ASSERT_EQ(loopExpected, loopFound);
        } else {
            const char *tagValue;
            status = AMediaFormat_getString(fileMeta, key.c_str(), &tagValue);
            ASSERT_TRUE(status) << "Failed to get the tag value";
            ASSERT_STREQ(value.c_str(), tagValue);
        }
        AMediaFormat_delete(fileMeta);
    }
}

// Info File contains the type and length for each chunk/frame
INSTANTIATE_TEST_SUITE_P(
        MetaDataUtilsTestAll, AvcCSDTest,
        ::testing::Values(make_tuple("crowd_8x8p50f32_200kbps_bp.h264",
                                     "crowd_8x8p50f32_200kbps_bp.info", 8, 8),
                          make_tuple("crowd_1280x720p30f300_5000kbps_bp.h264",
                                     "crowd_1280x720p30f300_5000kbps_bp.info", 1280, 720),
                          make_tuple("crowd_1920x1080p50f300_12000kbps_bp.h264",
                                     "crowd_1920x1080p50f300_12000kbps_bp.info", 1920, 1080)));

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AacCSDTest,
                         ::testing::Values(make_tuple(AACObjectMain, 1, 1)));

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AacADTSTest,
                         ::testing::Values(make_tuple("loudsoftAAC_adts", 1, 44100)));

// TODO: Add test vector for vorbis thumbnail tag
// Info file contains TAG, Key, Value and size of the vorbis comment
INSTANTIATE_TEST_SUITE_P(
        MetaDataUtilsTestAll, VorbisTest,
        ::testing::Values(make_pair("vorbisComment_Sintel.dat", "vorbisComment_Sintel.info"),
                          make_pair("vorbisComment_Album.dat", "vorbisComment_Album.info"),
                          make_pair("vorbisComment_Loop.dat", "vorbisComment_Loop.info")));

int main(int argc, char **argv) {
    gEnv = new MetaDataUtilsTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
