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
#define LOG_TAG "WriterTest"
#include <utils/Log.h>

#include <fstream>
#include <iostream>

#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>

#include <media/mediarecorder.h>

#include <media/stagefright/AACWriter.h>
#include <media/stagefright/AMRWriter.h>
#include <media/stagefright/MPEG2TSWriter.h>
#include <media/stagefright/MPEG4Writer.h>
#include <media/stagefright/OggWriter.h>
#include <webm/WebmWriter.h>

#include "WriterTestEnvironment.h"
#include "WriterUtility.h"

#define OUTPUT_FILE_NAME "/data/local/tmp/writer.out"

static WriterTestEnvironment *gEnv = nullptr;

struct configFormat {
    char mime[128];
    int32_t width;
    int32_t height;
    int32_t sampleRate;
    int32_t channelCount;
};

class WriterTest : public ::testing::TestWithParam<pair<string, int32_t>> {
  public:
    virtual void SetUp() override {
        mNumCsds = 0;
        mInputFrameId = 0;
        mWriterName = unknown_comp;
        mDisableTest = false;

        std::map<std::string, standardWriters> mapWriter = {
                {"ogg", OGG},     {"aac", AAC},      {"aac_adts", AAC_ADTS}, {"webm", WEBM},
                {"mpeg4", MPEG4}, {"amrnb", AMR_NB}, {"amrwb", AMR_WB},      {"mpeg2Ts", MPEG2TS}};
        // Find the component type
        string writerFormat = GetParam().first;
        if (mapWriter.find(writerFormat) != mapWriter.end()) {
            mWriterName = mapWriter[writerFormat];
        }
        if (mWriterName == standardWriters::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. No specific writer mentioned\n";
            mDisableTest = true;
        }
    }

    virtual void TearDown() override {
        mWriter.clear();
        mFileMeta.clear();
        mBufferInfo.clear();
        if (mInputStream) mInputStream.close();
    }

    void getInputBufferInfo(string inputFileName, string inputInfo);

    int32_t createWriter(int32_t fd);

    int32_t addWriterSource(bool isAudio, configFormat params);

    enum standardWriters {
        OGG,
        AAC,
        AAC_ADTS,
        WEBM,
        MPEG4,
        AMR_NB,
        AMR_WB,
        MPEG2TS,
        unknown_comp,
    };

    standardWriters mWriterName;
    sp<MediaWriter> mWriter;
    sp<MetaData> mFileMeta;
    sp<MediaAdapter> mCurrentTrack;

    bool mDisableTest;
    int32_t mNumCsds;
    int32_t mInputFrameId;
    ifstream mInputStream;
    vector<BufferInfo> mBufferInfo;
};

void WriterTest::getInputBufferInfo(string inputFileName, string inputInfo) {
    std::ifstream eleInfo;
    eleInfo.open(inputInfo.c_str());
    CHECK_EQ(eleInfo.is_open(), true);
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    int64_t timestamp = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) break;
        eleInfo >> flags;
        eleInfo >> timestamp;
        mBufferInfo.push_back({bytesCount, flags, timestamp});
        if (flags == CODEC_CONFIG_FLAG) mNumCsds++;
    }
    eleInfo.close();
    mInputStream.open(inputFileName.c_str(), std::ifstream::binary);
    CHECK_EQ(mInputStream.is_open(), true);
}

int32_t WriterTest::createWriter(int32_t fd) {
    mFileMeta = new MetaData;
    switch (mWriterName) {
        case OGG:
            mWriter = new OggWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_OGG);
            break;
        case AAC:
            mWriter = new AACWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADIF);
            break;
        case AAC_ADTS:
            mWriter = new AACWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AAC_ADTS);
            break;
        case WEBM:
            mWriter = new WebmWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_WEBM);
            break;
        case MPEG4:
            mWriter = new MPEG4Writer(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG_4);
            break;
        case AMR_NB:
            mWriter = new AMRWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_NB);
            break;
        case AMR_WB:
            mWriter = new AMRWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_AMR_WB);
            break;
        case MPEG2TS:
            mWriter = new MPEG2TSWriter(fd);
            mFileMeta->setInt32(kKeyFileType, output_format::OUTPUT_FORMAT_MPEG2TS);
            break;
        default:
            return -1;
    }
    if (mWriter == nullptr) return -1;
    mFileMeta->setInt32(kKeyRealTimeRecording, false);
    return 0;
}

int32_t WriterTest::addWriterSource(bool isAudio, configFormat params) {
    if (mInputFrameId) return -1;
    sp<AMessage> format = new AMessage;
    if (mInputStream.is_open()) {
        format->setString("mime", params.mime);
        if (isAudio) {
            format->setInt32("channel-count", params.channelCount);
            format->setInt32("sample-rate", params.sampleRate);
        } else {
            format->setInt32("width", params.width);
            format->setInt32("height", params.height);
        }

        int32_t status =
                writeHeaderBuffers(mInputStream, mBufferInfo, mInputFrameId, format, mNumCsds);
        if (status != 0) return -1;
    }
    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);
    mCurrentTrack = new MediaAdapter(trackMeta);
    status_t result = mWriter->addSource(mCurrentTrack);
    return result;
}

void getFileDetails(string &inputFilePath, string &info, configFormat &params, bool &isAudio,
                    int32_t streamIndex = 0) {
    if (streamIndex > sizeof(kInputData) / sizeof(kInputData[0])) {
        return;
    }
    inputFilePath += kInputData[streamIndex].inputFile;
    info += kInputData[streamIndex].info;
    strcpy(params.mime, kInputData[streamIndex].mime);
    isAudio = kInputData[streamIndex].isAudio;
    if (isAudio) {
        params.sampleRate = kInputData[streamIndex].firstParam;
        params.channelCount = kInputData[streamIndex].secondParam;
    } else {
        params.width = kInputData[streamIndex].firstParam;
        params.height = kInputData[streamIndex].secondParam;
    }
    return;
}

TEST_P(WriterTest, CreateWriterTest) {
    if (mDisableTest) return;
    ALOGV("Tests the creation of writers");

    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) return;

    // Creating writer within a test scope. Destructor should be called when the test ends
    int32_t status = createWriter(fd);
    if (status) {
        cout << "Failed to create writer for output format:" << GetParam().first << "\n";
        ASSERT_TRUE(false);
    }
}

TEST_P(WriterTest, WriteTest) {
    if (mDisableTest) return;
    ALOGV("Checks if for a given input, a valid muxed file has been created or not");

    string writerFormat = GetParam().first;
    string outputFile = OUTPUT_FILE_NAME;
    int32_t fd =
            open(outputFile.c_str(), O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) return;
    int32_t status = createWriter(fd);
    if (status) {
        cout << "Failed to create writer for output format:" << writerFormat << "\n";
        ASSERT_TRUE(false);
    }
    string inputFile = gEnv->getRes();
    string inputInfo = gEnv->getRes();
    configFormat param;
    bool isAudio;
    int32_t inputFileIdx = GetParam().second;
    getFileDetails(inputFile, inputInfo, param, isAudio, inputFileIdx);
    if (!inputFile.compare(gEnv->getRes())) {
        ALOGV("No input file specified");
        return;
    }
    getInputBufferInfo(inputFile, inputInfo);
    status = addWriterSource(isAudio, param);
    if (status) {
        cout << "Failed to add source for " << writerFormat << "Writer \n";
        ASSERT_TRUE(false);
    }
    CHECK_EQ((status_t)OK, mWriter->start(mFileMeta.get()));
    status = sendBuffersToWriter(mInputStream, mBufferInfo, mInputFrameId, mCurrentTrack,
                                  0 /*offset*/, mBufferInfo.size());
    mCurrentTrack->stop();
    if (status) {
        cout << writerFormat << " writer failed while writing to a file \n";
        mWriter->stop();
        ASSERT_TRUE(false);
    }
    CHECK_EQ((status_t)OK, mWriter->stop());
    close(fd);
}

INSTANTIATE_TEST_SUITE_P(WriterTestAll, WriterTest,
                         ::testing::Values(make_pair("ogg", 0), make_pair("webm", 0),
                                           make_pair("aac", 1), make_pair("mpeg4", 1),
                                           make_pair("webm", 3), make_pair("webm", 4),
                                           make_pair("mpeg4", 5), make_pair("mpeg4", 6),
                                           make_pair("amrnb", 7), make_pair("amrwb", 8)));

int main(int argc, char **argv) {
    gEnv = new WriterTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
