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
#define LOG_TAG "C2EncoderTest"

#include <fstream>
#include <iostream>
#include <limits>

#include "BenchmarkTestEnvironment.h"
#include "C2Encoder.h"
#include "Decoder.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class C2EncoderTest : public ::testing::TestWithParam<pair<string, string>> {
  public:
    C2EncoderTest() : mEncoder(nullptr), disableTest(false) { setupC2EncoderTest(); }

    void setupC2EncoderTest();

    vector<string> mCodecList;
    C2Encoder *mEncoder;
    bool disableTest;
};

void C2EncoderTest::setupC2EncoderTest() {
    mEncoder = new C2Encoder();
    if (!mEncoder) {
        cout << "[   WARN   ] Test Skipped. C2Encoder creation failed\n";
        disableTest = true;
        return;
    }
    int32_t status = mEncoder->setupCodec2();
    if (status != 0) {
        cout << "[   WARN   ] Test Skipped. Codec2 setup failed \n";
        disableTest = true;
        return;
    }
    mCodecList = mEncoder->getSupportedComponentList(true /* isEncoder*/);
    if (!mCodecList.size()) {
        cout << "[   WARN   ] Test Skipped. Codec2 client didn't recognise any component \n";
        disableTest = true;
        return;
    }
}

TEST_P(C2EncoderTest, Codec2Encode) {
    if (disableTest) return;

    ALOGV("Encodes the input using codec2 framework");
    string inputFile = gEnv->getRes() + GetParam().first;
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    if (!inputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }

    Decoder *decoder = new Decoder();
    Extractor *extractor = decoder->getExtractor();
    if (!extractor) {
        cout << "[   WARN   ] Test Skipped. Extractor creation failed \n";
        return;
    }

    // Read file properties
    fseek(inputFp, 0, SEEK_END);
    size_t fileSize = ftell(inputFp);
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);

    if (fileSize > kMaxBufferSize) {
        cout << "[   WARN   ] Test Skipped. Input file size is greater than the threshold memory "
                "dedicated to the test \n";
    }

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        cout << "[   WARN   ] Test Skipped. initExtractor failed\n";
        return;
    }
    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            cout << "[   WARN   ] Test Skipped. Track Format invalid \n";
            return;
        }

        uint8_t *inputBuffer = (uint8_t *)malloc(fileSize);
        if (!inputBuffer) {
            cout << "[   WARN   ] Test Skipped. Insufficient memory \n";
            return;
        }
        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > fileSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        string decName = "";
        string outputFileName = "decode.out";
        FILE *outFp = fopen(outputFileName.c_str(), "wb");
        if (outFp == nullptr) {
            cout << "[   WARN   ] Test Skipped. Unable to open output file" << outputFileName
                 << " for dumping decoder's output \n";
            return;
        }
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, decName, false /*asyncMode */, outFp);
        if (status != AMEDIA_OK) {
            cout << "[   WARN   ] Test Skipped. Decode returned error : " << status << "\n";
            return;
        }

        // Encode the given input stream for all C2 codecs supported by device
        AMediaFormat *format = extractor->getFormat();
        ifstream eleStream;
        eleStream.open(outputFileName.c_str(), ifstream::binary | ifstream::ate);
        ASSERT_EQ(eleStream.is_open(), true) << outputFileName.c_str() << " - file not found";
        size_t eleSize = eleStream.tellg();

        for (string codecName : mCodecList) {
            if (codecName.find(GetParam().second) != string::npos) {
                status = mEncoder->createCodec2Component(codecName, format);
                if (status != 0) {
                    cout << "[   WARN   ] Test Skipped. Create component failed for " << codecName << "\n";
                    continue;
                }

                // Send the inputs to C2 Encoder and wait till all buffers are returned.
                eleStream.seekg(0, ifstream::beg);
                mEncoder->encodeFrames(eleStream, eleSize);
                mEncoder->waitOnInputConsumption();
                if (!mEncoder->mEos) {
                    cout << "[   WARN   ] Test Failed. Didn't receive EOS \n";
                }
                mEncoder->deInitCodec();
                int64_t durationUs = extractor->getClipDuration();
                cout << "codec: " << codecName << endl;
                mEncoder->dumpStatistics(GetParam().first, durationUs);
                mEncoder->resetEncoder();
            }
        }

        // Destroy the decoder for the given input
        decoder->deInitCodec();
        decoder->resetDecoder();
        free(inputBuffer);
    }
    fclose(inputFp);
    extractor->deInitExtractor();
    delete decoder;
    delete mEncoder;
}

INSTANTIATE_TEST_SUITE_P(
        AudioEncoderTest, C2EncoderTest,
        ::testing::Values(
                make_pair("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "aac"),
                make_pair("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "amrnb"),
                make_pair("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "amrwb"),
                make_pair("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "flac"),
                make_pair("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "opus")));

INSTANTIATE_TEST_SUITE_P(
        VideoEncoderTest, C2EncoderTest,
        ::testing::Values(
                make_pair("crowd_1920x1080_25fps_4000kbps_vp9.webm", "vp9"),
                make_pair("crowd_1920x1080_25fps_4000kbps_vp8.webm", "vp8"),
                make_pair("crowd_176x144_25fps_6000kbps_mpeg4.mp4", "mpeg4"),
                make_pair("crowd_176x144_25fps_6000kbps_h263.3gp", "h263"),
                make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", "avc"),
                make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", "hevc")));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("C2 Encoder Test result = %d\n", status);
    }
    return status;
}