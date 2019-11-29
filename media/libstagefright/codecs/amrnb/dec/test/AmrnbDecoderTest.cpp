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
#define LOG_TAG "AmrnbDecoderTest"

#include <utils/Log.h>

#include <audio_utils/sndfile.h>
#include <stdio.h>

#include "gsmamr_dec.h"

#include "AmrnbDecTestEnvironment.h"

// Constants for AMR-NB
constexpr int32_t kInputBufferSize = 64;
constexpr int32_t kSamplesPerFrame = L_FRAME;
constexpr int32_t kBitsPerSample = 16;
constexpr int32_t kSampleRate = 8000;
constexpr int32_t kChannels = 1;
const uint32_t kFrameSizes[] = {12, 13, 15, 17, 19, 20, 26, 31};

constexpr int32_t kNumFrameReset = 150;

static AmrnbDecTestEnvironment *gEnv = nullptr;

class AmrnbDecoderTest : public ::testing::TestWithParam<string> {
  public:
    virtual void SetUp() override {
        mDisableTest = false;

        mInputBuf = static_cast<uint8_t *>(malloc(kInputBufferSize));
        if (!mInputBuf) {
            cout << "[   WARN   ] Test Skipped. Unable to allocate input buffer\n";
            mDisableTest = true;
        }

        int32_t outputBufferSize = kSamplesPerFrame * kBitsPerSample / 8;
        mOutputBuf = static_cast<int16_t *>(malloc(outputBufferSize));
        if (!mOutputBuf) {
            cout << "[   WARN   ] Test Skipped. Unable to allocate output buffer\n";
            mDisableTest = true;
        }
    }
    virtual void TearDown() override {
        if (mFpInput) {
            fclose(mFpInput);
        }
        if (mInputBuf) {
            free(mInputBuf);
        }
        if (mOutputBuf) {
            free(mOutputBuf);
        }
    }

    bool mDisableTest;
    uint8_t *mInputBuf;
    int16_t *mOutputBuf;
    FILE *mFpInput;

    SNDFILE *openOutputFile(SF_INFO *sfInfo, string fileName);
    int32_t DecodeFrames(void *amrHandle, SNDFILE *handle, int32_t frameCount = INT32_MAX);
};

SNDFILE *AmrnbDecoderTest::openOutputFile(SF_INFO *sfInfo, string fileName) {
    memset(sfInfo, 0, sizeof(SF_INFO));
    sfInfo->channels = kChannels;
    sfInfo->format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfInfo->samplerate = kSampleRate;
    string outputFile = gEnv->getRes() + fileName;
    SNDFILE *handle = sf_open(outputFile.c_str(), SFM_WRITE, sfInfo);
    return handle;
}

int32_t AmrnbDecoderTest::DecodeFrames(void *amrHandle, SNDFILE *handle, int32_t frameCount) {
    while (frameCount > 0) {
        uint8_t mode;
        int bytesRead = fread(&mode, 1, 1, mFpInput);
        if (bytesRead != 1) break;

        // Find frame type
        Frame_Type_3GPP frameType = (Frame_Type_3GPP)((mode >> 3) & 0x0f);
        if (frameType >= AMR_SID) {
            ALOGE("Illegal frame type");
            return -1;
        }

        int32_t frameSize = kFrameSizes[frameType];
        bytesRead = fread(mInputBuf, 1, frameSize, mFpInput);
        if (bytesRead != frameSize) break;

        int32_t bytesDecoded = AMRDecode(amrHandle, frameType, (uint8_t *)mInputBuf,
                                          (int16_t *)mOutputBuf, MIME_IETF);
        if (bytesDecoded == -1) {
            return -1;
        }

        sf_writef_short(handle, (int16_t *)mOutputBuf, kSamplesPerFrame);
        frameCount--;
    }
    return 0;
}

TEST_F(AmrnbDecoderTest, CreateAmrnbDecoderTest) {
    void *amrHandle;
    int status = GSMInitDecode(&amrHandle, (Word8 *)"AMRNBDecoder");
    ASSERT_EQ(status, 0) << "Error creating AMR-NB decoder";
    GSMDecodeFrameExit(&amrHandle);
    ASSERT_EQ(amrHandle, nullptr) << "Error deleting AMR-NB decoder";
}

TEST_P(AmrnbDecoderTest, DecodeTest) {
    if (mDisableTest) return;

    string inputFile = gEnv->getRes() + GetParam();
    mFpInput = fopen(inputFile.c_str(), "rb");
    if (mFpInput == nullptr) {
        cout << "[   WARN   ] Test Skipped. Could not open %s\n" << inputFile;
        return;
    }

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *handle = openOutputFile(&sfInfo, "amrnbDecode.out");
    if (handle == nullptr) {
        cout << "[   WARN   ] Test Skipped. Unable to open output file for writing decoded "
                "output\n";
        return;
    }

    void *amrHandle;
    int status = GSMInitDecode(&amrHandle, (Word8 *)"AMRNBDecoder");
    ASSERT_EQ(status, 0) << "Error creating AMR-NB decoder";

    // Decode
    int32_t decoderErr = DecodeFrames(amrHandle, handle);
    ASSERT_EQ(decoderErr, 0) << "DecodeFrames returned error";

    sf_close(handle);
    GSMDecodeFrameExit(&amrHandle);
    ASSERT_EQ(amrHandle, nullptr) << "Error deleting AMR-NB decoder";
}

TEST_P(AmrnbDecoderTest, ResetDecodeTest) {
    if (mDisableTest) return;

    string inputFile = gEnv->getRes() + GetParam();
    mFpInput = fopen(inputFile.c_str(), "rb");
    if (mFpInput == nullptr) {
        cout << "[   WARN   ] Test Skipped. Could not open %s\n" << inputFile;
        return;
    }

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *handle = openOutputFile(&sfInfo, "amrnbDecodeReset.out");
    if (handle == nullptr) {
        cout << "[   WARN   ] Test Skipped. Unable to open output file for writing decoded "
                "output\n";
        return;
    }

    void *amrHandle;
    int status = GSMInitDecode(&amrHandle, (Word8 *)"AMRNBDecoder");
    ASSERT_EQ(status, 0) << "Error creating AMR-NB decoder";

    // Decode kNumFrameReset first
    int32_t decoderErr = DecodeFrames(amrHandle, handle, kNumFrameReset);
    ASSERT_EQ(decoderErr, 0) << "DecodeFrames returned error";

    status = Speech_Decode_Frame_reset(amrHandle);
    ASSERT_EQ(status, 0) << "Error resting AMR-NB decoder";

    // Start decoding again
    decoderErr = DecodeFrames(amrHandle, handle);
    ASSERT_EQ(decoderErr, 0) << "DecodeFrames returned error";

    sf_close(handle);
    GSMDecodeFrameExit(&amrHandle);
    ASSERT_EQ(amrHandle, nullptr) << "Error deleting AMR-NB decoder";
}

INSTANTIATE_TEST_SUITE_P(AmrnbDecoderTestAll, AmrnbDecoderTest,
                         ::testing::Values(("bbb_8000hz_1ch_8kbps_amrnb_30sec.amrnb"),
                                           ("sine_amrnb_1ch_12kbps_8000hz.amrnb")));

int main(int argc, char **argv) {
    gEnv = new AmrnbDecTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
