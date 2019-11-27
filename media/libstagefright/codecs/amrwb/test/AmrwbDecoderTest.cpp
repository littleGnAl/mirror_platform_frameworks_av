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
#define LOG_TAG "AmrwbDecoderTest"

#include <utils/Log.h>

#include <audio_utils/sndfile.h>
#include <stdio.h>

#include "pvamrwbdecoder.h"
#include "pvamrwbdecoder_api.h"

#include "AmrwbDecTestEnvironment.h"

typedef enum ERROR_CODE { NO_DECODING_ERROR, DECODING_ERROR, ILLEGAL_FRAME_MODE } ERROR_CODE;

// Constants for AMR-WB.
constexpr int32_t kInputBufferSize = 64;
constexpr int32_t kSamplesPerFrame = 320;
constexpr int32_t kBitsPerSample = 16;
constexpr int32_t kSampleRate = 16000;
constexpr int32_t kChannels = 1;
constexpr int32_t kMaxSourceDataUnitSize = NBBITS_24k * sizeof(int16_t);
const uint32_t kFrameSizes[] = {17, 23, 32, 36, 40, 46, 50, 58, 60};
constexpr int32_t kNumFrameReset = 150;

constexpr int32_t kMaxCount = 10;

static AmrwbDecTestEnvironment *gEnv = nullptr;

class AmrwbDecoderTest : public ::testing::TestWithParam<string> {
  public:
    virtual void SetUp() override {
        mDisableTest = false;

        mInputBuf = static_cast<uint8_t *>(malloc(kInputBufferSize));
        if (!mInputBuf) {
            cout << "[   WARN   ] Test Skipped. Unable to allocate input buffer\n";
            mDisableTest = true;
        }

        mInputSampleBuf = (int16_t *)malloc(kMaxSourceDataUnitSize);
        if (!mInputSampleBuf) {
            cout << "[   WARN   ] Test Skipped. Unable to allocate input sample buffer\n";
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
        if (mInputSampleBuf) {
            free(mInputSampleBuf);
        }
        if (mOutputBuf) {
            free(mOutputBuf);
        }
    }

    bool mDisableTest;
    uint8_t *mInputBuf;
    int16_t *mInputSampleBuf;
    int16_t *mOutputBuf;
    FILE *mFpInput;

    ERROR_CODE DecodeFrames(int16_t *decoderCookie, void *decoderBuf, SNDFILE *handle,
                            int32_t frameCount = INT32_MAX);
    SNDFILE *openOutputFile(SF_INFO *sfInfo, string fileName);
};

SNDFILE *AmrwbDecoderTest::openOutputFile(SF_INFO *sfInfo, string fileName) {
    memset(sfInfo, 0, sizeof(SF_INFO));
    sfInfo->channels = kChannels;
    sfInfo->format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfInfo->samplerate = kSampleRate;
    string outputFile = gEnv->getRes() + fileName;
    SNDFILE *handle = sf_open(outputFile.c_str(), SFM_WRITE, sfInfo);
    return handle;
}

ERROR_CODE AmrwbDecoderTest::DecodeFrames(int16_t *decoderCookie, void *decoderBuf, SNDFILE *handle,
                                          int32_t frameCount) {
    while (frameCount > 0) {
        uint8_t modeByte;
        int bytesRead = fread(&modeByte, 1, 1, mFpInput);
        if (bytesRead != 1) break;

        int16 mode = ((modeByte >> 3) & 0x0f);
        // AMR-WB file format cannot have mode 10, 11, 12 and 13.
        if (mode > 9 && mode < 14) {
            return ILLEGAL_FRAME_MODE;
        }

        if (mode >= 9) {
            // Produce silence for comfort noise, speech lost and no data.
            int32_t outputBufferSize = kSamplesPerFrame * kBitsPerSample / 8;
            memset(mOutputBuf, 0, outputBufferSize);
        } else {
            // Read rest of the frame.
            int32_t frameSize = kFrameSizes[mode];
            bytesRead = fread(mInputBuf, 1, frameSize, mFpInput);
            if (bytesRead != frameSize) break;

            int16 frameMode = mode;
            int16 frameType;
            RX_State_wb rx_state;
            mime_unsorting(mInputBuf, mInputSampleBuf, &frameType, &frameMode, 1, &rx_state);

            int16_t numSamplesOutput;
            pvDecoder_AmrWb(frameMode, mInputSampleBuf, mOutputBuf, &numSamplesOutput, decoderBuf,
                            frameType, decoderCookie);
            if (numSamplesOutput != kSamplesPerFrame) {
                return DECODING_ERROR;
            }
            for (int i = 0; i < kSamplesPerFrame; ++i) {
                mOutputBuf[i] &= 0xfffC;
            }
        }
        sf_writef_short(handle, mOutputBuf, kSamplesPerFrame / kChannels);
    }
    return NO_DECODING_ERROR;
}

TEST_F(AmrwbDecoderTest, MultiCreateAmrwbDecoderTest) {
    if (mDisableTest) return;

    uint32_t memRequirements = pvDecoder_AmrWbMemRequirements();
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;

    // Create AMR-WB decoder instance.
    void *amrHandle;
    int16_t *decoderCookie;
    for (int i = 0; i < kMaxCount; i++) {
        pvDecoder_AmrWb_Init(&amrHandle, decoderBuf, &decoderCookie);
        ALOGV("Decoder created successfully");
    }
    if (decoderBuf) {
        free(decoderBuf);
    }
}

TEST_P(AmrwbDecoderTest, DecodeTest) {
    if (mDisableTest) return;

    uint32_t memRequirements = pvDecoder_AmrWbMemRequirements();
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;

    void *amrHandle;
    int16_t *decoderCookie;
    pvDecoder_AmrWb_Init(&amrHandle, decoderBuf, &decoderCookie);

    string inputFile = gEnv->getRes() + GetParam();
    mFpInput = fopen(inputFile.c_str(), "rb");
    if (mFpInput == nullptr) {
        cout << "[   WARN   ] Test Skipped. Could not open %s\n" << inputFile;
        return;
    }

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *handle = openOutputFile(&sfInfo, "amrwbDecode.out");
    if (handle == nullptr) {
        cout << "[   WARN   ] Test Skipped. Unable to open output file for writing decoded "
                "output\n";
        return;
    }
    ERROR_CODE decoderErr = DecodeFrames(decoderCookie, decoderBuf, handle);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "DecodeFrames returned error: " << decoderErr;

    sf_close(handle);
    if (decoderBuf) {
        free(decoderBuf);
    }
}

TEST_P(AmrwbDecoderTest, ResetDecoderTest) {
    if (mDisableTest) return;

    uint32_t memRequirements = pvDecoder_AmrWbMemRequirements();
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;

    void *amrHandle;
    int16_t *decoderCookie;
    pvDecoder_AmrWb_Init(&amrHandle, decoderBuf, &decoderCookie);

    string inputFile = gEnv->getRes() + GetParam();
    mFpInput = fopen(inputFile.c_str(), "rb");
    if (mFpInput == nullptr) {
        cout << "[   WARN   ] Test Skipped. Could not open %s\n" << inputFile;
        return;
    }

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *handle = openOutputFile(&sfInfo, "amrwbDecodeReset.out");
    if (handle == nullptr) {
        cout << "[   WARN   ] Test Skipped. Unable to open output file for writing decoded "
                "output\n";
        return;
    }
    // Decode 150 frames first
    ERROR_CODE decoderErr = DecodeFrames(decoderCookie, decoderBuf, handle, kNumFrameReset);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "DecodeFrames returned error: " << decoderErr;

    // Reset Decoder
    pvDecoder_AmrWb_Reset(decoderBuf, 1);

    // Start decoding again
    decoderErr = DecodeFrames(decoderCookie, decoderBuf, handle);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "DecodeFrames returned error: " << decoderErr;

    sf_close(handle);
    if (decoderBuf) {
        free(decoderBuf);
    }
}

INSTANTIATE_TEST_SUITE_P(AmrwbDecoderTestAll, AmrwbDecoderTest,
                         ::testing::Values(("bbb_amrwb_1ch_14kbps_16000hz.amrwb"),
                                           ("bbb_16000hz_1ch_9kbps_amrwb_30sec.amrwb")));

int main(int argc, char **argv) {
    gEnv = new AmrwbDecTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
