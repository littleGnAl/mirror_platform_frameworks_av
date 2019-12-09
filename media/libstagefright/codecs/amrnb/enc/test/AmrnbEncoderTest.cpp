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
#define LOG_TAG "AmrnbEncoderTest"

#include <audio_utils/sndfile.h>
#include <stdio.h>
#include <utils/Log.h>

#include "gsmamr_enc.h"

#include "AmrnbEncTestEnvironment.h"

#define OUTPUT_FILE "/data/local/tmp/amrnbEncode.out"

constexpr int32_t kInputBufferSize = L_FRAME * 2;  // 160 samples * 16-bit per sample.
constexpr int32_t kOutputBufferSize = 1024;
constexpr int32_t kNumFrameReset = 200;
constexpr int32_t kMaxCount = 10;
struct AmrNbEncState {
    void *encCtx;
    void *pidSyncCtx;
};

static AmrnbEncTestEnvironment *gEnv = nullptr;

class AmrnbEncoderTest : public ::testing::TestWithParam<string> {
  public:
    virtual void SetUp() override {
        mAmrEncHandle = nullptr;

        mInputBuf = static_cast<uint16_t *>(malloc(kInputBufferSize));
        ASSERT_NE(mInputBuf, nullptr) << "Unable to allocate input buffer";

        mOutputBuf = static_cast<uint8_t *>(malloc(kOutputBufferSize));
        ASSERT_NE(mOutputBuf, nullptr) << "Unable to allocate output buffer";
    }
    virtual void TearDown() override {
        if (mInputBuf) {
            free(mInputBuf);
            mInputBuf = nullptr;
        }
        if (mOutputBuf) {
            free(mOutputBuf);
            mOutputBuf = nullptr;
        }
    }

    uint16_t *mInputBuf;
    uint8_t *mOutputBuf;
    AmrNbEncState *mAmrEncHandle;
    int32_t EncodeFrames(int32_t mode, FILE *fpInput, FILE *mFpOutput,
                         int32_t frameCount = INT32_MAX);
};

int32_t AmrnbEncoderTest::EncodeFrames(int32_t mode, FILE *fpInput, FILE *mFpOutput,
                                       int32_t frameCount) {
    int frameNum = 0;
    while (frameNum < frameCount) {
        int32_t bytesRead = fread(mInputBuf, 1, kInputBufferSize, fpInput);
        if (bytesRead != kInputBufferSize && !feof(fpInput)) {
            ALOGE("Unable to read data from input file");
            return -1;
        } else if (feof(fpInput) && bytesRead == 0) {
            break;
        }
        Frame_Type_3GPP frame_type = (Frame_Type_3GPP)mode;
        int32_t bytesGenerated =
                AMREncode(mAmrEncHandle->encCtx, mAmrEncHandle->pidSyncCtx, (Mode)mode,
                          (Word16 *)mInputBuf, mOutputBuf, &frame_type, AMR_TX_WMF);
        frameNum++;
        if (bytesGenerated < 0) {
            ALOGE("Error in encoging the file: Invalid output format");
            return -1;
        }

        // Convert from WMF to RFC 3267 format.
        if (bytesGenerated > 0) {
            mOutputBuf[0] = ((mOutputBuf[0] << 3) | 4) & 0x7c;
        }
        fwrite(mOutputBuf, 1, bytesGenerated, mFpOutput);
    }
    return 0;
}

TEST_F(AmrnbEncoderTest, CreateAmrnbEncoderTest) {
    mAmrEncHandle = (AmrNbEncState *)malloc(sizeof(AmrNbEncState));
    ASSERT_NE(mAmrEncHandle, nullptr) << "Error in allocating memory to Codec handle";
    for (int i = 0; i < kMaxCount; i++) {
        int16_t status = AMREncodeInit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx, 0);
        ASSERT_EQ(status, 0) << "Error creating AMR-NB encoder";
        ALOGV("Successfully created encoder");
    }
    if (mAmrEncHandle) {
        AMREncodeExit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx);
        ASSERT_EQ(mAmrEncHandle->encCtx, nullptr) << "Error deleting AMR-NB encoder";
        ASSERT_EQ(mAmrEncHandle->pidSyncCtx, nullptr) << "Error deleting AMR-NB encoder";
        free(mAmrEncHandle);
        mAmrEncHandle = nullptr;
        ALOGV("Successfully deleted encoder");
    }
}

TEST_P(AmrnbEncoderTest, EncodeTest) {
    mAmrEncHandle = (AmrNbEncState *)malloc(sizeof(AmrNbEncState));
    ASSERT_NE(mAmrEncHandle, nullptr) << "Error in allocating memory to Codec handle";
    int16_t status = AMREncodeInit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx, 0);
    ASSERT_EQ(status, 0) << "Error creating AMR-NB encoder";

    int32_t mode;
    int32_t encodeErr;

    string inputFile = gEnv->getRes() + GetParam();
    FILE *fpInput = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(fpInput, nullptr) << "Error opening input file " << inputFile;

    for (mode = MR475; mode <= MR122; mode++) {
        fseek(fpInput, 0, SEEK_SET);

        FILE *fpOutput = fopen(OUTPUT_FILE, "wb");
        ASSERT_NE(fpOutput, nullptr) << "Error opening output file " << OUTPUT_FILE;
        // Write file header.
        fwrite("#!AMR\n", 1, 6, fpOutput);
        encodeErr = EncodeFrames(mode, fpInput, fpOutput);
        fclose(fpOutput);
        fpOutput = nullptr;
        ASSERT_EQ(encodeErr, 0) << "EncodeFrames returned error for Codec mode: " << mode;
    }
    fclose(fpInput);
    fpInput = nullptr;

    if (mAmrEncHandle) {
        AMREncodeExit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx);
        ASSERT_EQ(mAmrEncHandle->encCtx, nullptr) << "Error deleting AMR-NB encoder";
        ASSERT_EQ(mAmrEncHandle->pidSyncCtx, nullptr) << "Error deleting AMR-NB encoder";
        free(mAmrEncHandle);
        mAmrEncHandle = nullptr;
        ALOGV("Successfully deleted encoder");
    }
}

TEST_P(AmrnbEncoderTest, ResetEncoderTest) {
    mAmrEncHandle = (AmrNbEncState *)malloc(sizeof(AmrNbEncState));
    int16_t status = AMREncodeInit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx, 0);
    ASSERT_EQ(status, 0) << "Error creating AMR-NB encoder";

    int32_t mode;
    int32_t encodeErr;

    string inputFile = gEnv->getRes() + GetParam();
    FILE *fpInput = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(fpInput, nullptr) << "Error opening input file " << inputFile;

    for (mode = MR475; mode <= MR122; mode++) {
        fseek(fpInput, 0, SEEK_SET);

        FILE *fpOutput = fopen(OUTPUT_FILE, "wb");
        ASSERT_NE(fpOutput, nullptr) << "Error opening output file " << OUTPUT_FILE;

        // Write file header.
        fwrite("#!AMR\n", 1, 6, fpOutput);

        // Encode kNumFrameReset first
        encodeErr = EncodeFrames(mode, fpInput, fpOutput, kNumFrameReset);
        ASSERT_EQ(encodeErr, 0) << "EncodeFrames returned error for Codec mode: " << mode;

        int status = AMREncodeReset(mAmrEncHandle->encCtx, mAmrEncHandle->pidSyncCtx);
        ASSERT_EQ(status, 0) << "Error resting AMR-NB encoder";

        // Start encoding again
        encodeErr = EncodeFrames(mode, fpInput, fpOutput);
        ASSERT_EQ(encodeErr, 0) << "EncodeFrames returned error for Codec mode: " << mode;

        fclose(fpOutput);
        fpOutput = nullptr;
    }
    fclose(fpInput);
    fpInput = nullptr;

    if (mAmrEncHandle) {
        AMREncodeExit(&mAmrEncHandle->encCtx, &mAmrEncHandle->pidSyncCtx);
        ASSERT_EQ(mAmrEncHandle->encCtx, nullptr) << "Error deleting AMR-NB encoder";
        ASSERT_EQ(mAmrEncHandle->pidSyncCtx, nullptr) << "Error deleting AMR-NB encoder";
        free(mAmrEncHandle);
        mAmrEncHandle = nullptr;
        ALOGV("Successfully deleted encoder");
    }
}

INSTANTIATE_TEST_SUITE_P(AmrnbEncoderTestAll, AmrnbEncoderTest,
                         ::testing::Values(("bbb_raw_1ch_8khz_s16le.raw")));

int main(int argc, char **argv) {
    gEnv = new AmrnbEncTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
