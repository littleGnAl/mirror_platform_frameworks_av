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
#define LOG_TAG "SonivoxTest"
#include <utils/Log.h>

#include <fstream>

#include <datasource/FileSource.h>

#include <media/MidiIoWrapper.h>
#include <media/NdkMediaFormat.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/foundation/ABitReader.h>

#include <libsonivox/eas.h>
#include <libsonivox/eas_reverb.h>

#include "SonivoxTestEnvironment.h"

#define OUTPUT_FILE "/data/local/tmp/output_midi.pcm"

using namespace android;

// number of Sonivox output buffers to aggregate into one MediaBuffer
static constexpr uint32_t kNumBuffersToCombine = 4;
static constexpr uint32_t kRandomSeekOffsetMs = 10;
static constexpr int kResumeWaitUs = 10 * 1000;

static SonivoxTestEnvironment *gEnv = nullptr;

class SonivoxTest : public ::testing::TestWithParam<tuple</*fileName*/ string,
                                                          /*audioPlayTimeMs*/ uint32_t,
                                                          /*totalChannels*/ uint32_t,
                                                          /*sampleRateHz*/ uint32_t>> {
  public:
    SonivoxTest()
        : mInputFp(nullptr),
          mDataSource(nullptr),
          mIoWrapper(nullptr),
          mEASDataHandle(nullptr),
          mEASStreamHandle(nullptr) {}

    ~SonivoxTest() {
        if (mInputFp) fclose(mInputFp);
        if (mDataSource) mDataSource.clear();
        if (mIoWrapper) delete mIoWrapper;
        if (gEnv->cleanUp()) remove(OUTPUT_FILE);
    }

    virtual void SetUp() override {
        tuple<string, uint32_t, uint32_t, uint32_t> params = GetParam();
        mInputMediaFile = gEnv->getRes() + get<0>(params);
        mAudioplayTimeMs = get<1>(params);
        mTotalAudioChannels = get<2>(params);
        mAudioSampleRate = get<3>(params);

        bool status = setDataSource(mInputMediaFile);
        ASSERT_TRUE(status) << "Failed to set data source for file: " << mInputMediaFile;

        mIoWrapper = new MidiIoWrapper(mDataSource->wrap());
        ASSERT_NE(mIoWrapper, nullptr) << "Failed to create a Midi IO Wrapper";

        EAS_RESULT result = EAS_Init(&mEASDataHandle);
        ASSERT_EQ(result, EAS_SUCCESS) << "Failed to initialize synthesizer library";

        ASSERT_NE(mEASDataHandle, nullptr) << "Failed to initialize EAS data handle";

        result = EAS_OpenFile(mEASDataHandle, mIoWrapper->getLocator(), &mEASStreamHandle);
        ASSERT_EQ(result, EAS_SUCCESS) << "Failed to open file";

        ASSERT_NE(mEASStreamHandle, nullptr) << "Failed to initialize EAS stream handle";

        result = EAS_Prepare(mEASDataHandle, mEASStreamHandle);
        ASSERT_EQ(result, EAS_SUCCESS) << "Failed to prepare EAS data and stream handles";
    }

    virtual void TearDown() {
        EAS_RESULT result;
        if (mEASDataHandle) {
            if (mEASStreamHandle) {
                result = EAS_CloseFile(mEASDataHandle, mEASStreamHandle);
                ASSERT_EQ(result, EAS_SUCCESS) << "Failed to close audio file/stream";
            }
            result = EAS_Shutdown(mEASDataHandle);
            ASSERT_EQ(result, EAS_SUCCESS)
                    << "Failed to deallocate the resources for synthesizer library";
        }
    }

    bool seekToPosition(EAS_I32);
    bool setDataSource(string);
    bool renderAudio(EAS_I32 bufferSize);

    string mInputMediaFile;
    uint32_t mAudioplayTimeMs;
    uint32_t mTotalAudioChannels;
    uint32_t mAudioSampleRate;

    FILE *mInputFp;
    sp<DataSource> mDataSource;
    MidiIoWrapper *mIoWrapper;
    EAS_DATA_HANDLE mEASDataHandle;
    EAS_HANDLE mEASStreamHandle;
};

bool SonivoxTest::setDataSource(string inputFileName) {
    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        ALOGE("Unable to open input file for reading");
        return false;
    }
    struct stat buf;
    uint32_t err = stat(inputFileName.c_str(), &buf);
    if (err != 0) {
        ALOGE("Failed to get information for file: %s", inputFileName.c_str());
        return false;
    }

    int32_t fd = fileno(mInputFp);
    if (fd < 0) {
        ALOGE("Failed to get the integer file descriptor");
        return false;
    }

    mDataSource = new FileSource(dup(fd), 0, buf.st_size);
    if (!mDataSource) return false;
    return true;
}

bool SonivoxTest::seekToPosition(EAS_I32 locationMs) {
    EAS_RESULT result = EAS_Locate(mEASDataHandle, mEASStreamHandle, locationMs, false);
    if (result != EAS_SUCCESS) return false;

    // position in milliseconds
    EAS_I32 positionMs;
    result = EAS_GetLocation(mEASDataHandle, mEASStreamHandle, &positionMs);
    if (result != EAS_SUCCESS) return false;

    if (positionMs != locationMs) return false;

    return true;
}

bool SonivoxTest::renderAudio(EAS_I32 bufferSize) {
    EAS_I32 count = -1;
    EAS_PCM *pcmBuffer = new EAS_PCM[bufferSize];

    EAS_PCM *pcm = pcmBuffer;
    EAS_RESULT result = EAS_Render(mEASDataHandle, pcm, bufferSize, &count);

    if (result != EAS_SUCCESS) {
        ALOGE("Failed to render audio");
        return false;
    }
    if (count < 0 || count != bufferSize) {
        ALOGE("Failed to write %ld bytes of data to buffer", bufferSize);
        return false;
    }

    delete[] pcmBuffer;
    return true;
}

TEST_P(SonivoxTest, MetaDataTest) {
    EAS_I32 playTimeMs;
    EAS_RESULT result = EAS_ParseMetaData(mEASDataHandle, mEASStreamHandle, &playTimeMs);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to parse meta data";

    ASSERT_EQ(playTimeMs, mAudioplayTimeMs)
            << "Invalid audio play time found for file: " << mInputMediaFile;

    EAS_I32 fileType;
    result = EAS_GetFileType(mEASDataHandle, mEASStreamHandle, &fileType);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get file type";

    ASSERT_NE(fileType, 0) << "Wrong file type for file: " << mInputMediaFile;

    const S_EAS_LIB_CONFIG *easConfig = EAS_Config();
    ASSERT_NE(easConfig, nullptr) << "Failed to configure the library";

    EAS_I32 totalChannels = easConfig->numChannels;
    ASSERT_EQ(totalChannels, mTotalAudioChannels)
            << "Expected: " << mTotalAudioChannels << " channels, Found: " << totalChannels;

    EAS_I32 sampleRate = easConfig->sampleRate;
    ASSERT_EQ(sampleRate, mAudioSampleRate)
            << "Expected: " << mAudioSampleRate << " sample rate, Found: " << sampleRate;
}

TEST_P(SonivoxTest, DecodeTest) {
    EAS_I32 playTimeMs;
    EAS_RESULT result = EAS_ParseMetaData(mEASDataHandle, mEASStreamHandle, &playTimeMs);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to parse meta data";

    EAS_I32 locationMs;
    /* EAS_ParseMetaData resets the parser to the starting of file */
    EAS_GetLocation(mEASDataHandle, mEASStreamHandle, &locationMs);
    ASSERT_EQ(locationMs, 0) << "Expected position: 0, found: " << locationMs;

    const S_EAS_LIB_CONFIG *easConfig = EAS_Config();
    ASSERT_NE(easConfig, nullptr) << "Failed to configure the library";

    // select reverb preset and enable
    result = EAS_SetParameter(mEASDataHandle, EAS_MODULE_REVERB, EAS_PARAM_REVERB_PRESET,
                              EAS_PARAM_REVERB_CHAMBER);
    ASSERT_EQ(result, EAS_SUCCESS)
            << "Failed to set reverberation preset parameter in reverb module";

    result =
            EAS_SetParameter(mEASDataHandle, EAS_MODULE_REVERB, EAS_PARAM_REVERB_BYPASS, EAS_FALSE);
    ASSERT_EQ(result, EAS_SUCCESS)
            << "Failed to set reverberation bypass parameter in reverb module";

    EAS_I32 bufferSize = sizeof(EAS_PCM) * easConfig->mixBufferSize * easConfig->numChannels *
                         kNumBuffersToCombine;
    EAS_I32 count;
    EAS_STATE state;

    FILE *filePtr = fopen(OUTPUT_FILE, "wb");
    ASSERT_NE(filePtr, nullptr) << "Failed to open file: " << OUTPUT_FILE;
    while (1) {
        EAS_PCM buffer[bufferSize];
        EAS_PCM *pcm = buffer;

        int32_t numBytesOutput = 0;
        result = EAS_State(mEASDataHandle, mEASStreamHandle, &state);
        ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get EAS State";

        ASSERT_NE(state, EAS_STATE_ERROR) << "Error state found";

        /* is playback complete */
        if (state == EAS_STATE_STOPPED) {
            ALOGE("Stop state reached\n");
            break;
        }

        result = EAS_GetLocation(mEASDataHandle, mEASStreamHandle, &locationMs);
        ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get the current location in ms";

        if (locationMs >= playTimeMs) {
            ALOGI("Reached the end of the file");
            ASSERT_NE(state, EAS_STATE_STOPPED)
                    << "Invalid state reached when rendering is complete";

            break;
        }

        for (uint32_t i = 0; i < kNumBuffersToCombine; i++) {
            result = EAS_Render(mEASDataHandle, pcm, easConfig->mixBufferSize, &count);
            ASSERT_EQ(result, EAS_SUCCESS) << "Failed to render the audio data";

            pcm += count * easConfig->numChannels;
            numBytesOutput += count * easConfig->numChannels * sizeof(EAS_PCM);
        }
        int32_t numBytes = fwrite(buffer, 1, numBytesOutput, filePtr);
        ASSERT_EQ(numBytes, numBytesOutput) << "Failed to write to file: " << OUTPUT_FILE;
    }
}

TEST_P(SonivoxTest, SeekTest) {
    EAS_I32 playTimeMs;
    EAS_RESULT result = EAS_ParseMetaData(mEASDataHandle, mEASStreamHandle, &playTimeMs);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to parse meta data";

    bool status = seekToPosition(0);
    ASSERT_TRUE(status) << "Seek test failed for location(ms): 0";

    status = seekToPosition(playTimeMs / 2);
    ASSERT_TRUE(status) << "Seek test failed for location(ms): " << playTimeMs / 2;

    status = seekToPosition(playTimeMs);
    ASSERT_TRUE(status) << "Seek test failed for location(ms): " << playTimeMs;

    status = seekToPosition(playTimeMs + kRandomSeekOffsetMs);
    ASSERT_FALSE(status) << "Invalid seek position: " << playTimeMs + kRandomSeekOffsetMs;
}

TEST_P(SonivoxTest, DecodePauseResumeTest) {
    EAS_I32 playTimeMs;
    EAS_STATE state;
    EAS_RESULT result = EAS_ParseMetaData(mEASDataHandle, mEASStreamHandle, &playTimeMs);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to parse meta data";

    const S_EAS_LIB_CONFIG *easConfig = EAS_Config();
    ASSERT_NE(easConfig, nullptr) << "Failed to configure the library";

    // go to middle of the audio
    result = EAS_Locate(mEASDataHandle, mEASStreamHandle, playTimeMs / 2, false);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to locate to location(ms): " << playTimeMs / 2;

    bool status = renderAudio(easConfig->mixBufferSize);
    ASSERT_TRUE(status) << "Audio not rendered when paused";

    result = EAS_Pause(mEASDataHandle, mEASStreamHandle);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to pause";

    // library takes time to set state
    usleep(kResumeWaitUs);

    result = EAS_State(mEASDataHandle, mEASStreamHandle, &state);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get EAS state";

    ASSERT_EQ(state, EAS_STATE_PAUSED) << "Invalid state reached when paused";

    result = EAS_Resume(mEASDataHandle, mEASStreamHandle);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to resume";

    // current position in milliseconds
    EAS_I32 currentPosMs;
    result = EAS_GetLocation(mEASDataHandle, mEASStreamHandle, &currentPosMs);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get current location";

    ASSERT_LE(currentPosMs, playTimeMs) << "No data to render";

    status = renderAudio(easConfig->mixBufferSize);
    ASSERT_TRUE(status) << "Audio not rendered when resumed";

    result = EAS_State(mEASDataHandle, mEASStreamHandle, &state);
    ASSERT_EQ(result, EAS_SUCCESS) << "Failed to get EAS state";

    ASSERT_EQ(state, EAS_STATE_PLAY) << "Invalid state reached when resumed";
}

INSTANTIATE_TEST_SUITE_P(SonivoxTestAll, SonivoxTest,
                         ::testing::Values(make_tuple("midi_a.mid", 2000, 2, 22050),
                                           make_tuple("midi8sec.mid", 8002, 2, 22050),
                                           make_tuple("midi_cs.mid", 2000, 2, 22050),
                                           make_tuple("midi_gs.mid", 2000, 2, 22050)));

int main(int argc, char **argv) {
    gEnv = new SonivoxTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
