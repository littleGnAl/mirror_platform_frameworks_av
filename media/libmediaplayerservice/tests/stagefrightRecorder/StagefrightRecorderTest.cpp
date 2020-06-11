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

// #define LOG_NDEBUG 0
#define LOG_TAG "StagefrightRecorderTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <time.h>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include <MediaPlayerService.h>
#include <media/NdkMediaExtractor.h>
#include <media/stagefright/MediaCodec.h>
#include <system/audio-base.h>

#include "StagefrightRecorder.h"

#define PACKAGE_NAME "StagefrightRecorderTest"
#define OUTPUT_INFO_FILE_NAME "/data/local/tmp/dump_info.out"
#define OUTPUT_FILE_NAME_AUDIO "/data/local/tmp/stfrecorder_audio.out"

const bool kDebug = false;
constexpr int32_t kMaxLoopCount = 10;
constexpr int32_t kClipDurationInSec = 4;
constexpr int32_t kPauseTimeInSec = 2;
// Tolerance value for extracted clipduration is maximum 10% of total clipduration
constexpr int32_t kToleranceValueInUs = kClipDurationInSec * 100000;

using namespace android;

class StagefrightRecorderTest
    : public ::testing::TestWithParam<std::pair<output_format, audio_encoder>> {
  public:
    StagefrightRecorderTest() : mStfRecorder(nullptr), mOutputAudioFp(nullptr) {}

    ~StagefrightRecorderTest() {
        if (mStfRecorder) free(mStfRecorder);
        if (mOutputAudioFp) fclose(mOutputAudioFp);
    }

    void SetUp() override {
        mStfRecorder = new StagefrightRecorder(String16(PACKAGE_NAME));
        ASSERT_NE(mStfRecorder, nullptr) << "Failed to create the instance of recorder";

        mOutputAudioFp = fopen(OUTPUT_FILE_NAME_AUDIO, "wb");
        ASSERT_NE(mOutputAudioFp, nullptr) << "Failed to open output file for audio recorder";

        int32_t fd = fileno(mOutputAudioFp);
        ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

        status_t status = mStfRecorder->setOutputFile(fd);
        ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";
    }

    void TearDown() override {
        if (mOutputAudioFp) {
            fclose(mOutputAudioFp);
            mOutputAudioFp = nullptr;
        }
        if (!kDebug) {
            int32_t status = remove(OUTPUT_FILE_NAME_AUDIO);
            ASSERT_EQ(status, 0) << "Unable to delete the output file";
        }
    }

    void setAudioRecorderFormat(output_format outputFormat, audio_encoder encoder,
                                audio_source_t audioSource = AUDIO_SOURCE_DEFAULT);
    void recordMedia();
    void dumpInfo();
    void setupExtractor(AMediaExtractor *extractor, int32_t &trackCount);
    void validateOutput(bool isPaused = false);

    MediaRecorderBase *mStfRecorder;
    FILE *mOutputAudioFp;
};

void StagefrightRecorderTest::setAudioRecorderFormat(output_format outputFormat,
                                                     audio_encoder encoder,
                                                     audio_source_t audioSource) {
    status_t status = mStfRecorder->setAudioSource(audioSource);
    ASSERT_EQ(status, OK) << "Failed to set the audio source";

    status = mStfRecorder->setOutputFormat(outputFormat);
    ASSERT_EQ(status, OK) << "Failed to set the output format";

    status = mStfRecorder->setAudioEncoder(encoder);
    ASSERT_EQ(status, OK) << "Failed to set the audio encoder";
}

void StagefrightRecorderTest::recordMedia() {
    status_t status = mStfRecorder->init();
    ASSERT_EQ(status, OK) << "Failed to initialize stagefright recorder";

    status = mStfRecorder->prepare();
    ASSERT_EQ(status, OK) << "Failed to preapre the reorder";

    status = mStfRecorder->start();
    ASSERT_EQ(status, OK) << "Failed to start the recorder";

    std::cout << "Recording media for 4 secs\n";
    std::this_thread::sleep_for(std::chrono::seconds(kClipDurationInSec));

    status = mStfRecorder->stop();
    ASSERT_EQ(status, OK) << "Failed to stop the recorder";
}

void StagefrightRecorderTest::dumpInfo() {
    FILE *dumpOutput = fopen(OUTPUT_INFO_FILE_NAME, "wb");
    int32_t dumpFd = fileno(dumpOutput);
    Vector<String16> args;
    status_t status = mStfRecorder->dump(dumpFd, args);
    ASSERT_EQ(status, OK) << "Failed to dump the info for the recorder";
    fclose(dumpOutput);
    if (!kDebug) {
        status = remove(OUTPUT_INFO_FILE_NAME);
        ASSERT_EQ(status, 0) << "Unable to delete output info file";
    }
}

void StagefrightRecorderTest::setupExtractor(AMediaExtractor *extractor, int32_t &trackCount) {
    int32_t fd = open(OUTPUT_FILE_NAME_AUDIO, O_RDONLY);
    ASSERT_GE(fd, 0) << "Failed to open recorder's output file to validate";

    struct stat buf;
    int32_t status = fstat(fd, &buf);
    ASSERT_EQ(status, 0) << "Failed to get properties of input file for extractor";

    size_t fileSize = buf.st_size;
    ALOGV("Size of input file to extractor: %zu", fileSize);

    status = AMediaExtractor_setDataSourceFd(extractor, fd, 0, fileSize);
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to set data source for extractor";

    trackCount = AMediaExtractor_getTrackCount(extractor);
    ASSERT_GT(trackCount, 0) << "No tracks reported by extractor";
    ALOGV("Number of tracks reported by extractor : %d", trackCount);
}

// Validate recoder's output using extractor
void StagefrightRecorderTest::validateOutput(bool isPaused) {
    int32_t trackCount = -1;
    AMediaExtractor *extractor = AMediaExtractor_new();
    ASSERT_NE(extractor, nullptr) << "Failed to create extractor";
    ASSERT_NO_FATAL_FAILURE(setupExtractor(extractor, trackCount));

    for (int32_t idx = 0; idx < trackCount; idx++) {
        AMediaExtractor_selectTrack(extractor, idx);
        AMediaFormat *format = AMediaExtractor_getTrackFormat(extractor, idx);
        ASSERT_NE(format, nullptr) << "Track format is NULL";
        ALOGI("Track format = %s", AMediaFormat_toString(format));

        int32_t totalClipDurationInUs = kClipDurationInSec * 1000000;
        if (isPaused) {
            totalClipDurationInUs = totalClipDurationInUs - kPauseTimeInSec * 1000000;
        }
        int64_t clipDurationUs;
        AMediaFormat_getInt64(format, AMEDIAFORMAT_KEY_DURATION, &clipDurationUs);
        ASSERT_LE((totalClipDurationInUs - clipDurationUs), kToleranceValueInUs)
                << "Difference in clip duration is higher than tolerance value";

        const char *mime = nullptr;
        AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
        ASSERT_NE(mime, nullptr) << "Track mime is NULL";
        ALOGI("Track mime = %s", mime);

        int32_t sampleRate, channelCount, bitRate;
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &channelCount);
        ALOGI("Channel count reported by extractor: %d", channelCount);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate);
        ALOGI("Sample Rate reported by extractor: %d", sampleRate);
        AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, &bitRate);
        ALOGI("Bit Rate reported by extractor: %d", bitRate);
    }
}

TEST_F(StagefrightRecorderTest, RecordingAudioSanityTest) {
    ASSERT_NO_FATAL_FAILURE(setAudioRecorderFormat(OUTPUT_FORMAT_DEFAULT, AUDIO_ENCODER_DEFAULT));

    int32_t maxAmplitude = -1;
    status_t status = mStfRecorder->getMaxAmplitude(&maxAmplitude);
    ASSERT_EQ(maxAmplitude, 0) << "Invalid value of max amplitude";

    ASSERT_NO_FATAL_FAILURE(recordMedia());

    // Verify getMetrics() behavior
    Parcel parcel;
    status = mStfRecorder->getMetrics(&parcel);
    ASSERT_EQ(status, OK) << "Failed to get the parcel from getMetrics";
    ALOGV("Size of the Parcel returned by getMetrics: %zu", parcel.dataSize());
    ASSERT_GT(parcel.dataSize(), 0) << "Parcel size reports empty record";
    ASSERT_NO_FATAL_FAILURE(validateOutput());
    ASSERT_NO_FATAL_FAILURE(dumpInfo());
}

TEST_P(StagefrightRecorderTest, MultiFormatAudioRecordTest) {
    output_format outputFormat = GetParam().first;
    audio_encoder audioEncoder = GetParam().second;
    ASSERT_NO_FATAL_FAILURE(setAudioRecorderFormat(outputFormat, audioEncoder));
    ASSERT_NO_FATAL_FAILURE(recordMedia());
    // TODO: b/161687761
    // Skip for AMR-NB/WB output format
    if (outputFormat != OUTPUT_FORMAT_AMR_NB || outputFormat != OUTPUT_FORMAT_AMR_WB) {
        ASSERT_NO_FATAL_FAILURE(validateOutput());
    }
    ASSERT_NO_FATAL_FAILURE(dumpInfo());
}

TEST_F(StagefrightRecorderTest, GetActiveMicrophonesTest) {
    ASSERT_NO_FATAL_FAILURE(
            setAudioRecorderFormat(OUTPUT_FORMAT_DEFAULT, AUDIO_ENCODER_DEFAULT, AUDIO_SOURCE_MIC));

    status_t status = mStfRecorder->init();
    ASSERT_EQ(status, OK) << "Init failed for stagefright recorder";

    status = mStfRecorder->prepare();
    ASSERT_EQ(status, OK) << "Failed to preapre the reorder";

    status = mStfRecorder->start();
    ASSERT_EQ(status, OK) << "Failed to start the recorder";

    std::cout << "Recording media for 4 secs\n";
    std::this_thread::sleep_for(std::chrono::seconds(kClipDurationInSec));

    std::vector<media::MicrophoneInfo> activeMicrophones{};
    status = mStfRecorder->getActiveMicrophones(&activeMicrophones);
    ASSERT_EQ(status, OK) << "Failed to get Active Microphones";
    ASSERT_GT(activeMicrophones.size(), 0) << "No active microphones are found";

    status = mStfRecorder->stop();
    ASSERT_EQ(status, OK) << "Failed to stop the recorder";
    ASSERT_NO_FATAL_FAILURE(dumpInfo());
}

TEST_F(StagefrightRecorderTest, MultiStartStopPauseTest) {
    ASSERT_NO_FATAL_FAILURE(setAudioRecorderFormat(OUTPUT_FORMAT_DEFAULT, AUDIO_ENCODER_DEFAULT));

    status_t status = mStfRecorder->init();
    ASSERT_EQ(status, OK) << "Init failed for stagefright recorder";

    status = mStfRecorder->prepare();
    ASSERT_EQ(status, OK) << "Failed to preapre the reorder";

    // first start should succeed.
    status = mStfRecorder->start();
    ASSERT_EQ(status, OK) << "Failed to start the recorder";

    for (int32_t count = 0; count < kMaxLoopCount; count++) {
        status = mStfRecorder->start();
    }

    std::cout << "Recording media for 2 secs\n";
    std::this_thread::sleep_for(std::chrono::seconds(kClipDurationInSec / 2));

    // first pause should succeed.
    status = mStfRecorder->pause();
    ASSERT_EQ(status, OK) << "Failed to pause the recorder";

    std::cout << "Paused recorder for 2 secs\n";
    std::this_thread::sleep_for(std::chrono::seconds(kPauseTimeInSec));

    for (int32_t count = 0; count < kMaxLoopCount; count++) {
        status = mStfRecorder->pause();
    }

    // first resume should succeed.
    status = mStfRecorder->resume();
    ASSERT_EQ(status, OK) << "Failed to resume the recorder";

    for (int32_t count = 0; count < kMaxLoopCount; count++) {
        status = mStfRecorder->resume();
    }

    std::cout << "Recording media for 2 secs\n";
    std::this_thread::sleep_for(std::chrono::seconds(kClipDurationInSec / 2));

    status = mStfRecorder->stop();
    ASSERT_EQ(status, OK) << "Failed to stop the recorder";

    ASSERT_NO_FATAL_FAILURE(validateOutput(true));
    ASSERT_NO_FATAL_FAILURE(dumpInfo());
}

INSTANTIATE_TEST_SUITE_P(
        StagefrightRecorderTestAll, StagefrightRecorderTest,
        ::testing::Values(std::make_pair(OUTPUT_FORMAT_AMR_NB, AUDIO_ENCODER_AMR_NB),
                          std::make_pair(OUTPUT_FORMAT_AMR_WB, AUDIO_ENCODER_AMR_WB),
                          std::make_pair(OUTPUT_FORMAT_AAC_ADTS, AUDIO_ENCODER_AAC),
                          std::make_pair(OUTPUT_FORMAT_OGG, AUDIO_ENCODER_OPUS)));

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
