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
#include <media/stagefright/MediaCodec.h>
#include <system/audio-base.h>

#include "StagefrightRecorder.h"

#define PACKAGE_NAME "StagefrightRecorderTest"
#define OUTPUT_FILE_NAME_V "/data/local/tmp/stfrecorder_video.out"
#define OUTPUT_FILE_NAME_A "/data/local/tmp/stfrecorder_audio.out"

constexpr int32_t kRecordTimeSec = 5;
constexpr int32_t kVideoWidth = 176;
constexpr int32_t kVideoHeight = 144;
constexpr int32_t kFrameRate = 30;

using namespace android;

class StagefrightRecorderTest : public ::testing::Test {
  public:
    StagefrightRecorderTest()
        : mStfRecorder(nullptr), mOutputVideoFp(nullptr), mOutputAudioFp(nullptr) {}

    ~StagefrightRecorderTest() {
        if (mStfRecorder) free(mStfRecorder);
        if (mOutputVideoFp) fclose(mOutputVideoFp);
        if (mOutputAudioFp) fclose(mOutputAudioFp);
    }

    void SetUp() override {
        mStfRecorder = new StagefrightRecorder(String16(PACKAGE_NAME));
        ASSERT_NE(mStfRecorder, nullptr) << "Failed to create the instance of recorder";

        std::string outputFileName = OUTPUT_FILE_NAME_V;
        mOutputVideoFp = fopen(outputFileName.c_str(), "wb");
        ASSERT_NE(mOutputVideoFp, nullptr) << "Failed to open output file for video recorder";

        outputFileName = OUTPUT_FILE_NAME_A;
        mOutputAudioFp = fopen(outputFileName.c_str(), "wb");
        ASSERT_NE(mOutputAudioFp, nullptr) << "Failed to open output file for audio recorder";
    }

    void recordAudioInRawFormat(output_format outputFormat, audio_encoder encoder);
    void recordMedia();
    void checkOutputExists(bool isAudio);

    MediaRecorderBase *mStfRecorder;
    FILE *mOutputVideoFp;
    FILE *mOutputAudioFp;
};

void StagefrightRecorderTest::recordAudioInRawFormat(output_format outputFormat,
                                                     audio_encoder encoder) {
    status_t status = mStfRecorder->setAudioSource(AUDIO_SOURCE_DEFAULT);
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

    std::cout << "Waiting for 5 secs to record ...\n";
    std::this_thread::sleep_for(std::chrono::seconds(kRecordTimeSec));

    status = mStfRecorder->stop();
    ASSERT_EQ(status, OK) << "Failed to stop the recorder";
}

void StagefrightRecorderTest::checkOutputExists(bool isAudio) {
    std::string outputFileName = OUTPUT_FILE_NAME_V;
    if (isAudio) {
        outputFileName = OUTPUT_FILE_NAME_A;
    }

    struct stat buf;
    int32_t status = stat(outputFileName.c_str(), &buf);
    ASSERT_EQ(status, 0) << "Failed to get properties of output file";

    size_t fileSize = buf.st_size;
    ALOGV("Size of input file to extractor: %zu", fileSize);
    ASSERT_GT(fileSize, 0) << "Output file cannot be empty";
}

TEST_F(StagefrightRecorderTest, RecordingVideoSanityTest) {
    int32_t fd = fileno(mOutputVideoFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    status = mStfRecorder->setVideoSource(VIDEO_SOURCE_DEFAULT);
    ASSERT_EQ(status, OK) << "Failed to set the video source";

    status = mStfRecorder->setOutputFormat(OUTPUT_FORMAT_DEFAULT);
    ASSERT_EQ(status, OK) << "Failed to set the output format";

    status = mStfRecorder->setVideoEncoder(VIDEO_ENCODER_DEFAULT);
    ASSERT_EQ(status, OK) << "Failed to set the video encoder";

    status = mStfRecorder->setVideoSize(kVideoWidth, kVideoHeight);
    ASSERT_EQ(status, OK) << "Failed to set the video size";

    status = mStfRecorder->setVideoFrameRate(kFrameRate);
    ASSERT_EQ(status, OK) << "Failed to set the video frame rate";

    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(false));
}

TEST_F(StagefrightRecorderTest, RecordingAudioSanityTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    ASSERT_NO_FATAL_FAILURE(recordAudioInRawFormat(OUTPUT_FORMAT_DEFAULT, AUDIO_ENCODER_DEFAULT));

    int32_t maxAmplitude;
    status = mStfRecorder->getMaxAmplitude(&maxAmplitude);
    ASSERT_EQ(maxAmplitude, 0) << "Invalid value of max amplitude";

    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(true));
}

TEST_F(StagefrightRecorderTest, RecordAudioInAMRNBFormatTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    ASSERT_NO_FATAL_FAILURE(recordAudioInRawFormat(OUTPUT_FORMAT_AMR_NB, AUDIO_ENCODER_AMR_NB));
    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(true));
}

TEST_F(StagefrightRecorderTest, RecordAudioInAMRWBFormatTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    ASSERT_NO_FATAL_FAILURE(recordAudioInRawFormat(OUTPUT_FORMAT_AMR_WB, AUDIO_ENCODER_AMR_WB));
    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(true));
}

TEST_F(StagefrightRecorderTest, RecordAudioInAACFormatTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    ASSERT_NO_FATAL_FAILURE(recordAudioInRawFormat(OUTPUT_FORMAT_AAC_ADTS, AUDIO_ENCODER_AAC));
    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(true));
}

TEST_F(StagefrightRecorderTest, RecordAudioInOPUSFormatTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    ASSERT_NO_FATAL_FAILURE(recordAudioInRawFormat(OUTPUT_FORMAT_OGG, AUDIO_ENCODER_OPUS));
    ASSERT_NO_FATAL_FAILURE(recordMedia());
    ASSERT_NO_FATAL_FAILURE(checkOutputExists(true));
}

TEST_F(StagefrightRecorderTest, GetActiveMicrophonesTest) {
    int32_t fd = fileno(mOutputAudioFp);
    ASSERT_GE(fd, 0) << "Failed to open output file for recorder";

    status_t status = mStfRecorder->setOutputFile(fd);
    ASSERT_EQ(status, OK) << "SetOutputFile failed for stagefright recorder";

    status = mStfRecorder->setAudioSource(AUDIO_SOURCE_MIC);
    ASSERT_EQ(status, OK) << "Failed to set the audio source";

    status = mStfRecorder->setOutputFormat(OUTPUT_FORMAT_DEFAULT);
    ASSERT_EQ(status, OK) << "Failed to set the output format";

    status = mStfRecorder->setAudioEncoder(AUDIO_ENCODER_DEFAULT);
    ASSERT_EQ(status, OK) << "Failed to set the audio encoder";

    status = mStfRecorder->init();
    ASSERT_EQ(status, OK) << "Init failed for stagefright recorder";

    status = mStfRecorder->prepare();
    ASSERT_EQ(status, OK) << "Failed to preapre the reorder";

    status = mStfRecorder->start();
    ASSERT_EQ(status, OK) << "Failed to start the recorder";

    std::cout << "Waiting for 5 secs to record ...\n";
    std::this_thread::sleep_for(std::chrono::seconds(kRecordTimeSec));

    std::vector<media::MicrophoneInfo> activeMicrophones{};
    status = mStfRecorder->getActiveMicrophones(&activeMicrophones);
    ASSERT_EQ(status, OK) << "Failed to get Active Microphones";
    ASSERT_GT(activeMicrophones.size(), 0) << "No active microphones are found";
    status = mStfRecorder->stop();
    ASSERT_EQ(status, OK) << "Failed to stop the recorder";
}
