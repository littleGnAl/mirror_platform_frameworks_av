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
#define LOG_TAG "decoderTest"

#include <fstream>
#include <iostream>
#include <limits>

#include <android/binder_process.h>

#include "StressTestEnvironment.h"
#include "Decoder.h"

static StressTestEnvironment *gEnv = nullptr;

class VideoDecoderStressTest : public ::testing::TestWithParam<tuple<string, string, int>> {};

TEST_P(VideoDecoderStressTest, DecodeStartMany) {
    ALOGV("Decode the samples given by extractor");
    tuple<string /* inputfile */, string /* codecName */, int /* nCodecs */> params = GetParam();

    string inputFile = gEnv->getRes() + get<0>(params);
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(inputFp, nullptr) << "Unable to open " << inputFile << " file for reading";


    string codecName = get<1>(params);
    int nCodecStress = get<2>(params);

    std::vector<Decoder*> decoderVec;
    //let's first do a extractor and its setup the rest of the codecs
    //should just follow that file.

    Decoder *decoder = new Decoder();
    ASSERT_NE(decoder, nullptr) << "Decoder creation failed";
    Extractor *extractor = decoder->getExtractor();
    AMediaFormat * Format = nullptr;
    const char * mime = nullptr;
    // Read file properties
    struct stat buf;
    stat(inputFile.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int32_t fd = fileno(inputFp);

    bool found_valid_video = false;

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    ASSERT_GT(trackCount, 0) << "initExtractor failed";
    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
          int32_t status = extractor->setupTrackFormat(curTrack);
          ASSERT_EQ(status, 0) << "Track Format invalid";
          Format = extractor->getFormat();
          AMediaFormat_getString(Format, AMEDIAFORMAT_KEY_MIME, &mime);
          if(mime != nullptr) {
            string sMime = mime;
            if(sMime.compare(0,6,"video/") == 0) {
                found_valid_video = true;
                break;
            }
          }
    }

    if(!found_valid_video) {
        ALOGE("No Valid video found in the resource");
        return ;
    }
    AMediaFormat_getString(Format, AMEDIAFORMAT_KEY_MIME, &mime);
    /*
      const char * mime;
      AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
      mCodec = createMediaCodec(format,mime,codecName,false);
        if(mCodec != nullptr) {
            ALOGE("New Codec Creation complete");
            AMediaCodec_start(mCodec);
        }else {
            ALOGE("Codec Creation failed");
        }
        return 0;
     *
     *
     */
    decoder->initCodec(Format, codecName, false);
    decoderVec.push_back(decoder);
    ALOGE("Enqueueing the decoder : ID: 1");
    for(int i = 1 ;i < nCodecStress;i++) {
        decoder = new Decoder();
        if(decoder) {
          decoder->initCodec(Format, codecName, false);
          ALOGE("Enqueueing the decoder : ID: %d", i + 1);
          decoderVec.push_back(decoder);
        }
    }

    extractor->deInitExtractor();
    for (int i = 0 ; i < decoderVec.size(); i++) {
        //free the decoder.
        ALOGE("Freeing the Decoders: %d", i + 1);
        auto dec = decoderVec[i];
        dec->deInitCodec();
        dec->resetDecoder();
        delete(dec);
    }

    decoderVec.clear();

    fclose(inputFp);
}
TEST_P(VideoDecoderStressTest, DecoderQuickStartStop) {
    ALOGV("Decode the samples given by extractor");
    tuple<string /* inputfile */, string /* codecName */, int /* nCodecs */> params = GetParam();

    string inputFile = gEnv->getRes() + get<0>(params);
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(inputFp, nullptr) << "Unable to open " << inputFile << " file for reading";


    string codecName = get<1>(params);
    int nCodecStress = get<2>(params);

    //let's first do a extractor and its setup the rest of the codecs
    //should just follow that file.

    Decoder *decoder = new Decoder();
    ASSERT_NE(decoder, nullptr) << "Decoder creation failed";
    Extractor *extractor = decoder->getExtractor();
    AMediaFormat * Format = nullptr;
    const char * mime = nullptr;
    // Read file properties
    struct stat buf;
    stat(inputFile.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int32_t fd = fileno(inputFp);

    bool found_valid_video = false;

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    ASSERT_GT(trackCount, 0) << "initExtractor failed";
    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
          int32_t status = extractor->setupTrackFormat(curTrack);
          ASSERT_EQ(status, 0) << "Track Format invalid";
          Format = extractor->getFormat();
          AMediaFormat_getString(Format, AMEDIAFORMAT_KEY_MIME, &mime);
          if(mime != nullptr) {
            string sMime = mime;
            if(sMime.compare(0,6,"video/") == 0) {
                found_valid_video = true;
                break;
            }
          }
    }

    if(!found_valid_video) {
        ALOGE("No Valid video found in the resource");
        return ;
    }
    AMediaFormat_getString(Format, AMEDIAFORMAT_KEY_MIME, &mime);
    for (int i = 0  ; i < nCodecStress; i++) {
        decoder->initCodec(Format,codecName,false);
        decoder->deInitCodec();
    }
    extractor->deInitExtractor();
    decoder->resetDecoder();
    delete(decoder);
    fclose(inputFp);
}
INSTANTIATE_TEST_SUITE_P(VideoDecoderStress, VideoDecoderStressTest,
                         ::testing::Values(
                                 // Hardware codecs
                                 make_tuple("testVideo_HEVC_medium.mp4", "", 4000)));

int main(int argc, char **argv) {
    ABinderProcess_startThreadPool();
    gEnv = new StressTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        gEnv->setStatsFile("Decoder.csv");
        status = gEnv->writeStatsHeader();
        ALOGV("Stats file = %d\n", status);
        status = RUN_ALL_TESTS();
        ALOGV("Decoder Test result = %d\n", status);
    }
    return status;
}
