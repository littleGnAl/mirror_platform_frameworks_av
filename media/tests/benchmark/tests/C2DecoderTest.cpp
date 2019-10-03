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

#define LOG_NDEBUG 0
#define LOG_TAG "codec2DecoderTest"

#include <fstream>
#include <iostream>
#include <limits>

#include "Extractor.h"
#include "C2Decoder.h"
#include "BenchmarkTestEnvironment.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class C2DecoderTest : public ::testing::TestWithParam<pair<string, string>> {};

TEST_P(C2DecoderTest, Codec2Decode) {
    ALOGV("Decode the samples given by extractor using codec2");
    string inputFile = gEnv->getRes() + GetParam().first;
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    if (!inputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }

    C2Decoder *decoder = new C2Decoder();
    int32_t status = decoder->setupCodec2();
    if (status != 0) {
        cout << "[   WARN   ] Test Skipped. Component creation failed \n";
        return;
    }
    Extractor *extractor = new Extractor();
    if (!extractor) {
        cout << "[   WARN   ] Test Skipped. Extractor creation failed \n";
        return;
    }

    // Read file properties
    fseek(inputFp, 0, SEEK_END);
    size_t fileSize = ftell(inputFp);
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        cout << "[   WARN   ] Test Skipped. initExtractor failed\n";
        return;
    }
    for (int32_t curTrack = 0; curTrack < trackCount; curTrack++) {
        status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            cout << "[   WARN   ] Test Skipped. Track Format invalid \n";
            return;
        }

        uint8_t *inputBuffer = (uint8_t *)malloc(kMaxBufferSize);
        if (!inputBuffer) {
            cout << "[   WARN   ] Test Skipped. Insufficient memory \n";
            return;
        }

        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;
        int32_t idx = 0;

        // Get CSD data
        while (1) {
            void *csdBuffer = extractor->getCSDSample(info, idx);
            if (!csdBuffer || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > kMaxBufferSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, csdBuffer, info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
            idx++;
        }

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > kMaxBufferSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        AMediaFormat *format = extractor->getFormat();
        string codecName = GetParam().second;
        status = decoder->createCodec2Component(codecName, format);
        if (status != 0) {
            cout << "[   WARN   ] Test Skipped. Create component failed \n";
            return;
        }

        // Send the inputs to C2 Decoder and wait till all buffers are returned.
        decoder->decodeFrames(inputBuffer, frameInfo);
        decoder->waitOnInputConsumption();
        if (!decoder->mEos) {
            cout << "[   WARN   ] Test Failed. Didn't receive EOS \n";
        }
        decoder->deInitCodec();
        int64_t durationUs = extractor->getClipDuration();
        decoder->dumpStatistics(GetParam().first, durationUs);
        free(inputBuffer);
        decoder->resetDecoder();
    }
    fclose(inputFp);
    extractor->deInitExtractor();
    delete extractor;
    delete decoder;
}

// TODO: (b/140549596)
// Add wav files
INSTANTIATE_TEST_SUITE_P(
        AudioDecoderTest, C2DecoderTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "c2.android.aac.decoder"),
                          make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", "c2.android.mp3.decoder"),
                          make_pair("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "c2.android.amrnb.decoder"),
                          make_pair("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "c2.android.amrnb.decoder"),
                          make_pair("bbb_44100hz_2ch_80kbps_vorbis_30sec.mp4", "c2.android.vorbis.decoder"),
                          make_pair("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "c2.android.flac.decoder"),
                          make_pair("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "c2.android.opus.decoder")));

INSTANTIATE_TEST_SUITE_P(
        VideoDecoderTest, C2DecoderTest,
        ::testing::Values(make_pair("crowd_1920x1080_25fps_4000kbps_vp9.webm", "c2.android.vp9.decoder"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_vp8.webm", "c2.android.vp8.decoder"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_av1.webm", "c2.android.av1.decoder"),
                          make_pair("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", "c2.android.mpeg2.decoder"),
                          make_pair("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "c2.android.mpeg4.decoder"),
                          make_pair("crowd_352x288_25fps_6000kbps_h263.3gp", "c2.android.h263.decoder"),
                          make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", "c2.android.avc.decoder"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", "c2.android.hevc.decoder")));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    cout<<"initFromOptions \n";
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("C2 Decoder Test result = %d\n", status);
    }
    return status;
}