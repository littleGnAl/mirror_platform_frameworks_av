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

#ifndef WRITER_UTILITY_H_
#define WRITER_UTILITY_H_

#include <fstream>
#include <iostream>
#include <vector>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>

#include <media/stagefright/MediaAdapter.h>
#include <media/stagefright/MediaDefs.h>

using namespace android;
using namespace std;

#define CODEC_CONFIG_FLAG 32

constexpr uint32_t kMaxCSDStrlen = 16;

struct BufferInfo {
    int32_t size;
    uint32_t flags;
    int64_t timeUs;
};

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    const char *mime;
    string inputFile;
    string info;
    int32_t firstParam;
    int32_t secondParam;
    bool isAudio;
} kInputData[] = {
        {MEDIA_MIMETYPE_AUDIO_OPUS, "bbb_opus_stereo_128kbps_48000hz.opus",
         "bbb_opus_stereo_128kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_AAC, "bbb_aac_stereo_128kbps_48000hz.aac",
         "bbb_aac_stereo_128kbps_48000hz.info", 48000, 2, true},
        {MEDIA_MIMETYPE_AUDIO_AAC_ADTS, "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.adts",
         "Mps_2_c2_fr1_Sc1_Dc2_0x03_raw.info", 48000, 2, true},
        {MEDIA_MIMETYPE_VIDEO_VP9, "bbb_vp9_176x144_285kbps_60fps.vp9",
         "bbb_vp9_176x144_285kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_VP8, "bbb_vp8_176x144_240kbps_60fps.vp8",
         "bbb_vp8_176x144_240kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_AVC, "bbb_avc_176x144_300kbps_60fps.h264",
         "bbb_avc_176x144_300kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_HEVC, "bbb_hevc_176x144_176kbps_60fps.hevc",
         "bbb_hevc_176x144_176kbps_60fps.info", 176, 144, false},
        {MEDIA_MIMETYPE_AUDIO_AMR_NB, "sine_amrnb_1ch_12kbps_8000hz.amrnb",
         "sine_amrnb_1ch_12kbps_8000hz.info", 8000, 1, true},
        {MEDIA_MIMETYPE_AUDIO_AMR_WB, "bbb_amrwb_1ch_14kbps_16000hz.amrwb",
         "bbb_amrwb_1ch_14kbps_16000hz.info", 16000, 1, true},
};

int32_t sendBuffersToWriter(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                            int32_t &inputFrameId, sp<MediaAdapter> &currentTrack, int32_t offset,
                            int32_t range);

int32_t writeHeaderBuffers(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                           int32_t &inputFrameId, sp<AMessage> &format, int32_t numCsds);

#endif  // WRITER_UTILITY_H_
