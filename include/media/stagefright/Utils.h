/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef UTILS_H_

#define UTILS_H_

#include <media/stagefright/foundation/AString.h>
#include <stdint.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <system/audio.h>
#include <media/MediaPlayerInterface.h>

namespace android {

#define FOURCC(c1, c2, c3, c4) \
    ((c1) << 24 | (c2) << 16 | (c3) << 8 | (c4))

uint16_t U16_AT(const uint8_t *ptr);
uint32_t U32_AT(const uint8_t *ptr);
uint64_t U64_AT(const uint8_t *ptr);

uint16_t U16LE_AT(const uint8_t *ptr);
uint32_t U32LE_AT(const uint8_t *ptr);
uint64_t U64LE_AT(const uint8_t *ptr);

uint64_t ntoh64(uint64_t x);
uint64_t hton64(uint64_t x);

class MetaData;
struct AMessage;
status_t convertMetaDataToMessage(
        const sp<MetaData> &meta, sp<AMessage> *format);
void convertMessageToMetaData(
        const sp<AMessage> &format, sp<MetaData> &meta);

AString MakeUserAgent();

// Convert a MIME type to a AudioSystem::audio_format
status_t mapMimeToAudioFormat(audio_format_t& format, const char* mime);

// Convert a aac profile to a AudioSystem::audio_format
void mapAACProfileToAudioFormat(audio_format_t& format, uint64_t eAacProfile);

// Send information from MetaData to the HAL via AudioSink
status_t sendMetaDataToHal(sp<MediaPlayerBase::AudioSink>& sink, const sp<MetaData>& meta);

// Check whether the stream defined by meta can be offloaded to hardware
bool canOffloadStream(const sp<MetaData>& meta, bool hasVideo,
                      bool isStreaming, audio_stream_type_t streamType);

AString uriDebugString(const AString &uri, bool incognito = false);

struct HLSTime {
    int32_t mSeq;
    int64_t mTimeUs;
    sp<AMessage> mMeta;

    explicit HLSTime(const sp<AMessage> &meta = NULL);
    int64_t getSegmentTimeUs() const;
};

bool operator <(const HLSTime &t0, const HLSTime &t1);

// read and write various object to/from AMessage

void writeToAMessage(sp<AMessage> msg, const AudioPlaybackRate &rate);
void readFromAMessage(const sp<AMessage> &msg, AudioPlaybackRate *rate /* nonnull */);

void writeToAMessage(sp<AMessage> msg, const AVSyncSettings &sync, float videoFpsHint);
void readFromAMessage(
        const sp<AMessage> &msg, AVSyncSettings *sync /* nonnull */, float *videoFps /* nonnull */);

}  // namespace android

#endif  // UTILS_H_
