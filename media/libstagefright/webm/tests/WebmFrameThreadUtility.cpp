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
#define LOG_TAG "WebmFrameThreadUtility"
#include <utils/Log.h>

#include "WebmFrameThreadUtility.h"

size_t XiphLaceCodeLen(size_t size) {
    return size / 0xff + 1;
}

size_t XiphLaceEnc(uint8_t *buf, size_t size) {
    size_t i;
    for (i = 0; size >= 0xff; ++i, size -= 0xff) {
        buf[i] = 0xff;
    }
    buf[i++] = size;
    return i;
}

int32_t writeAudioHeaderData(const sp<AMessage> &format, const char *mimeType) {
    if (strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_OPUS, strlen(MEDIA_MIMETYPE_AUDIO_OPUS)) &&
        strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_VORBIS, strlen(MEDIA_MIMETYPE_AUDIO_VORBIS))) {
        ALOGE("Unsupported mime type");
        return -1;
    }

    // Dummy CSD buffers for Opus and Vorbis
    int32_t csdSize = 32;
    char csdBuffer[csdSize];
    memset(csdBuffer, 0xFF, csdSize);
    sp<ABuffer> csdBuffer0 = ABuffer::CreateAsCopy((void *)csdBuffer, csdSize);
    sp<ABuffer> csdBuffer1 = ABuffer::CreateAsCopy((void *)csdBuffer, csdSize);
    sp<ABuffer> csdBuffer2 = ABuffer::CreateAsCopy((void *)csdBuffer, csdSize);
    if (csdBuffer0.get() == nullptr || csdBuffer0->base() == nullptr ||
        csdBuffer1.get() == nullptr || csdBuffer1->base() == nullptr ||
        csdBuffer2.get() == nullptr || csdBuffer2->base() == nullptr) {
        return -1;
    }
    format->setBuffer("csd-0", csdBuffer0);
    format->setBuffer("csd-1", csdBuffer1);
    format->setBuffer("csd-2", csdBuffer2);
    return 0;
}

sp<WebmElement> videoTrack(const sp<MetaData> &md) {
    int32_t width, height;
    const char *mimeType;
    if (!md->findInt32(kKeyWidth, &width) || !md->findInt32(kKeyHeight, &height) ||
        !md->findCString(kKeyMIMEType, &mimeType)) {
        ALOGE("Missing format keys for video track");
        md->dumpToLog();
        return nullptr;
    }
    const char *codec;
    if (!strncasecmp(mimeType, MEDIA_MIMETYPE_VIDEO_VP8, strlen(MEDIA_MIMETYPE_VIDEO_VP8))) {
        codec = "V_VP8";
    } else if (!strncasecmp(mimeType, MEDIA_MIMETYPE_VIDEO_VP9, strlen(MEDIA_MIMETYPE_VIDEO_VP9))) {
        codec = "V_VP9";
    } else {
        ALOGE("Unsupported codec: %s", mimeType);
        return nullptr;
    }
    return WebmElement::VideoTrackEntry(codec, width, height, md);
}

sp<WebmElement> audioTrack(const sp<MetaData> &md) {
    int32_t nChannels, samplerate;
    const char *mimeType;

    if (!md->findInt32(kKeyChannelCount, &nChannels) ||
        !md->findInt32(kKeySampleRate, &samplerate) || !md->findCString(kKeyMIMEType, &mimeType)) {
        ALOGE("Missing format keys for audio track");
        md->dumpToLog();
        return nullptr;
    }

    int32_t bitsPerSample = 0;
    if (!strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_OPUS, strlen(MEDIA_MIMETYPE_AUDIO_OPUS))) {
        OpusHeader header;
        header.channels = nChannels;
        header.num_streams = nChannels;
        header.num_coupled = 0;
        header.channel_mapping = ((nChannels > 8) ? 255 : (nChannels > 2));
        header.gain_db = 0;
        header.skip_samples = 0;

        // headers are 21-bytes + something driven by channel count
        // expect numbers in the low 30's here. WriteOpusHeader() will tell us
        // if things are bad.
        unsigned char header_data[100];
        int32_t headerSize =
                WriteOpusHeader(header, samplerate, (uint8_t *)header_data, sizeof(header_data));
        if (headerSize < 0) {
            ALOGE("failed to generate OPUS header");
            return nullptr;
        }

        size_t codecPrivateSize = 0;
        codecPrivateSize += headerSize;

        sp<ABuffer> codecPrivateBuf = new ABuffer(codecPrivateSize);
        uint8_t *codecPrivateData = codecPrivateBuf->data();

        memcpy(codecPrivateData, (uint8_t *)header_data, headerSize);
        sp<WebmElement> entry = WebmElement::AudioTrackEntry("A_OPUS", nChannels, samplerate,
                                                             codecPrivateBuf, bitsPerSample);
        return entry;
    } else if (!strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_VORBIS,
                            strlen(MEDIA_MIMETYPE_AUDIO_VORBIS))) {
        uint32_t type;
        const void *headerData1;
        const char headerData2[] = {3,   'v', 'o', 'r', 'b', 'i', 's', 7, 0, 0, 0, 'a',
                                    'n', 'd', 'r', 'o', 'i', 'd', 0,   0, 0, 0, 1};
        const void *headerData3;
        size_t headerSize1, headerSize2 = sizeof(headerData2), headerSize3;

        if (!md->findData(kKeyOpaqueCSD0, &type, &headerData1, &headerSize1) ||
            !md->findData(kKeyOpaqueCSD1, &type, &headerData3, &headerSize3)) {
            ALOGE("Missing header format keys for vorbis track");
            md->dumpToLog();
            return nullptr;
        }

        size_t codecPrivateSize = 1;
        codecPrivateSize += XiphLaceCodeLen(headerSize1);
        codecPrivateSize += XiphLaceCodeLen(headerSize2);
        codecPrivateSize += headerSize1 + headerSize2 + headerSize3;

        off_t off = 0;
        sp<ABuffer> codecPrivateBuf = new ABuffer(codecPrivateSize);
        uint8_t *codecPrivateData = codecPrivateBuf->data();
        codecPrivateData[off++] = 2;

        off += XiphLaceEnc(codecPrivateData + off, headerSize1);
        off += XiphLaceEnc(codecPrivateData + off, headerSize2);

        memcpy(codecPrivateData + off, headerData1, headerSize1);
        off += headerSize1;
        memcpy(codecPrivateData + off, headerData2, headerSize2);
        off += headerSize2;
        memcpy(codecPrivateData + off, headerData3, headerSize3);

        sp<WebmElement> entry = WebmElement::AudioTrackEntry("A_VORBIS", nChannels, samplerate,
                                                             codecPrivateBuf, bitsPerSample);
        return entry;
    } else {
        ALOGE("Track (%s) is not a supported audio format", mimeType);
        return nullptr;
    }
}
