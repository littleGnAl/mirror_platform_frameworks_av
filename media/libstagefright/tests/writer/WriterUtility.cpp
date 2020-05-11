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
#define LOG_TAG "WriterUtility"
#include <utils/Log.h>

#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>

#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaDefs.h>

#include "WriterUtility.h"

int32_t sendBuffersToWriter(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                            int32_t &inputFrameId, sp<MediaAdapter> &currentTrack, int32_t offset,
                            int32_t range, bool isPaused, sp<WriterListener> listener) {
    while (1) {
        if (inputFrameId >= (int)bufferInfo.size() || inputFrameId >= (offset + range)) break;
        if (listener != nullptr) {
            if (listener->mSignaledDuration || listener->mSignaledSize) {
                ALOGV("Max File limit reached. No more buffers will be sent to the writer");
                break;
            }
        }

        int32_t size = bufferInfo[inputFrameId].size;
        char *data = (char *)malloc(size);
        if (!data) {
            ALOGE("Insufficient memeory to read input");
            return -1;
        }

        inputStream.read(data, size);
        CHECK_EQ(inputStream.gcount(), size);

        sp<ABuffer> buffer = new ABuffer((void *)data, size);
        if (buffer.get() == nullptr) {
            ALOGE("sendBuffersToWriter() got a nullptr buffer.");
            return -1;
        }
        MediaBuffer *mediaBuffer = new MediaBuffer(buffer);

        // Released in MediaAdapter::signalBufferReturned().
        mediaBuffer->add_ref();
        mediaBuffer->set_range(buffer->offset(), buffer->size());

        MetaDataBase &sampleMetaData = mediaBuffer->meta_data();
        sampleMetaData.setInt64(kKeyTime, bufferInfo[inputFrameId].timeUs);
        // Just set the kKeyDecodingTime as the presentation time for now.
        sampleMetaData.setInt64(kKeyDecodingTime, bufferInfo[inputFrameId].timeUs);

        if (bufferInfo[inputFrameId].flags == 1) {
            sampleMetaData.setInt32(kKeyIsSyncFrame, true);
        }

        // This pushBuffer will wait until the mediaBuffer is consumed.
        int status = currentTrack->pushBuffer(mediaBuffer);
        free(data);
        inputFrameId++;

        if (OK != status) {
            if (!isPaused) return status;
            else {
                ALOGD("Writer is in paused state. Input buffers won't get consumed");
                return 0;
            }
        }
    }
    return 0;
}

int32_t writeHeaderBuffers(ifstream &inputStream, vector<BufferInfo> &bufferInfo,
                           int32_t &inputFrameId, sp<AMessage> &format, int32_t numCsds) {
    char csdName[kMaxCSDStrlen];
    for (int csdId = 0; csdId < numCsds; csdId++) {
        int32_t flags = bufferInfo[inputFrameId].flags;
        if (flags == CODEC_CONFIG_FLAG) {
            int32_t size = bufferInfo[inputFrameId].size;
            char *data = (char *)malloc(size);
            if (!data) {
                ALOGE("Insufficient memeory to read input");
                return -1;
            }
            inputStream.read(data, size);
            CHECK_EQ(inputStream.gcount(), size);

            sp<ABuffer> csdBuffer = ABuffer::CreateAsCopy((void *)data, size);
            if (csdBuffer.get() == nullptr || csdBuffer->base() == nullptr) {
                return -1;
            }
            snprintf(csdName, sizeof(csdName), "csd-%d", csdId);
            format->setBuffer(csdName, csdBuffer);
            inputFrameId++;
            free(data);
        }
    }
    return 0;
}

AMediaExtractor *createExtractor(string inputFileName, int32_t *trackCount) {
    ALOGV("Input file for extractor: %s", inputFileName.c_str());

    FILE *inputFp = fopen(inputFileName.c_str(), "rb");
    if (!inputFp) {
        ALOGE("Unable to open %s file for reading", inputFileName.c_str());
        return nullptr;
    }

    ALOGV("Reading file properties");
    struct stat buf;
    int32_t status = stat(inputFileName.c_str(), &buf);
    if (status != 0) {
        ALOGE("Failed to get properties of input file for extractor");
        return nullptr;
    }
    size_t fileSize = buf.st_size;
    ALOGV("Size of input file to extractor: %zu", fileSize);

    int32_t fd = fileno(inputFp);
    if (fd < 0) {
        ALOGE("Failed to open writer's output file to validate");
        return nullptr;
    }

    AMediaExtractor *extractor = AMediaExtractor_new();
    if (!extractor) {
        ALOGE("Failed to create extractor");
        return nullptr;
    }

    status = AMediaExtractor_setDataSourceFd(extractor, fd, 0, fileSize);
    if (status != AMEDIA_OK) {
        ALOGE("Failed to set data source for file : %s", inputFileName.c_str());
        return nullptr;
    }

    int32_t numTracks = AMediaExtractor_getTrackCount(extractor);
    if (numTracks <= 0) {
        ALOGE("No tracks reported by extractor");
    }
    *trackCount = numTracks;
    ALOGV("Number of tracks reported by extractor : %d", numTracks);

    fclose(inputFp);
    return extractor;
}

int32_t extract(AMediaExtractor *extractor, configFormat &params, vector<BufferInfo> &bufferInfo,
                int32_t idx, uint8_t *buffer, size_t bufSize, size_t *bytesExtracted) {

    AMediaExtractor_selectTrack(extractor, idx);
    AMediaFormat *format = AMediaExtractor_getTrackFormat(extractor, idx);
    ALOGI("Track format = %s", AMediaFormat_toString(format));

    const char *mime = nullptr;
    AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
    if (!mime) {
        ALOGE("Track mime is NULL");
        return -1;
    }
    ALOGI("Track mime = %s", mime);
    strncpy(params.mime, mime, kMimeSize);

    if (!strncmp(mime, "audio/", 6)) {
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &params.channelCount)) {
            ALOGE("Extractor did not find channel count");
            return -1;
        }
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, &params.sampleRate)) {
            ALOGE("Extractor did not find sample rate");
            return -1;
        }
    } else if (!strncmp(mime, "video/", 6) || !strncmp(mime, "image/", 6)) {
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &params.width)) {
            ALOGE("Extractor did not find width");
            return -1;
        }
        if (!AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &params.height)) {
            ALOGE("Extractor did not find height");
            return -1;
        }
    } else {
        ALOGE("Invalid mime: %s", mime);
        return -1;
    }

    // Get CSD data
    int index = 0;
    void *csdBuf;
    while (1) {
        csdBuf = nullptr;
        char csdName[16];
        snprintf(csdName, 16, "csd-%d", index);
        size_t csdSize = 0;
        bool csdFound = AMediaFormat_getBuffer(format, csdName, &csdBuf, &csdSize);
        if (!csdFound || !csdBuf || !csdSize) break;

        bufferInfo.push_back({static_cast<int32_t>(csdSize), CODEC_CONFIG_FLAG, 0});
        *bytesExtracted += csdSize;
        memcpy(buffer, csdBuf, csdSize);
        index++;
    }

    // Get frame data
    uint8_t *sampleBuffer = (uint8_t *)malloc(bufSize);
    if (!sampleBuffer) {
        ALOGE("Failed to allocate the buffer of size %zu", bufSize);
        return -1;
    }
    while (1) {
        int bytesRead = AMediaExtractor_readSampleData(extractor, sampleBuffer, bufSize);
        if (bytesRead <= 0) break;
        memcpy(buffer, sampleBuffer, bytesRead);

        int64_t pts = AMediaExtractor_getSampleTime(extractor);
        uint32_t flag = AMediaExtractor_getSampleFlags(extractor);

        if (mime == MEDIA_MIMETYPE_AUDIO_VORBIS) {
            // Removing 4 bytes of AMEDIAFORMAT_KEY_VALID_SAMPLES from sample size
            bytesRead = bytesRead - 4;
        }
        bufferInfo.push_back({bytesRead, flag, pts});
        *bytesExtracted += bytesRead;
        AMediaExtractor_advance(extractor);
    }
    free(sampleBuffer);
    return OK;
}
