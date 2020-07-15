/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef FUZZER_MEDIA_UTILITY_H_
#define FUZZER_MEDIA_UTILITY_H_
#include <fuzzer/FuzzedDataProvider.h>
#include <media/IMediaHTTPService.h>
#include <datasource/DataSourceFactory.h>
#include <media/stagefright/CallbackMediaSource.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/foundation/base64.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/MediaWriter.h>
#include <media/IMediaExtractor.h>
#include <utils/StrongPointer.h>
#include <media/mediarecorder.h>
#include <media/stagefright/MediaDefs.h>

namespace android {
enum StandardWriters {
    OGG,
    AAC,
    AAC_ADTS,
    WEBM,
    MPEG4,
    AMR_NB,
    AMR_WB,
    MPEG2TS,
    // Allows FuzzedDataProvider to find the end of this enum.
    kMaxValue = MPEG2TS,
};

std::string genMimeType(FuzzedDataProvider* dataProvider);
sp<IMediaExtractor> genMediaExtractor(FuzzedDataProvider* dataProvider, uint16_t dataAmount);
sp<MediaSource> genMediaSource(FuzzedDataProvider* dataProvider,
                               uint16_t maxMediaBlobSize);

sp<MediaWriter> createWriter(int32_t fd, StandardWriters writerType, sp<MetaData> fileMeta);
} // namespace android
#endif // FUZZER_MEDIA_UTILITY_H_
