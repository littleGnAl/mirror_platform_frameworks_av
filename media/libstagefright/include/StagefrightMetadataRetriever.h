/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef STAGEFRIGHT_METADATA_RETRIEVER_H_

#define STAGEFRIGHT_METADATA_RETRIEVER_H_

#include <media/IMediaExtractor.h>
#include <media/MediaMetadataRetrieverInterface.h>

#include <utils/KeyedVector.h>

namespace android {

class DataSource;
class MediaExtractor;

struct StagefrightMetadataRetriever : public MediaMetadataRetrieverInterface {
    StagefrightMetadataRetriever();
    virtual ~StagefrightMetadataRetriever();

    virtual status_t setDataSource(
            const sp<IMediaHTTPService> &httpService,
            const char *url,
            const KeyedVector<String8, String8> *headers);

    virtual status_t setDataSource(int fd, int64_t offset, int64_t length);
    virtual status_t setDataSource(const sp<DataSource>& source, const char *mime);

    virtual VideoFrame *getFrameAtTime(int64_t timeUs, int option, int colorFormat, bool metaOnly);
    virtual MediaAlbumArt *extractAlbumArt();
    virtual const char *extractMetadata(int keyCode);

private:
    sp<DataSource> mSource;
    sp<IMediaExtractor> mExtractor;

    bool mParsedMetaData;
    KeyedVector<int, String8> mMetaData;
    MediaAlbumArt *mAlbumArt;

    void parseMetaData();
    // Delete album art and clear metadata.
    void clearMetadata();

    StagefrightMetadataRetriever(const StagefrightMetadataRetriever &);

    StagefrightMetadataRetriever &operator=(
            const StagefrightMetadataRetriever &);
};

}  // namespace android

#endif  // STAGEFRIGHT_METADATA_RETRIEVER_H_
