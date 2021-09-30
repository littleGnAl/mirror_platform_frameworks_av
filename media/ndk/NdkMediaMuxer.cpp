/*
 * Copyright (C) 2014 The Android Open Source Project
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
#define LOG_TAG "NdkMediaMuxer"


#include <media/NdkMediaMuxer.h>
#include <media/NdkMediaCodec.h>
#include <media/NdkMediaErrorPriv.h>
#include <media/NdkMediaFormatPriv.h>


#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/MediaMuxer.h>
#include <media/IMediaHTTPService.h>
#include <android_util_Binder.h>

#include <jni.h>

using namespace android;

struct AMediaMuxer {
    sp<MediaMuxer> mImpl;

};

extern "C" {

EXPORT
AMediaMuxer* AMediaMuxer_new(int fd, OutputFormat format) {
    ALOGV("ctor");
    // check for invalid file descriptor.
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        ALOGE("Invalid File Status Flags: %d", flags);
        return nullptr;
    }
    // fd must be in read-write mode or write-only mode.
    if ((flags & (O_RDWR | O_WRONLY)) == 0) {
        ALOGE("File descriptor is not in read-write mode or write-only mode");
        return nullptr;
    }
    // fd must be in read-write for webm writer
    if (((MediaMuxer::OutputFormat)format == MediaMuxer::OUTPUT_FORMAT_WEBM) &&
        (flags & O_RDWR) == 0) {
        ALOGE("File descriptor must be in read-write mode for webm writer");
        return nullptr;
    }
    // Verify fd is seekable
    off64_t off = lseek64(fd, 0, SEEK_SET);
    if (off < 0) {
        ALOGE("File descriptor is not seekable");
        return nullptr;
    }
    // check for valid output format
    if (((MediaMuxer::OutputFormat)format < MediaMuxer::OUTPUT_FORMAT_MPEG_4) ||
        ((MediaMuxer::OutputFormat)format >= MediaMuxer::OUTPUT_FORMAT_LIST_END)) {
        ALOGE("Invalid output format given to muxer : %d", format);
        return nullptr;
    }
    AMediaMuxer *mData = new AMediaMuxer();
    mData->mImpl = new MediaMuxer(fd, (android::MediaMuxer::OutputFormat)format);
    return mData;
}

EXPORT
media_status_t AMediaMuxer_delete(AMediaMuxer *muxer) {
    ALOGV("dtor");
    delete muxer;
    return AMEDIA_OK;
}

EXPORT
media_status_t AMediaMuxer_setLocation(AMediaMuxer *muxer, float latitude, float longtitude) {
    return translate_error(muxer->mImpl->setLocation(latitude * 10000, longtitude * 10000));
}

EXPORT
media_status_t AMediaMuxer_setOrientationHint(AMediaMuxer *muxer, int degrees) {
    return translate_error(muxer->mImpl->setOrientationHint(degrees));
}

EXPORT
ssize_t AMediaMuxer_addTrack(AMediaMuxer *muxer, const AMediaFormat *format) {
    sp<AMessage> msg;
    AMediaFormat_getFormat(format, &msg);
    ssize_t ret = muxer->mImpl->addTrack(msg);
    return (ret >= 0) ? ret : translate_error(ret);
}

EXPORT
media_status_t AMediaMuxer_start(AMediaMuxer *muxer) {
    return translate_error(muxer->mImpl->start());
}

EXPORT
media_status_t AMediaMuxer_stop(AMediaMuxer *muxer) {
    return translate_error(muxer->mImpl->stop());
}

EXPORT
media_status_t AMediaMuxer_writeSampleData(AMediaMuxer *muxer,
        size_t trackIdx, const uint8_t *data, const AMediaCodecBufferInfo *info) {
    sp<ABuffer> buf = new ABuffer((void*)(data + info->offset), info->size);
    return translate_error(
            muxer->mImpl->writeSampleData(buf, trackIdx, info->presentationTimeUs, info->flags));
}


} // extern "C"

