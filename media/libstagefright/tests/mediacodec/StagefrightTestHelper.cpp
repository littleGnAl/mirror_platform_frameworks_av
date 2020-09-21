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

#include <media/stagefright/MediaCodec.h>
#include <media/stagefright/MediaCodecListWriter.h>

#include "StagefrightTestHelper.h"

namespace android {

// static
sp<MediaCodec> StagefrightTestHelper::CreateCodec(
        const AString &name,
        const sp<ALooper> &looper,
        std::function<sp<CodecBase>(const AString &, const char *)> getCodecBase,
        std::function<sp<MediaCodecInfo>(const AString &, status_t *)> getCodecInfo) {
    sp<MediaCodec> codec = new MediaCodec(
            looper, MediaCodec::kNoPid, MediaCodec::kNoUid, getCodecBase, getCodecInfo);
    if (codec->init(name) != OK) {
        return nullptr;
    }
    return codec;
}

// static
void StagefrightTestHelper::Reclaim(const sp<MediaCodec> &codec, bool force) {
    codec->reclaim(force);
}

// static
std::shared_ptr<MediaCodecListWriter> StagefrightTestHelper::CreateCodecListWriter() {
    return std::shared_ptr<MediaCodecListWriter>(new MediaCodecListWriter);
}

// static
void StagefrightTestHelper::WriteCodecInfos(
        const std::shared_ptr<MediaCodecListWriter> &writer,
        std::vector<sp<MediaCodecInfo>> *codecInfos) {
    writer->writeCodecInfos(codecInfos);
}

}  // namespace android
