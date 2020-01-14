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

#ifndef WEBM_FRAME_THREAD_UTILITY_H_
#define WEBM_FRAME_THREAD_UTILITY_H_

#include <media/stagefright/MediaAdapter.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/OpusHeader.h>

#include "webm/EbmlUtil.h"
#include "webm/WebmConstants.h"
#include "webm/WebmFrameThread.h"

using namespace android;
using namespace webm;
using namespace std;

// Helper methods to writer codec specific header in the webm file
size_t XiphLaceCodeLen(size_t size);

size_t XiphLaceEnc(uint8_t *buf, size_t size);

int32_t writeAudioHeaderData(const sp<AMessage> &msg, const char *mime);

sp<WebmElement> videoTrack(const sp<MetaData> &md);

sp<WebmElement> audioTrack(const sp<MetaData> &md);

#endif  // WEBM_FRAME_THREAD_UTILITY_H_
