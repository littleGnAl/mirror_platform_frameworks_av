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
// Authors: corbin.souffrant@leviathansecurity.com
//          dylan.katz@leviathansecurity.com

#include <MediaMuxerFuzzer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/stagefright/MediaMuxer.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

// Can't seem to get setBuffer or setString working. It always segfaults on a
// null pointer read or memleaks. So that functionality is missing.
void createMessage(AMessage *msg, FuzzedDataProvider *fdp) {
  size_t count = 32;
  while (fdp->remaining_bytes() > 0 && count > 0) {
    uint8_t function_id =
        fdp->ConsumeIntegralInRange<uint8_t>(0, amessage_setvals.size() - 1);
    amessage_setvals[function_id](msg, fdp);
    count--;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
  int fd = fdp.ConsumeIntegral<int>();
  if (fd >= 0 && fd <= 2) fd = 3;

  MediaMuxer::OutputFormat format =
      (MediaMuxer::OutputFormat)fdp.ConsumeIntegralInRange<int32_t>(0, 4);
  sp<MediaMuxer> mMuxer(new MediaMuxer(fd, format));

  while (fdp.remaining_bytes() > 0) {
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
      case 0: {
        // For some reason it only likes mp4s here...
        if (format == 1 || format == 4) break;

        sp<AMessage> a_format(new AMessage);
        createMessage(a_format.get(), &fdp);
        mMuxer->addTrack(a_format);
        break;
      }
      case 1: {
        mMuxer->start();
        break;
      }
      case 2: {
        int degrees = fdp.ConsumeIntegral<int>();
        mMuxer->setOrientationHint(degrees);
        break;
      }
      case 3: {
        int latitude = fdp.ConsumeIntegral<int>();
        int longitude = fdp.ConsumeIntegral<int>();
        mMuxer->setLocation(latitude, longitude);
        break;
      }
      case 4: {
        mMuxer->stop();
        break;
      }
      case 5: {
        // Cap size to 1024 to limit max amount allocated.
        size_t buf_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
        sp<ABuffer> a_buffer(new ABuffer(buf_size));

        size_t trackIndex = fdp.ConsumeIntegral<size_t>();
        int64_t timeUs = fdp.ConsumeIntegral<int64_t>();
        uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
        mMuxer->writeSampleData(a_buffer, trackIndex, timeUs, flags);
      }
    }
  }

  return 0;
}
}  // namespace android
