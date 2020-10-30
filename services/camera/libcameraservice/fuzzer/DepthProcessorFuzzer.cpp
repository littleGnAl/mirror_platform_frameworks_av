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

#include <vector>

#include "common/DepthPhotoProcessor.h"

using namespace android;
using namespace android::camera3;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    DepthPhotoInputFrame inputFrame;
    // Worst case both depth and confidence maps have the same size as the main color image.
    inputFrame.mMaxJpegSize = inputFrame.mMainJpegSize * 3;

    std::vector<uint8_t> depthPhotoBuffer(inputFrame.mMaxJpegSize);
    size_t actualDepthPhotoSize = 0;

    inputFrame.mMainJpegBuffer = reinterpret_cast<const char*> (data);
    inputFrame.mMainJpegSize = size;
    processDepthPhotoFrame(
        inputFrame,
        depthPhotoBuffer.size(),
        depthPhotoBuffer.data(),
        &actualDepthPhotoSize);

  return 0;
}
