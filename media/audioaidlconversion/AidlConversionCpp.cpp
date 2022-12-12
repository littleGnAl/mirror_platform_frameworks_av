/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <utility>

#define LOG_TAG "AidlConversionCpp"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/AidlConversionCpp.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL CPP backend to legacy audio data structure conversion utilities.

namespace android {
namespace media {

////////////////////////////////////////////////////////////////////////////////////////////////////
// Converters

ConversionResult<media::MicrophoneInfo>
aidl2legacy_MicrophoneInfo(const media::MicrophoneInfoData& aidl) {
    media::MicrophoneInfo legacy;
    RETURN_IF_ERROR(legacy.readFromParcelable(aidl));
    return legacy;
}

ConversionResult<media::MicrophoneInfoData>
legacy2aidl_MicrophoneInfo(const media::MicrophoneInfo& legacy) {
    media::MicrophoneInfoData aidl;
    RETURN_IF_ERROR(legacy.writeToParcelable(&aidl));
    return aidl;
}

}  // namespace media
}  // namespace android
