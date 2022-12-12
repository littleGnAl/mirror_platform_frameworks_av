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

#pragma once

#include <functional>

#include <aidl/android/media/audio/common/AudioUuid.h>
#include <binder/Status.h>
#include <error/Result.h>
#include <media/AidlConversionUtil.h>
#include <system/audio.h>

using ::aidl::android::media::audio::common::AudioUuid;
using android::base::unexpected;

namespace android {

class ConversionHelperAidl {
  public:
    const std::string mClassName;

    ConversionHelperAidl(std::string_view className) : mClassName(className) {}

    const std::string& getClassName() const { return mClassName; }

    status_t aidl2hal_string(std::string_view aidl, char* dest, size_t maxSize) {
        if (aidl.size() > maxSize - 1) {
            return BAD_VALUE;
        }
        aidl.copy(dest, aidl.size());
        dest[aidl.size()] = '\0';
        return OK;
    }

    ConversionResult<std::string> hal2aidl_string(const char* hal, size_t maxSize) {
        if (hal == nullptr) {
            return unexpected(BAD_VALUE);
        }
        if (strnlen(hal, maxSize) == maxSize) {
            // No null-terminator.
            return unexpected(BAD_VALUE);
        }
        return std::string(hal);
    }

    ConversionResult<audio_uuid_t> aidl2hal_AudioUuid_audio_uuid_t(const AudioUuid& aidl) {
        audio_uuid_t hal;
        hal.timeLow = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.timeLow));
        hal.timeMid = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.timeMid));
        hal.timeHiAndVersion = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.timeHiAndVersion));
        hal.clockSeq = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.clockSeq));
        if (aidl.node.size() != std::size(hal.node)) {
            return unexpected(BAD_VALUE);
        }
        std::copy(aidl.node.begin(), aidl.node.end(), hal.node);
        return hal;
    }

    ConversionResult<AudioUuid> hal2aidl_audio_uuid_t_AudioUuid(const audio_uuid_t& hal) {
        AudioUuid aidl;
        aidl.timeLow = VALUE_OR_RETURN(convertReinterpret<int32_t>(hal.timeLow));
        aidl.timeMid = VALUE_OR_RETURN(convertIntegral<int32_t>(hal.timeMid));
        aidl.timeHiAndVersion = VALUE_OR_RETURN(convertIntegral<int32_t>(hal.timeHiAndVersion));
        aidl.clockSeq = VALUE_OR_RETURN(convertIntegral<int32_t>(hal.clockSeq));
        std::copy(hal.node, hal.node + std::size(hal.node), std::back_inserter(aidl.node));
        return aidl;
    }

  private:
    void emitError(const char* funcName, const char* description) {
        ALOGE("%s %p %s: %s (from rpc)", mClassName.c_str(), this, funcName, description);
    }
};

}  // namespace android
