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

  private:
    void emitError(const char* funcName, const char* description) {
        ALOGE("%s %p %s: %s (from rpc)", mClassName.c_str(), this, funcName, description);
    }
};

}  // namespace android
