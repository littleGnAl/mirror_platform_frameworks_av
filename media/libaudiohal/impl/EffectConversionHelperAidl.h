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

#include <utils/Log.h>

#include "ConversionHelperAidl.h"
#include <aidl/android/hardware/audio/effect/Descriptor.h>
#include <aidl/android/hardware/audio/effect/Flags.h>
#include <hardware/audio_effect.h>
#include <system/audio_effect.h>

namespace android {

class EffectConversionHelperAidl : public ConversionHelperAidl {
  public:
    explicit EffectConversionHelperAidl(std::string_view className)
        : ConversionHelperAidl(className) {}

    ConversionResult<uint32_t> aidl2hal_flags(
            const ::aidl::android::hardware::audio::effect::Flags aidl);
    ConversionResult<::aidl::android::hardware::audio::effect::Flags> hal2aidl_flags(
            const uint32_t hal);

    ConversionResult<effect_descriptor_t> aidl2hal_Descriptor_effect_descriptor(
            const ::aidl::android::hardware::audio::effect::Descriptor& aidl);
    ConversionResult<::aidl::android::hardware::audio::effect::Descriptor>
    hal2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& hal);

  private:

};

}  // namespace android
