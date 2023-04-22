/*
 * Copyright (C) 2023 The Android Open Source Project
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

/**
 * Conversions between the NDK and CPP backends for common types.
 */
#include <aidl/android/media/audio/common/AudioFormatDescription.h>
#include <aidl/android/media/audio/common/AudioHalEngineConfig.h>
#include <aidl/android/media/audio/common/AudioMMapPolicyInfo.h>
#include <aidl/android/media/audio/common/AudioMMapPolicyType.h>
#include <aidl/android/media/audio/common/AudioPort.h>
#include <android/media/audio/common/AudioFormatDescription.h>
#include <android/media/audio/common/AudioHalEngineConfig.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <android/media/audio/common/AudioPort.h>
#include <media/AidlConversionUtil.h>

namespace android {

ConversionResult<::aidl::android::media::audio::common::AudioFormatDescription>
cpp2ndk_AudioFormatDescription(const media::audio::common::AudioFormatDescription& cpp);
ConversionResult<media::audio::common::AudioFormatDescription>
ndk2cpp_AudioFormatDescription(
        const ::aidl::android::media::audio::common::AudioFormatDescription& ndk);

ConversionResult<::aidl::android::media::audio::common::AudioHalEngineConfig>
cpp2ndk_AudioHalEngineConfig(const media::audio::common::AudioHalEngineConfig& cpp);
ConversionResult<media::audio::common::AudioHalEngineConfig>
ndk2cpp_AudioHalEngineConfig(
        const ::aidl::android::media::audio::common::AudioHalEngineConfig& ndk);

ConversionResult<::aidl::android::media::audio::common::AudioMMapPolicyInfo>
cpp2ndk_AudioMMapPolicyInfo(const media::audio::common::AudioMMapPolicyInfo& cpp);
ConversionResult<media::audio::common::AudioMMapPolicyInfo>
ndk2cpp_AudioMMapPolicyInfo(const ::aidl::android::media::audio::common::AudioMMapPolicyInfo& ndk);

ConversionResult<::aidl::android::media::audio::common::AudioMMapPolicyType>
cpp2ndk_AudioMMapPolicyType(const media::audio::common::AudioMMapPolicyType& cpp);
ConversionResult<media::audio::common::AudioMMapPolicyType>
ndk2cpp_AudioMMapPolicyType(const ::aidl::android::media::audio::common::AudioMMapPolicyType& ndk);

ConversionResult<::aidl::android::media::audio::common::AudioPort>
cpp2ndk_AudioPort(const media::audio::common::AudioPort& cpp);
ConversionResult<media::audio::common::AudioPort>
ndk2cpp_AudioPort(const ::aidl::android::media::audio::common::AudioPort& ndk);

}  // namespace android
