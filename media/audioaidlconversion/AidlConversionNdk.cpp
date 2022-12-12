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

#define LOG_TAG "AidlConversionNdk"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// AIDL NDK backend to legacy audio data structure conversion utilities.

namespace aidl {
namespace android {

using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Flags;

using ::android::BAD_VALUE;
using ::android::OK;
using ::android::base::unexpected;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Converters

ConversionResult<uint32_t> aidl2legacy_Flags_uint32(Flags aidl) {
    uint32_t legacy = 0;
    switch (aidl.type) {
        case Flags::Type::INSERT:
            legacy |= EFFECT_FLAG_TYPE_INSERT;
            break;
        case Flags::Type::AUXILIARY:
            legacy |= EFFECT_FLAG_TYPE_AUXILIARY;
            break;
        case Flags::Type::REPLACE:
            legacy |= EFFECT_FLAG_TYPE_REPLACE;
            break;
        case Flags::Type::PRE_PROC:
            legacy |= EFFECT_FLAG_TYPE_PRE_PROC;
            break;
        case Flags::Type::POST_PROC:
            legacy |= EFFECT_FLAG_TYPE_POST_PROC;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    switch (aidl.insert) {
        case Flags::Insert::ANY:
            legacy |= EFFECT_FLAG_INSERT_ANY;
            break;
        case Flags::Insert::FIRST:
            legacy |= EFFECT_FLAG_INSERT_FIRST;
            break;
        case Flags::Insert::LAST:
            legacy |= EFFECT_FLAG_INSERT_LAST;
            break;
        case Flags::Insert::EXCLUSIVE:
            legacy |= EFFECT_FLAG_INSERT_EXCLUSIVE;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    switch (aidl.volume) {
        case Flags::Volume::NONE:
            break;
        case Flags::Volume::CTRL:
            legacy |= EFFECT_FLAG_VOLUME_CTRL;
            break;
        case Flags::Volume::IND:
            legacy |= EFFECT_FLAG_VOLUME_IND;
            break;
        case Flags::Volume::MONITOR:
            legacy |= EFFECT_FLAG_VOLUME_MONITOR;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    switch (aidl.hwAcceleratorMode) {
        case Flags::HardwareAccelerator::NONE:
            break;
        case Flags::HardwareAccelerator::SIMPLE:
            legacy |= EFFECT_FLAG_HW_ACC_SIMPLE;
            break;
        case Flags::HardwareAccelerator::TUNNEL:
            legacy |= EFFECT_FLAG_HW_ACC_TUNNEL;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    if (aidl.offloadIndication) {
        legacy |= EFFECT_FLAG_OFFLOAD_SUPPORTED;
    }
    if (aidl.deviceIndication) {
        legacy |= EFFECT_FLAG_DEVICE_IND;
    }
    if (aidl.audioModeIndication) {
        legacy |= EFFECT_FLAG_AUDIO_MODE_IND;
    }
    if (aidl.audioSourceIndication) {
        legacy |= EFFECT_FLAG_AUDIO_SOURCE_IND;
    }
    if (aidl.noProcessing) {
        legacy |= EFFECT_FLAG_NO_PROCESS;
    }
    return legacy;
}

ConversionResult<Flags> legacy2aidl_uint32_Flags(const uint32_t legacy) {
    Flags aidl;
    switch (legacy & EFFECT_FLAG_TYPE_MASK) {
        case EFFECT_FLAG_TYPE_INSERT:
            aidl.type = Flags::Type::INSERT;
            break;
        case EFFECT_FLAG_TYPE_AUXILIARY:
            aidl.type = Flags::Type::AUXILIARY;
            break;
        case EFFECT_FLAG_TYPE_REPLACE:
            aidl.type = Flags::Type::REPLACE;
            break;
        case EFFECT_FLAG_TYPE_PRE_PROC:
            aidl.type = Flags::Type::PRE_PROC;
            break;
        case EFFECT_FLAG_TYPE_POST_PROC:
            aidl.type = Flags::Type::POST_PROC;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    switch (legacy & EFFECT_FLAG_INSERT_MASK) {
        case EFFECT_FLAG_INSERT_ANY:
            aidl.insert = Flags::Insert::ANY;
            break;
        case EFFECT_FLAG_INSERT_FIRST:
            aidl.insert = Flags::Insert::FIRST;
            break;
        case EFFECT_FLAG_INSERT_LAST:
            aidl.insert = Flags::Insert::LAST;
            break;
        case EFFECT_FLAG_INSERT_EXCLUSIVE:
            aidl.insert = Flags::Insert::EXCLUSIVE;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    switch (legacy & EFFECT_FLAG_VOLUME_MASK) {
        case EFFECT_FLAG_VOLUME_IND:
            aidl.volume = Flags::Volume::IND;
            break;
        case EFFECT_FLAG_VOLUME_MONITOR:
            aidl.volume = Flags::Volume::MONITOR;
            break;
        case EFFECT_FLAG_VOLUME_NONE:
            aidl.volume = Flags::Volume::NONE;
            break;
        default:
            return unexpected(BAD_VALUE);
    }

    aidl.offloadIndication = (legacy & EFFECT_FLAG_OFFLOAD_SUPPORTED);
    aidl.deviceIndication = (legacy & EFFECT_FLAG_DEVICE_IND);
    aidl.audioModeIndication = (legacy & EFFECT_FLAG_AUDIO_MODE_IND);
    aidl.audioSourceIndication = (legacy & EFFECT_FLAG_AUDIO_SOURCE_IND);
    aidl.noProcessing = (legacy & EFFECT_FLAG_NO_PROCESS);
    return aidl;
}

ConversionResult<effect_descriptor_t> aidl2legacy_Descriptor_effect_descriptor(
        const ::aidl::android::hardware::audio::effect::Descriptor& aidl) {
    effect_descriptor_t legacy;
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.common.id.type));
    legacy.uuid = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.common.id.uuid));
    // legacy descriptor doesn't have proxy information
    // proxy = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.proxy));
    legacy.apiVersion = EFFECT_CONTROL_API_VERSION;
    // TODO: need a method to convert flags
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_Flags_uint32(aidl.common.flags));
    legacy.cpuLoad = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.cpuLoad));
    legacy.memoryUsage = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.memoryUsage));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.common.name, legacy.name, sizeof(legacy.name)));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.common.implementor, legacy.implementor,
                                        sizeof(legacy.implementor)));
    return legacy;
}

ConversionResult<::aidl::android::hardware::audio::effect::Descriptor>
legacy2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& legacy) {
    Descriptor aidl;
    aidl.common.id.type = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.type));
    aidl.common.id.uuid = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.uuid));
    // legacy descriptor doesn't have proxy information
    // aidl.common.id.proxy
    aidl.common.flags = VALUE_OR_RETURN(legacy2aidl_uint32_Flags(legacy.flags));
    aidl.common.cpuLoad = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.cpuLoad));
    aidl.common.memoryUsage = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.memoryUsage));
    aidl.common.name = VALUE_OR_RETURN(legacy2aidl_string(legacy.name, sizeof(legacy.name)));
    aidl.common.implementor =
            VALUE_OR_RETURN(legacy2aidl_string(legacy.implementor, sizeof(legacy.implementor)));
    return aidl;
}

}  // namespace android
}  // aidl
