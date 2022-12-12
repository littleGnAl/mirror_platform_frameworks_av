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

#define LOG_TAG "EffectHalAidl"
#include <utils/Log.h>

#include <media/AidlConversionUtil.h>

#include "EffectConversionHelperAidl.h"

using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::Flags;

namespace android {

// static
ConversionResult<uint32_t> EffectConversionHelperAidl::aidl2hal_flags(const Flags aidl) {
    uint32_t hal = 0;
    switch (aidl.type) {
        case Flags::Type::INSERT:
            hal |= EFFECT_FLAG_TYPE_INSERT;
            break;
        case Flags::Type::AUXILIARY:
            hal |= EFFECT_FLAG_TYPE_AUXILIARY;
            break;
        case Flags::Type::REPLACE:
            hal |= EFFECT_FLAG_TYPE_REPLACE;
            break;
        case Flags::Type::PRE_PROC:
            hal |= EFFECT_FLAG_TYPE_PRE_PROC;
            break;
        case Flags::Type::POST_PROC:
            hal |= EFFECT_FLAG_TYPE_POST_PROC;
            break;
        default:
            break;
    }

    switch (aidl.insert) {
        case Flags::Insert::ANY:
            hal |= EFFECT_FLAG_INSERT_ANY;
            break;
        case Flags::Insert::FIRST:
            hal |= EFFECT_FLAG_INSERT_FIRST;
            break;
        case Flags::Insert::LAST:
            hal |= EFFECT_FLAG_INSERT_LAST;
            break;
        case Flags::Insert::EXCLUSIVE:
            hal |= EFFECT_FLAG_INSERT_EXCLUSIVE;
            break;
        default:
            break;
    }

    switch (aidl.volume) {
        case Flags::Volume::CTRL:
            hal |= EFFECT_FLAG_VOLUME_CTRL;
            break;
        case Flags::Volume::IND:
            hal |= EFFECT_FLAG_VOLUME_IND;
            break;
        case Flags::Volume::MONITOR:
            hal |= EFFECT_FLAG_VOLUME_MONITOR;
            break;
        default:
            break;
    }

    switch (aidl.hwAcceleratorMode) {
        case Flags::HardwareAccelerator::SIMPLE:
            hal |= EFFECT_FLAG_HW_ACC_SIMPLE;
            break;
        case Flags::HardwareAccelerator::TUNNEL:
            hal |= EFFECT_FLAG_HW_ACC_TUNNEL;
            break;
        default:
            break;
    }

    if (aidl.offloadIndication) {
        hal |= EFFECT_FLAG_OFFLOAD_SUPPORTED;
    }
    if (aidl.deviceIndication) {
        hal |= EFFECT_FLAG_DEVICE_IND;
    }
    if (aidl.audioModeIndication) {
        hal |= EFFECT_FLAG_AUDIO_MODE_IND;
    }
    if (aidl.audioSourceIndication) {
        hal |= EFFECT_FLAG_AUDIO_SOURCE_IND;
    }
    if (aidl.noProcessing) {
        hal |= EFFECT_FLAG_NO_PROCESS;
    }
    return hal;
}

ConversionResult<Flags> EffectConversionHelperAidl::hal2aidl_flags(const uint32_t hal) {
    Flags aidl;
    switch (hal & EFFECT_FLAG_TYPE_MASK) {
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
            break;
    }

    switch (hal & EFFECT_FLAG_INSERT_MASK) {
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
            break;
    }

    switch (hal & EFFECT_FLAG_VOLUME_MASK) {
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
            break;
    }

    aidl.offloadIndication = (hal & EFFECT_FLAG_OFFLOAD_SUPPORTED);
    aidl.deviceIndication = (hal & EFFECT_FLAG_DEVICE_IND);
    aidl.audioModeIndication = (hal & EFFECT_FLAG_AUDIO_MODE_IND);
    aidl.audioSourceIndication = (hal & EFFECT_FLAG_AUDIO_SOURCE_IND);
    aidl.noProcessing = (hal & EFFECT_FLAG_NO_PROCESS);
    return aidl;
}

ConversionResult<effect_descriptor_t>
EffectConversionHelperAidl::aidl2hal_Descriptor_effect_descriptor(const Descriptor& aidl) {
    effect_descriptor_t hal;
    hal.type = VALUE_OR_RETURN(aidl2hal_AudioUuid_audio_uuid_t(aidl.common.id.type));
    hal.uuid = VALUE_OR_RETURN(aidl2hal_AudioUuid_audio_uuid_t(aidl.common.id.uuid));
    // only libaudiohal effectProxy cares about the proxy information.
    // proxy = VALUE_OR_RETURN(aidl2hal_AudioUuid_audio_uuid_t(aidl.proxy));
    hal.apiVersion = EFFECT_CONTROL_API_VERSION;
    // TODO: need a method to convert flags
    hal.flags = VALUE_OR_RETURN(aidl2hal_flags(aidl.common.flags));
    hal.cpuLoad = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.cpuLoad));
    hal.memoryUsage = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.common.memoryUsage));
    RETURN_IF_ERROR(aidl2hal_string(aidl.common.name, hal.name, sizeof(hal.name)));
    RETURN_IF_ERROR(aidl2hal_string(aidl.common.implementor, hal.implementor,
                                        sizeof(hal.implementor)));
    return hal;
}

ConversionResult<Descriptor>
EffectConversionHelperAidl::hal2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& hal) {
    Descriptor aidl;
    aidl.common.id.type = VALUE_OR_RETURN(hal2aidl_audio_uuid_t_AudioUuid(hal.type));
    aidl.common.id.uuid = VALUE_OR_RETURN(hal2aidl_audio_uuid_t_AudioUuid(hal.uuid));
    // only libaudiohal effectProxy cares about the proxy information.
    // aidl.common.id.proxy
    aidl.common.flags = VALUE_OR_RETURN(hal2aidl_flags(hal.flags));
    aidl.common.cpuLoad = VALUE_OR_RETURN(convertIntegral<int32_t>(hal.cpuLoad));
    aidl.common.memoryUsage = VALUE_OR_RETURN(convertIntegral<int32_t>(hal.memoryUsage));
    aidl.common.name = VALUE_OR_RETURN(hal2aidl_string(hal.name, sizeof(hal.name)));
    aidl.common.implementor =
            VALUE_OR_RETURN(hal2aidl_string(hal.implementor, sizeof(hal.implementor)));
    return aidl;
}
}  // namespace android
