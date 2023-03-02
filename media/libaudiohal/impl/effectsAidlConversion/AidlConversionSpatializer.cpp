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

#include <cstdint>
#include <cstring>
#include <optional>
#define LOG_TAG "AidlConversionSpatializer"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effects/effect_spatializer.h>

#include <utils/Log.h>

#include "AidlConversionSpatializer.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionSpatializer::setParameter(EffectParamReader& param) {
    Parameter aidlParam = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_EffectParameterReader_ParameterExtension(param));
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionSpatializer::getParameter(EffectParamWriter& param) {
    Parameter aidlParam;
    Parameter::Id id = UNION_MAKE(Parameter::Id, vendorEffectTag, 0 /* no tag */);
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    const auto& extBytes = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_ParameterExtension_vector_uint8(aidlParam));
    if (param.getValueSize() < extBytes.size()) {
        ALOGE("%s extension return data %zu exceed vsize %zu", __func__, extBytes.size(),
              param.getValueSize());
        param.setStatus(BAD_VALUE);
        return BAD_VALUE;
    }
    return param.writeToValue(extBytes.data(), extBytes.size());
}

} // namespace effect
} // namespace android
