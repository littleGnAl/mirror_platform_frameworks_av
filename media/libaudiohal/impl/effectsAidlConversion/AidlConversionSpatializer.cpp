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

#include <aidl/android/hardware/audio/effect/DefaultExtension.h>
#include <aidl/android/hardware/audio/effect/VendorExtension.h>
#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio_effects/effect_spatializer.h>

#include <utils/Log.h>

#include "AidlConversionSpatializer.h"

namespace android {
namespace effect {

using ::aidl::android::getParameterSpecificField;
using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::DefaultExtension;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::Spatializer;
using ::aidl::android::hardware::audio::effect::VendorExtension;
using ::aidl::android::media::audio::common::HeadTracking;
using ::aidl::android::media::audio::common::Spatialization;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

#define MAKE_SPATIALIZER_PARAMETER(_field, _value) \
    MAKE_SPECIFIC_PARAMETER(Spatializer, spatializer, _field, _value)

#define MAKE_SPATIALIZER_PARAMETER_ID(_field) \
    MAKE_SPECIFIC_PARAMETER_ID(Spatializer, spatializerTag, (_field))

status_t AidlConversionSpatializer::setParameter(EffectParamReader& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t) /* parameter size */,
                                      sizeof(uint16_t) /* value size */) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    Parameter aidlParam;
    if (mIsParameterSupported) {
        switch (type) {
            case SPATIALIZER_PARAM_LEVEL: {
                Spatialization::Level level;
                param.readFromValue(&level);
                aidlParam = MAKE_SPATIALIZER_PARAMETER(spatializationLevel, level);
                break;
            }
            case SPATIALIZER_PARAM_HEADTRACKING_MODE: {
                HeadTracking::Mode mode;
                param.readFromValue(&mode);
                aidlParam = MAKE_SPATIALIZER_PARAMETER(headTrackingMode, mode);
                break;
            }
            case SPATIALIZER_PARAM_HEAD_TO_STAGE: {
                std::array<float, 6> headToStage = {};
                param.readFromValue(headToStage.data());
                HeadTracking::SensorData sensorData =
                        HeadTracking::SensorData::make<HeadTracking::SensorData::headToStage>(
                                headToStage);
                aidlParam = MAKE_SPATIALIZER_PARAMETER(headTrackingSensorData, sensorData);
                break;
            }
            case SPATIALIZER_PARAM_HEADTRACKING_CONNECTION: {
                break;
            }
            default: {
                aidlParam = VALUE_OR_RETURN_STATUS(
                        ::aidl::android::legacy2aidl_EffectParameterReader_Parameter(param));
                break;
            }
        }
    } else {
        // Spatializer parameter is not supported by HAL, send parameters with vendorExtension
        aidlParam = VALUE_OR_RETURN_STATUS(
                ::aidl::android::legacy2aidl_EffectParameterReader_Parameter(param));
    }
    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionSpatializer::getParameter(EffectParamWriter& param) {
    uint32_t type = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t) /* parameter size */,
                                      sizeof(uint16_t) /* value size */) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }

    Parameter::Id id;
    Parameter aidlParam;
    if (mIsParameterSupported) {
        switch (type) {
            case SPATIALIZER_PARAM_SUPPORTED_LEVELS: {
                // get supported levels from effect descriptor capability
                break;
            }
            case SPATIALIZER_PARAM_LEVEL: {
                id = MAKE_SPATIALIZER_PARAMETER_ID(Spatializer::spatializationLevel);
                break;
            }
            case SPATIALIZER_PARAM_HEADTRACKING_SUPPORTED: {
                // get supported levels from effect descriptor capability
                break;
            }
            case SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS: {
                // get supported channel layout from effect descriptor capability
                break;
            }
            case SPATIALIZER_PARAM_SUPPORTED_SPATIALIZATION_MODES: {
                // get supported mode from effect descriptor capability
                id = UNION_MAKE(Parameter::Id, spatializerTag, Spatializer::spatializationLevel);
                break;
            }
            case SPATIALIZER_PARAM_HEADTRACKING_MODE: {
                break;
            }
            case SPATIALIZER_PARAM_SUPPORTED_HEADTRACKING_CONNECTION: {
                // get supported mode from effect descriptor capability
                break;
            }
            case SPATIALIZER_PARAM_HEADTRACKING_CONNECTION: {
                id = MAKE_SPATIALIZER_PARAMETER_ID(Spatializer::headTrackingConnectionMode);
                break;
            }
            default: {
                VENDOR_EXTENSION_GET_AND_RETURN(Spatializer, spatializer, param);
            }
        }
    } else {
        VENDOR_EXTENSION_GET_AND_RETURN(Spatializer, spatializer, param);
    }

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
    // copy the AIDL extension data back to effect_param_t
    return VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Parameter_EffectParameterWriter(aidlParam, param));
}

} // namespace effect
} // namespace android
