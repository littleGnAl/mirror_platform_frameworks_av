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
#define LOG_TAG "AidlConversionAgc2"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <media/AidlConversionNdk.h>
#include <media/AidlConversionEffect.h>
#include <media/audiohal/AudioEffectUuid.h>
#include <system/audio_effects/effect_agc2.h>

#include <utils/Log.h>

#include "AidlConversionAgc2.h"

namespace android {
namespace effect {

using ::aidl::android::aidl_utils::statusTFromBinderStatus;
using ::aidl::android::hardware::audio::effect::AutomaticGainControl;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::android::status_t;
using utils::EffectParamReader;
using utils::EffectParamWriter;

status_t AidlConversionAgc2::setParameter(EffectParamReader& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type) || OK != param.readFromValue(&value)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            aidlParam = VALUE_OR_RETURN_STATUS(
                    aidl::android::legacy2aidl_uint32_fixedDigitalGain_Parameter_agc(value));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            if (value != kDefaultLevelEstimator) {
                // only RMS is supported
                return BAD_VALUE;
            }
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            if (value != kDefaultSaturationMargin) {
                // extra_staturation_margin_db is no longer configurable in webrtc
                return BAD_VALUE;
            }
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return statusTFromBinderStatus(mEffect->setParameter(aidlParam));
}

status_t AidlConversionAgc2::getParameter(EffectParamWriter& param) {
    uint32_t type = 0, value = 0;
    if (!param.validateParamValueSize(sizeof(uint32_t), sizeof(uint32_t)) ||
        OK != param.readFromParameter(&type)) {
        ALOGE("%s invalid param %s", __func__, param.toString().c_str());
        return BAD_VALUE;
    }
    Parameter aidlParam;
    switch (type) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN: {
            Parameter::Id id =
                    MAKE_SPECIFIC_PARAMETER_ID(AutomaticGainControl, automaticGainControlTag,
                                               AutomaticGainControl::fixedDigitalGainMb);
            RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mEffect->getParameter(id, &aidlParam)));
            value = VALUE_OR_RETURN_STATUS(
                    aidl::android::aidl2legacy_Parameter_agc_uint32_fixedDigitalGain(aidlParam));
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR: {
            value = kDefaultLevelEstimator;
            break;
        }
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN: {
            value = kDefaultSaturationMargin;
            break;
        }
        default: {
            ALOGW("%s unknown param %s", __func__, param.toString().c_str());
            return BAD_VALUE;
        }
    }

    return param.writeToValue(&value);
}

} // namespace effect
} // namespace android
