/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <string.h>

#include <string>

#include <media/AudioAttributes.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioEffect.h>
#include <media/AudioSystem.h>
#include <utils/Errors.h>

#include <gtest/gtest.h>
#include "policy.h"

#include "AudioTestParams.hpp"

static const std::vector<DeviceConnectionTestParams> gDynamicAddressInputDeviceTestParams = {
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDynamicAddressInputDeviceTestParams()
{
    return gDynamicAddressInputDeviceTestParams;
}

static const std::vector<DeviceConnectionTestParams> gDynamicAddressOutputDeviceTestParam = {
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDynamicAddressOutputDeviceTestParams()
{
    return gDynamicAddressOutputDeviceTestParam;
}

static const std::vector<DeviceConnectionTestParams> gDeclaredAddressInputDeviceTestParams = {
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDeclaredAddressInputDeviceTestParams()
{
    return gDeclaredAddressInputDeviceTestParams;
}

static const std::vector<DeviceConnectionTestParams> gDeclaredAddressOutputDeviceTestParams = {
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDeclaredAddressOutputDeviceTestParams()
{
    return gDeclaredAddressOutputDeviceTestParams;
}

static const std::vector<AudioProductStrategyTestParams> gAudioProductStrategyTestParams = {
    {"STRATEGY_ENFORCED_AUDIBLE", AUDIO_DEVICE_OUT_SPEAKER, ""},
    {"STRATEGY_PHONE", AUDIO_DEVICE_OUT_EARPIECE, ""},
    {"STRATEGY_SONIFICATION", AUDIO_DEVICE_OUT_SPEAKER_SAFE, ""},
    {"STRATEGY_ACCESSIBILITY", AUDIO_DEVICE_OUT_SPEAKER, ""},
    {"STRATEGY_SONIFICATION_RESPECTFUL", AUDIO_DEVICE_OUT_SPEAKER_SAFE, ""},
    {"STRATEGY_MEDIA", AUDIO_DEVICE_OUT_SPEAKER, ""},
    {"STRATEGY_DTMF", AUDIO_DEVICE_OUT_SPEAKER, ""},
    {"STRATEGY_TRANSMITTED_THROUGH_SPEAKER", AUDIO_DEVICE_OUT_SPEAKER, ""},
// It is prohibited by the framework to play using private stream types. As these
// strategies do not have valid attributes, do not test the following:
//    {"STRATEGY_REROUTING", AUDIO_DEVICE_OUT_SPEAKER, ""},
//    {"STRATEGY_PATCH", AUDIO_DEVICE_OUT_SPEAKER, ""},
};

/*static*/
std::vector<AudioProductStrategyTestParams> AudioTestParams::getAudioProductStrategyTestParams()
{
    return gAudioProductStrategyTestParams;
}

static const std::vector<ConcurrencyTestParams> gConcurrencyTestParamsTestParams = {
};

/*static*/
std::vector<ConcurrencyTestParams> AudioTestParams::getConcurrencyTestParamsTestParams()
{
    return gConcurrencyTestParamsTestParams;
}

static const std::vector<AttributeVolumeTestParams> gUnknownAttributesVolumeTestParams = {
    {{AUDIO_CONTENT_TYPE_MUSIC, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""},
     "music"},
    {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""},
     "music"}
};

/*static*/
std::vector<AttributeVolumeTestParams> AudioTestParams::getUnknownAttributesVolumeTestParams()
{
    return gUnknownAttributesVolumeTestParams;
}
