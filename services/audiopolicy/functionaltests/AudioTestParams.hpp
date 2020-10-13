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

#pragma once

#include <system/audio.h>
#include <system/audio_policy.h>
#include <vector>

using DeviceConnectionTestParams =
    std::tuple<const audio_devices_t /*type*/, const std::string /*name*/,
               const std::string /*address*/, audio_policy_dev_state_t, audio_mode_t>;

using AudioProductStrategyTestParams =
    std::tuple<const std::string /*strategyName*/,
               const audio_devices_t /*expectedDeviceType*/,
               const std::string /*expectedDeviceAddress*/>;

using ConcurrencyTestParams =
    std::tuple<const std::string /*strategyName1*/, const audio_devices_t /*expectedDeviceType1*/,
               const std::string /*expectedDeviceAddress1*/, const std::string /*strategyName2*/,
               const audio_devices_t /*expectedDeviceType2*/,
               const std::string /*expectedDeviceAddress2*/>;

using AttributeVolumeTestParams =
    std::tuple<const audio_attributes_t /*attributes injected*/, std::string /*expectedGroup*/>;

class AudioTestParams
{
public:
    static std::vector<DeviceConnectionTestParams> getDynamicAddressInputDeviceTestParams();

    static std::vector<DeviceConnectionTestParams> getDynamicAddressOutputDeviceTestParams();

    static std::vector<DeviceConnectionTestParams> getDeclaredAddressInputDeviceTestParams();

    static std::vector<DeviceConnectionTestParams> getDeclaredAddressOutputDeviceTestParams();

    static std::vector<AudioProductStrategyTestParams> getAudioProductStrategyTestParams();

    static std::vector<ConcurrencyTestParams> getConcurrencyTestParamsTestParams();

    static std::vector<AttributeVolumeTestParams> getUnknownAttributesVolumeTestParams();
};


