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

#include <media/AudioSystem.h>
#include <media/AudioEffect.h>
#include <utils/Errors.h>

#include <gtest/gtest.h>

#include "AudioTestParams.hpp"

static const std::vector<DeviceConnectionTestParams> gDynamicAddressInputDeviceTestParams = {
    {AUDIO_DEVICE_IN_HDMI, "my_dummy_mic_hdmi", "my_dummy_mic_hdmi",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_HDMI, "my_dummy_mic_hdmi", "my_dummy_mic_hdmi",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_HDMI, "my_dummy_mic_hdmi", "my_dummy_mic_hdmi",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_HDMI, "my_dummy_mic_hdmi", "my_dummy_mic_hdmi",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL}
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDynamicAddressInputDeviceTestParams()
{
    return gDynamicAddressInputDeviceTestParams;
}

static const std::vector<DeviceConnectionTestParams> gDynamicAddressOutputDeviceTestParam = {
    {AUDIO_DEVICE_OUT_HDMI, "my_dummy_hdmi_out", "my_dummy_hdmi_out",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_HDMI, "my_dummy_hdmi_out", "my_dummy_hdmi_out",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_HDMI, "my_dummy_hdmi_out", "my_dummy_hdmi_out",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_HDMI, "my_dummy_hdmi_out", "my_dummy_hdmi_out",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL}
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDynamicAddressOutputDeviceTestParams()
{
    return gDynamicAddressOutputDeviceTestParam;
}

static const std::vector<DeviceConnectionTestParams> gDeclaredAddressInputDeviceTestParams = {
    {AUDIO_DEVICE_IN_TELEPHONY_RX, "hfp_client_in", "hfp_client_in",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_TELEPHONY_RX, "hfp_client_in", "hfp_client_in",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_TELEPHONY_RX, "hfp_client_in", "hfp_client_in",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_IN_TELEPHONY_RX, "hfp_client_in", "hfp_client_in",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL}
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDeclaredAddressInputDeviceTestParams()
{
    return gDeclaredAddressInputDeviceTestParams;
}

static const std::vector<DeviceConnectionTestParams> gDeclaredAddressOutputDeviceTestParams = {
    {AUDIO_DEVICE_OUT_TELEPHONY_TX, "hfp_client_out", "hfp_client_out",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_TELEPHONY_TX, "hfp_client_out", "hfp_client_out",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_TELEPHONY_TX, "hfp_client_out", "hfp_client_out",
     AUDIO_POLICY_DEVICE_STATE_AVAILABLE, AUDIO_MODE_NORMAL},
    {AUDIO_DEVICE_OUT_TELEPHONY_TX, "hfp_client_out", "hfp_client_out",
     AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, AUDIO_MODE_NORMAL}
};

/*static*/
std::vector<DeviceConnectionTestParams> AudioTestParams::getDeclaredAddressOutputDeviceTestParams()
{
    return gDeclaredAddressOutputDeviceTestParams;
}

static const std::vector<AudioProductStrategyTestParams> gAudioProductStrategyTestParams = {
    {"oem_traffic_anouncement", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    {"oem_strategy_1", AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK"},
    {"radio", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    {"ext_audio_source", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    {"voice_command", AUDIO_DEVICE_OUT_BUS, "BUS03_PHONE"},
    {"safety_alert", AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    {"music", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    {"nav_guidance", AUDIO_DEVICE_OUT_BUS, "BUS02_NAV_GUIDANCE"},
    {"voice_call", AUDIO_DEVICE_OUT_BUS, "BUS03_PHONE"},
    {"alarm", AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    {"ring", AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    {"notification", AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    {"system", AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    {"tts", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    // It is prohibited by the framework to play using private stream types. As these
    // strategies do not have valid attributes, do not test the following:
    //    {"rerouting", AUDIO_DEVICE_OUT_SPEAKER, ""},
    //    {"patch", AUDIO_DEVICE_OUT_SPEAKER, ""},
};

/*static*/
std::vector<AudioProductStrategyTestParams> AudioTestParams::getAudioProductStrategyTestParams()
{
    return gAudioProductStrategyTestParams;
}

static const std::vector<ConcurrencyTestParams> gConcurrencyTestParamsTestParams = {
    /**
     * Put in concurrence a regular AudioTrack based on Attributes and an AudioTrack using
     * explicit routing.
     * They shares the same stream type but expect be routed on different devices.
     * Launch first the regular track, then the explicit routing.
     */
    {"ext_audio_source", AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA", ""/*explictRouting*/,
     AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    /**
     * Put in concurrence a regular AudioTrack based on Attributes and an AudioTrack using
     * explicit routing.
     * They shares the same stream type but expect be routed on different devices.
     * Launch first the explicit routing, then the regular track.
     */
    {""/*explictRouting*/, AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION", "ext_audio_source",
     AUDIO_DEVICE_OUT_BUS, "BUS00_MEDIA"},
    /**
     * Put in concurrence a regular AudioTrack based on Attributes and an AudioTrack using
     * explicit routing.
     * They shares the same stream type and expect be routed on same devices.
     * Launch first the regular track then the explicit routing.
     */
    {"oem_strategy_1", AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK", ""/*explictRouting*/,
     AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK"},
    /**
     * Put in concurrence a regular AudioTrack based on Attributes and an AudioTrack using
     * explicit routing.
     * They shares the same stream type and expect be routed on same devices.
     * Launch first the explicit routing then the regular track.
     */
    {""/*explictRouting*/, AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK", "oem_strategy_1",
     AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK"},
    /**
     * Put in concurrence 2 AudioTrack using explicit routing.
     * They shares the same stream type but expect be routed on different devices.
     */
    {""/*explictRouting*/, AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK", ""/*explictRouting*/,
     AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION"},
    /**
     * Put in concurrence 2 AudioTrack using explicit routing.
     * They shares the same stream type but expect be routed on different devices.
     */
    {""/*explictRouting*/, AUDIO_DEVICE_OUT_BUS, "BUS01_SYS_NOTIFICATION", ""/*explictRouting*/,
     AUDIO_DEVICE_OUT_BUS, "BUS05_BEEP_CLICK"}
};

/*static*/
std::vector<ConcurrencyTestParams> AudioTestParams::getConcurrencyTestParamsTestParams()
{
    return gConcurrencyTestParamsTestParams;
}

static const std::vector<AttributeVolumeTestParams> gUnknownAttributesVolumeTestParams = {
    {{AUDIO_CONTENT_TYPE_MUSIC, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""},
     "media"},
    {{AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""},
     "media"}
};

/*static*/
std::vector<AttributeVolumeTestParams> AudioTestParams::getUnknownAttributesVolumeTestParams()
{
    return gUnknownAttributesVolumeTestParams;
}
