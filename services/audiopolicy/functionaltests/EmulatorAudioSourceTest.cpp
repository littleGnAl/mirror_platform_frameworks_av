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

#include <gtest/gtest.h>

#include "AudioPolicyTestBase.hpp"

using namespace android;

using AudioSourceBridgeTestParams =
    std::tuple<const audio_attributes_t /*renderingAttributes*/,
        const audio_port /*sourcePort*/,
        const audio_source_t /* sourceUseCase*/,
        const audio_port /*sinkPort*/,
        const audio_stream_type_t /*sinkStream*/,
        bool /*useSwBridging, if false use HW bridging*/>;

using AudioSourceBridgingTest = AudioPolicyTestBase<AudioSourceBridgeTestParams>;

TEST_P(AudioSourceBridgingTest, UsingAudioSourceAPI)
{
    status_t ret;

    const audio_attributes_t attributes = std::get<0>(GetParam());
    const audio_port expectedSourcePort = std::get<1>(GetParam());
    (void) std::get<2>(GetParam());
    const audio_port expectedSinkPort = std::get<3>(GetParam());
    const audio_stream_type_t expectedStreamType = std::get<4>(GetParam());
    const bool expectUsingSwBridging = std::get<5>(GetParam());

    audio_port sourcePort {};
    audio_port sinkPort {};

    ASSERT_EQ(OK, findPort(expectedSinkPort, sinkPort))
            << "Could not find port: " << dumpPort(expectedSinkPort);

    // Register the device & ensure ports are available
    auto connectSourcePort = [&]() {
        ASSERT_TRUE(connectPort(expectedSourcePort, sourcePort))
                << "Could not connect port: " << dumpPort(expectedSourcePort);
    };

    ///
    /// First iteration: AudioSource is stopped first, then device is disconnected
    ///
    connectSourcePort();

    // Connect the source
    audio_port_handle_t sourcePortHandle = AUDIO_PORT_HANDLE_NONE;

    auto connectAudioSource = [&]() {
        sourcePortHandle = AUDIO_PORT_HANDLE_NONE;

        struct audio_port_config sourcePortConfig = sourcePort.active_config;
        sourcePortConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        sourcePortConfig.format = AUDIO_FORMAT_PCM_16_BIT;
        sourcePortConfig.sample_rate = 48000;
        ret = AudioSystem::startAudioSource(&sourcePortConfig,
                                            &attributes,
                                            &sourcePortHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::startAudioSource for source "
                           << sourcePort.ext.device.address << " failed";
    };

    connectAudioSource();

    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    auto releaseAudioSource = [&]() {
        EXPECT_NE(sourcePortHandle, AUDIO_PORT_HANDLE_NONE);
        if (sourcePortHandle != AUDIO_PORT_HANDLE_NONE) {
            ret = AudioSystem::stopAudioSource(sourcePortHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::stopAudioSource for handle "
                               <<  sourcePortHandle << " failed";
        }
    };

    releaseAudioSource();

    // Ensure Bridging is disabled
    checkPatchRemoved(sourcePort, sinkPort);

    // Unregister the device
    disconnectPort(sourcePort);

    ///
    /// Second iteration: disconnect the device (source) before stopping the audio source
    ///
    connectSourcePort();
    connectAudioSource();
    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);
    disconnectPort(sourcePort);
    checkPatchRemoved(sourcePort, sinkPort);
    // Automatic restart -> OK, otherwise BAD_VALUE expected since already stopped
    EXPECT_EQ(/*BAD_VALUE*/OK, AudioSystem::stopAudioSource(sourcePortHandle))
            << "Source shall be already stopped";

    /// Automatic restart ONLY
    /// Second iteration bis: disconnect the device (source) before stopping the audio source
    ///
    connectSourcePort();
    connectAudioSource();
    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);
    disconnectPort(sourcePort);
    checkPatchRemoved(sourcePort, sinkPort);

    connectSourcePort();
    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    EXPECT_EQ(OK, AudioSystem::stopAudioSource(sourcePortHandle))
            << "Source shall be already stopped";

    disconnectPort(sourcePort);
    ///
    /// third iteration: disconnect the device (sink) then reconnect it
    ///
    connectSourcePort();
    connectAudioSource();
    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    // Disconnect now the sinkport involved in the patch
    disconnectPort(sinkPort);
    checkPatchRemoved(sourcePort, sinkPort);

    // Re-Connect the sinkport
    connectPort(expectedSinkPort, sinkPort);
    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    releaseAudioSource();

    disconnectPort(sourcePort);
}

static const std::vector<AudioSourceBridgeTestParams> gAudioSourceBridgeTestParams = {
    { attributes_initializer(AUDIO_USAGE_MEDIA),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      AUDIO_SOURCE_FM_TUNER,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      AUDIO_STREAM_MUSIC,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE"},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_HDMI/*, .ext.device.address = "hdmi_in_mic"*/},
      AUDIO_SOURCE_MIC,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS05_BEEP_CLICK"},
      AUDIO_STREAM_MUSIC/*AUDIO_STREAM_SYSTEM*/,
      USE_SW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_SPEECH,
       .usage = AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE, .tags = "oem=ta"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      AUDIO_SOURCE_FM_TUNER,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      AUDIO_STREAM_MUSIC,
      USE_SW_BRIDGING
    },
    //
    // This test case will use Direct Output thanks to AUDIO_FLAG_HW_AV_SYNC
    //
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC,
       .usage = AUDIO_USAGE_ASSISTANCE_SONIFICATION,
       .flags = AUDIO_FLAG_HW_AV_SYNC},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_HDMI, .ext.device.address = ""},
      AUDIO_SOURCE_MIC,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS05_BEEP_CLICK"},
      AUDIO_STREAM_MUSIC/*AUDIO_STREAM_SYSTEM*/,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_MEDIA),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC,
       .usage = AUDIO_USAGE_MEDIA,
       .tags = "oem=ta"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_SPEECH,
       .usage = AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
       .tags = "oem=ta"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS05_BEEP_CLICK"},
      AUDIO_STREAM_SYSTEM, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioSourceTest,
        AudioSourceBridgingTest,
        ::testing::ValuesIn(gAudioSourceBridgeTestParams)
        );

using AudioSourceForceUseTogglingTestParams =
std::tuple<const audio_attributes_t /*renderingAttributes*/,
const audio_port /*sourcePort*/,
const audio_port /*sinkPort*/,
const audio_port /*forcedUseToggledSinkPort*/,
const audio_stream_type_t /*sinkStream*/,
const audio_policy_force_use_t /* forceUseToToggle*/,
const audio_policy_forced_cfg_t /* forcedConfig */,
bool /*useSwBridging, if false use HW bridging*/>;

using AudioSourceForceUseTogglingTest = AudioPolicyTestBase<AudioSourceForceUseTogglingTestParams>;

/**
 * @brief AudioSourceForceUseTogglingTest checks the start / stop of the Audio Source connected
 * through a HW / SW bridge (AudioHAL is >=3.0 but no direct path exist in Route section allowing to
 * connect the output device to the input port.
 * During connection, a setForceUse will change the routing.
 * @note: this use case WILL not work in case of HW bridging since the activity is checked only
 * on SwOutputs to take new routing decisions.
 */
TEST_P(AudioSourceForceUseTogglingTest, SetForceUseToggling)
{
    status_t ret;

    const audio_attributes_t attributes = std::get<0>(GetParam());
    const audio_port expectedSourcePort = std::get<1>(GetParam());
    const audio_port expectedSinkPort = std::get<2>(GetParam());
    const audio_port forceUseExpectedSinkPort = std::get<3>(GetParam());
    const audio_stream_type_t expectedStreamType = std::get<4>(GetParam());
    const audio_policy_force_use_t forceUseToToggle = std::get<5>(GetParam());
    const audio_policy_forced_cfg_t forcedConfig = std::get<6>(GetParam());
    const bool expectUsingSwBridging = std::get<7>(GetParam());

    const audio_policy_forced_cfg_t initialForcedCfd = AudioSystem::getForceUse(forceUseToToggle);

    audio_port sourcePort {};
    audio_port sinkPort {};
    audio_port sinkPortForcedConfig {};

    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, initialForcedCfd);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    // Register the device & ensure ports are available
    auto connectDevice = [&]() {
        ASSERT_TRUE(connectPort(expectedSourcePort, sourcePort))
                << "Could not connect port " << expectedSourcePort.ext.device.address;
        ASSERT_EQ(OK, findPort(expectedSinkPort, sinkPort))
                << "Could not find port " << expectedSinkPort.ext.device.address;

        ASSERT_EQ(OK, findPort(forceUseExpectedSinkPort, sinkPortForcedConfig))
                << "Could not find port " << forceUseExpectedSinkPort.ext.device.address;
    };

    connectDevice();

    // Connect the source
    audio_port_handle_t sourcePortHandle = AUDIO_PORT_HANDLE_NONE;

    auto connectAudioSource = [&]() {
        sourcePortHandle = AUDIO_PORT_HANDLE_NONE;
        struct audio_port_config sourcePortConfig = sourcePort.active_config;
        sourcePortConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        sourcePortConfig.format = AUDIO_FORMAT_PCM_16_BIT;
        sourcePortConfig.sample_rate = 48000;
        ret = AudioSystem::startAudioSource(&sourcePortConfig,
                                            &attributes,
                                            &sourcePortHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::startAudioSource for "
                           << expectedSourcePort.ext.device.address << " failed";
    };

    connectAudioSource();

    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    ret = AudioSystem::setForceUse(forceUseToToggle, forcedConfig);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    checkEstablishedPatch(
                sourcePort, sinkPortForcedConfig, expectUsingSwBridging, expectedStreamType);

    ret = AudioSystem::setForceUse(forceUseToToggle, initialForcedCfd);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    checkEstablishedPatch(sourcePort, sinkPort, expectUsingSwBridging, expectedStreamType);

    auto releaseAudioSource = [&]() {
        // Then, release the patches
        EXPECT_NE(sourcePortHandle, AUDIO_PORT_HANDLE_NONE);
        if (sourcePortHandle != AUDIO_PORT_HANDLE_NONE) {
            ret = AudioSystem::stopAudioSource(sourcePortHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::stopAudioSource for handle "
                               <<  sourcePortHandle << " failed";
        }
    };

    releaseAudioSource();

    // Ensure Bridging is disabled
    checkPatchRemoved(sourcePort, sinkPort);

    // Unregister the device
    disconnectPort(sourcePort);

    ret = AudioSystem::setForceUse(forceUseToToggle, initialForcedCfd);
    EXPECT_EQ(OK, ret) << "setForceUse failed";
}

static const std::vector<AudioSourceForceUseTogglingTestParams>
gAudioSourceForceUseTogglingTestParams = {
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC,
       .usage = AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE, .tags = "oem=ta"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_SPEAKER, .ext.device.address = "SPEAKER"},
      AUDIO_STREAM_MUSIC,
      AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_SPEAKER,
      USE_SW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioSourceTest,
        AudioSourceForceUseTogglingTest,
        ::testing::ValuesIn(gAudioSourceForceUseTogglingTestParams)
        );
