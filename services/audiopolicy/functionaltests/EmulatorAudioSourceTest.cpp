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

#include "Helper.hpp"

using namespace android;

static const bool USE_SW_BRIDGING = true;
static const bool USE_HW_BRIDGING = false;

using AudioSourceBridgeTestParams =
    std::tuple<const audio_attributes_t /*renderingAttributes*/,
               const audio_port /*sourcePort*/,
               const audio_source_t /* sourceUseCase*/,
               const audio_port /*sinkPort*/,
               const audio_stream_type_t /*sinkStream*/,
               bool /*useSwBridging, if false use HW bridging*/>;

using AudioSourceBridgingTest = ::testing::TestWithParam<AudioSourceBridgeTestParams>;

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

    // Register the device & ensure ports are available
    auto connectDevice = [&]() {
        ASSERT_TRUE(Helper::connectPort(expectedSourcePort, sourcePort));
        ASSERT_EQ(OK, Helper::findPort(expectedSinkPort, sinkPort))
                << "Could not find port: " << expectedSinkPort.ext.device.address;
    };

    ///
    /// First iteration: AudioSource is stopped first, then device is disconnected
    ///
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
        EXPECT_EQ(OK, ret) << "AudioSystem::startAudioSource for source "
                                    << sourcePort.ext.device.address << " failed";
    };

    connectAudioSource();

    auto checkEstablishedPatch = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        bool patchRealized = false;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            std::cerr << Helper::dumpPatch(patches[i]);
            audio_patch patch = patches[i];
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE &&
                    patch.sources[0].ext.device.type == sourcePort.ext.device.type) {

                if (expectUsingSwBridging) {
                    // Ensure SW Bridging is enabled : must find a mix port at source 1 of each
                    // patches by Internal Audio Policy convention shared with AudioFlinger
                    EXPECT_EQ(patch.num_sources, 2u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                    EXPECT_EQ(patch.sources[1].ext.mix.usecase.stream, expectedStreamType);
                } else {
                    EXPECT_EQ(patch.num_sources, 1u) << "Not a HW Bridging";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a HW Bridging";
                }
                EXPECT_EQ(strncmp(patch.sources[0].ext.device.address,
                          sourcePort.ext.device.address, AUDIO_DEVICE_MAX_ADDRESS_LEN), 0);
                EXPECT_EQ(patch.sinks[0].type, AUDIO_PORT_TYPE_DEVICE);
                EXPECT_EQ(patch.sinks[0].ext.device.type, sinkPort.ext.device.type);
                EXPECT_EQ(strncmp(patch.sinks[0].ext.device.address,
                          sinkPort.ext.device.address, AUDIO_DEVICE_MAX_ADDRESS_LEN), 0);
                patchRealized = true;
                break;
            }
        }
        EXPECT_TRUE(patchRealized) << "No patch found involving devices "
                           << sourcePort.ext.device.address << " and "
                           << sinkPort.ext.device.address;
    };

    checkEstablishedPatch();

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
    auto checkPatchRemoved = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            std::cerr << Helper::dumpPatch(patches[i]);
            audio_patch patch = patches[i];
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
                EXPECT_NE(patch.sources[0].ext.device.type, sourcePort.ext.device.type);
            }
        }
    };
    checkPatchRemoved();

    // Unregister the device
    auto disconnectDevice = [&]() {
        Helper::disconnectPort(sourcePort);
    };
    disconnectDevice();

    ///
    /// Second iteration: disconnect the device before stopping the audio source
    ///
    connectDevice();
    connectAudioSource();
    checkEstablishedPatch();
    disconnectDevice();
    checkPatchRemoved();
    EXPECT_EQ(BAD_VALUE, AudioSystem::stopAudioSource(sourcePortHandle))
            << "Source shall be already stopped";
}

static const std::vector<AudioSourceBridgeTestParams> gAudioSourceBridgeTestParams = {
    { attributes_initializer(AUDIO_USAGE_MEDIA),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      AUDIO_SOURCE_FM_TUNER,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_USAGE_MAIN"},
      AUDIO_STREAM_MUSIC,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
       AUDIO_SOURCE_VOICE_DOWNLINK,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS04_USAGE_VOICE"},
      AUDIO_STREAM_VOICE_CALL,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_HDMI, .ext.device.address = ""},
      AUDIO_SOURCE_MIC,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_USAGE_SYSTEM"},
      AUDIO_STREAM_SYSTEM,
      USE_SW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_SPEECH, .usage = AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
       .tags = "oem=2"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      AUDIO_SOURCE_FM_TUNER,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS02_USAGE_OEM"},
      AUDIO_STREAM_MUSIC,
      USE_SW_BRIDGING
    },
    //
    // This test case will use Direct Output thanks to AUDIO_FLAG_HW_AV_SYNC
    //
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC,
       .usage = AUDIO_USAGE_ASSISTANCE_SONIFICATION,
       .flags = AUDIO_FLAG_HW_AV_SYNC,
       .tags = "car_audio_type=3"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_HDMI, .ext.device.address = ""},
      AUDIO_SOURCE_MIC,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_USAGE_SYSTEM"},
      AUDIO_STREAM_SYSTEM,
      USE_SW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_MEDIA),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_USAGE_MAIN"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC,
       .usage = AUDIO_USAGE_MEDIA,
       .tags = "car_audio_type=3"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_USAGE_MAIN"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { {.content_type = AUDIO_CONTENT_TYPE_SPEECH,
       .usage = AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
       .tags = "oem=2"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT, // ignored for HW Bridging
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS02_USAGE_OEM"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
      USE_HW_BRIDGING
    },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION),
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      AUDIO_SOURCE_DEFAULT,
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_USAGE_SYSTEM"},
      AUDIO_STREAM_DEFAULT, // ignored for HW Bridging
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

using AudioSourceForceUseTogglingTest =
        ::testing::TestWithParam<AudioSourceForceUseTogglingTestParams>;

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
        ASSERT_TRUE(Helper::connectPort(expectedSourcePort, sourcePort));
        ASSERT_EQ(OK, Helper::findPort(expectedSinkPort, sinkPort))
                << "Could not find port " << expectedSinkPort.ext.device.address;

        ret = Helper::findPort(forceUseExpectedSinkPort, sinkPortForcedConfig);
        ASSERT_EQ(OK, ret) << "Could not find port "
                                    << forceUseExpectedSinkPort.ext.device.address;
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

    auto checkEstablishedPatch = [&](const audio_port &sinkDevicePort) {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        bool patchRealized = false;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            std::cerr << Helper::dumpPatch(patches[i]);
            audio_patch patch = patches[i];
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE &&
                    patch.sources[0].ext.device.type == sourcePort.ext.device.type) {
                EXPECT_EQ(strncmp(patch.sources[0].ext.device.address,
                          sourcePort.ext.device.address, AUDIO_DEVICE_MAX_ADDRESS_LEN), 0);

                if (expectUsingSwBridging) {
                    // Ensure SW Bridging is enabled : must find a mix port at source 1 of each
                    // patches by Internal Audio Policy convention shared with AudioFlinger
                    EXPECT_EQ(patch.num_sources, 2u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                    EXPECT_EQ(patch.sources[1].ext.mix.usecase.stream, expectedStreamType);
                } else {
                    EXPECT_EQ(patch.num_sources, 1u) << "Not a HW Bridging";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a HW Bridging";
                }
                EXPECT_EQ(patch.sinks[0].type, sinkDevicePort.type);
                EXPECT_EQ(patch.sinks[0].ext.device.type, sinkDevicePort.ext.device.type);
                EXPECT_EQ(strncmp(patch.sinks[0].ext.device.address,
                          sinkDevicePort.ext.device.address, AUDIO_DEVICE_MAX_ADDRESS_LEN), 0);
                patchRealized = true;
                break;
            }
        }
        EXPECT_TRUE(patchRealized) << "No patch found involving FM device";
    };
    checkEstablishedPatch(sinkPort);

    ret = AudioSystem::setForceUse(forceUseToToggle, forcedConfig);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    checkEstablishedPatch(sinkPortForcedConfig);

    ret = AudioSystem::setForceUse(forceUseToToggle, initialForcedCfd);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    checkEstablishedPatch(sinkPort);

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
    auto checkPatchRemoved = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            std::cerr << Helper::dumpPatch(patches[i]);
            audio_patch patch = patches[i];
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
                EXPECT_NE(patch.sources[0].ext.device.type, sourcePort.ext.device.type);
            }
        }
    };
    checkPatchRemoved();

    // Unregister the device
    Helper::disconnectPort(sourcePort);

    ret = AudioSystem::setForceUse(forceUseToToggle, initialForcedCfd);
    EXPECT_EQ(OK, ret) << "setForceUse failed";
}

static const std::vector<AudioSourceForceUseTogglingTestParams>
        gAudioSourceForceUseTogglingTestParams = {
    { {.content_type = AUDIO_CONTENT_TYPE_MUSIC, .usage = AUDIO_USAGE_MEDIA,
       .tags = "car_audio_type=3"},
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_USAGE_MAIN"},
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
