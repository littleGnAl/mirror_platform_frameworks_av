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

using AudioPatchTestParams = std::tuple<const audio_port /*sourcePort*/,
    const audio_port /*sinkPort*/, bool /*useSwBridging, if false use HW bridging*/>;

using AudioPatchBridgingTest = AudioPolicyTestBase<AudioPatchTestParams>;

/**
 * @brief AudioPatchBridgingTest uses AudioPatch System API to create an Audio Patch using
 * either an HW or SW bridge.
 * The source device is not always attached, in order to test both sequence of patch released first
 * and device disconnected first.
 */
TEST_P(AudioPatchBridgingTest, SingleAudioPatch)
{
    status_t ret;

    audio_port expectedSourcePort = std::get<0>(GetParam());
    audio_port expectedSinkPort = std::get<1>(GetParam());
    bool useSwBridging = std::get<2>(GetParam());

    audio_port sourcePort {};
    audio_port sinkPort {};

    struct audio_patch audioPatch;
    audio_patch_handle_t audioPatchHandle = AUDIO_PATCH_HANDLE_NONE;

    auto connectDevice = [&]() {
        ASSERT_TRUE(connectPort(expectedSourcePort, sourcePort))
                << "Could not connect port: " << expectedSourcePort.ext.device.address;
        ASSERT_EQ(OK, findPort(expectedSinkPort, sinkPort))
                << "Could not connect port: " << expectedSinkPort.ext.device.address;
    };
    auto createAudioPatch = [&]() {
        audioPatch.id = 0;
        audioPatch.num_sources = 1;
        audioPatch.num_sinks = 1;
        audioPatchHandle = AUDIO_PATCH_HANDLE_NONE;

        memcpy(&audioPatch.sources[0], &sourcePort.active_config, sizeof(audio_port_config));
        memcpy(&audioPatch.sinks[0], &sinkPort.active_config, sizeof(audio_port_config));

        ret = AudioSystem::createAudioPatch(&audioPatch, &audioPatchHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::createAudiopatch failed between source "
                           << expectedSourcePort.ext.device.address << " and sink "
                           << expectedSinkPort.ext.device.address;
    };
    auto releaseAudioPatch = [&]() {
        // Then, release the patches
        if (audioPatchHandle != AUDIO_PATCH_HANDLE_NONE) {
            ret = AudioSystem::releaseAudioPatch(audioPatchHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::releaseAudioPatch failed between source "
                               << expectedSourcePort.ext.device.address << " and sink "
                               << expectedSinkPort.ext.device.address;
        }
    };

    auto disconnectDevice = [&]() {
        disconnectPort(sourcePort);
    };

    ///
    /// First iteration: release the patch first, then disconnect device
    ///
    // Register the device & ensure ports are not available
    connectDevice();

    // Build the patch
    createAudioPatch();

    EXPECT_TRUE(checkEstablishedPatch(audioPatchHandle, expectedSourcePort, expectedSinkPort,
                                      useSwBridging, AUDIO_STREAM_PATCH));
    releaseAudioPatch();

    // Ensure HW or SW Bridging is disabled
    checkPatchRemoved(sourcePort, sinkPort, audioPatchHandle);

    // Unregister the devices & ensure ports are not available any more
    disconnectDevice();

    ///
    /// Second iteration: disconnect device before releasing the patch
    ///
    connectDevice();
    createAudioPatch();
    EXPECT_TRUE(checkEstablishedPatch(audioPatchHandle, expectedSourcePort, expectedSinkPort,
                                      useSwBridging, AUDIO_STREAM_PATCH));
    disconnectDevice();
    checkPatchRemoved(sourcePort, sinkPort, audioPatchHandle);
    releaseAudioPatch();
}

static const std::vector<AudioPatchTestParams> gAudioPatchTestParams = {
    { // FMSwBridging
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      USE_SW_BRIDGING
    },
    { // FMHwridging
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"},
      USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        AudioPatchBridgingTest,
        ::testing::ValuesIn(gAudioPatchTestParams)
        );

using FullDuplexAudioPatchTestParams =
    std::tuple<const audio_port /*uplinkSourcePort*/,
        const audio_port /*uplinkSinkPort*/,
        const audio_port /*downlinkSourcePort*/,
        const audio_port /*downSinkPort*/,
        bool /*useSwBridging, if false use HW bridging*/>;

using FullDuplexAudioPatchTest = AudioPolicyTestBase<FullDuplexAudioPatchTestParams>;

TEST_P(FullDuplexAudioPatchTest, UsingCreateAudioPatch)
{
    status_t ret;
    audio_port expectedUplinkSourcePort = std::get<0>(GetParam());
    audio_port expectedUplinkSinkPort = std::get<1>(GetParam());

    audio_port expectedDownlinkSourcePort = std::get<2>(GetParam());
    audio_port expectedDownlinkSinkPort = std::get<3>(GetParam());
    bool useSwBridging = std::get<4>(GetParam());


    // Register the devices & ensure ports are not available
    audio_port uplinkSinkPort;
    audio_port downlinkSourcePort;
    audio_port downlinkSinkPort {};
    audio_port uplinkSourcePort {};

    struct audio_patch uplinkPatch;
    struct audio_patch downlinkPatch;
    audio_patch_handle_t downlinkPatchHandle = AUDIO_PATCH_HANDLE_NONE;
    audio_patch_handle_t uplinkPatchHandle = AUDIO_PATCH_HANDLE_NONE;

    auto connectDevices = [&]() {
        ASSERT_TRUE(connectPort(expectedUplinkSinkPort, uplinkSinkPort))
                << "Could not connect port: " << expectedUplinkSinkPort.ext.device.address;
        ASSERT_TRUE(connectPort(expectedDownlinkSourcePort, downlinkSourcePort))
                << "Could not connect port: " << expectedDownlinkSourcePort.ext.device.address;
        ASSERT_EQ(OK, findPort(expectedDownlinkSinkPort, downlinkSinkPort))
                << "Could not find port: " << expectedDownlinkSinkPort.ext.device.address;
        ASSERT_EQ(OK, findPort(expectedUplinkSourcePort, uplinkSourcePort))
                << "Could not find port: " << expectedUplinkSourcePort.ext.device.address;
    };
    auto createAudioPatches = [&]() {
        uplinkPatch.id = 0;
        uplinkPatch.num_sources = 1;
        uplinkPatch.num_sinks = 1;
        uplinkPatchHandle = AUDIO_PATCH_HANDLE_NONE;

        memcpy(&uplinkPatch.sources[0], &uplinkSourcePort.active_config, sizeof(audio_port_config));
        memcpy(&uplinkPatch.sinks[0], &uplinkSinkPort.active_config, sizeof(audio_port_config));

        ret = AudioSystem::createAudioPatch(&uplinkPatch, &uplinkPatchHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::createAudiopatch for uplink failed";

        downlinkPatch.id = 0;
        downlinkPatch.num_sources = 1;
        downlinkPatch.num_sinks = 1;
        downlinkPatchHandle = AUDIO_PATCH_HANDLE_NONE;

        memcpy(&downlinkPatch.sources[0], &downlinkSourcePort.active_config,
                sizeof(audio_port_config));
        memcpy(&downlinkPatch.sinks[0], &downlinkSinkPort.active_config, sizeof(audio_port_config));

        downlinkPatch.sources[0].sample_rate = downlinkSourcePort.sample_rates[0];
        downlinkPatch.sources[0].channel_mask = downlinkSourcePort.channel_masks[0];
        downlinkPatch.sources[0].format = downlinkSourcePort.formats[0];

        status_t ret = AudioSystem::createAudioPatch(&downlinkPatch, &downlinkPatchHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::createAudiopatch for downlink failed";
    };
    auto checkEstablishedAudioPatches = [&]() {
        EXPECT_NE(downlinkPatchHandle, AUDIO_PATCH_HANDLE_NONE);
        EXPECT_NE(uplinkPatchHandle, AUDIO_PATCH_HANDLE_NONE);

        EXPECT_TRUE(checkEstablishedPatch(downlinkPatchHandle, downlinkSourcePort,
                                          downlinkSinkPort, useSwBridging,
                                          AUDIO_STREAM_PATCH));
        EXPECT_TRUE(checkEstablishedPatch(uplinkPatchHandle, uplinkSourcePort,
                                          uplinkSinkPort, useSwBridging,
                                          AUDIO_STREAM_PATCH));
    };
    auto disconnectUplinkSinkDevice = [&]() {
        disconnectPort(uplinkSinkPort);
    };
    auto disconnectDownlinkSourceDevice = [&]() {
        disconnectPort(downlinkSourcePort);
    };
    auto checkAudioPatchesRemoved = [&]() {
        checkPatchRemoved(uplinkSourcePort, uplinkSinkPort, uplinkPatchHandle);
        checkPatchRemoved(downlinkSourcePort, downlinkSinkPort, downlinkPatchHandle);
    };
    auto releaseAudioPatches = [&]() {
        // Then, release the patches
        if (downlinkPatchHandle != AUDIO_PATCH_HANDLE_NONE) {
            ret = AudioSystem::releaseAudioPatch(downlinkPatchHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::releaseAudioPatch for uplink failed";
        }
        if (uplinkPatchHandle != AUDIO_PATCH_HANDLE_NONE) {
            ret = AudioSystem::releaseAudioPatch(uplinkPatchHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::releaseAudioPatch for downlink failed";
        }
    };

    ///
    /// First iteration: remove devices first, starting with the source
    ///
    connectDevices();

    // Build the patches
    createAudioPatches();

    checkEstablishedAudioPatches();

    // Unregister the devices FIRST, starting with source & ensure ports are not available any more
    disconnectDownlinkSourceDevice();
    disconnectUplinkSinkDevice();

    // Ensure SW Bridging is disabled
    checkAudioPatchesRemoved();

    releaseAudioPatches();

    ///
    /// Second iteration: remove devices first, starting with the sink
    ///
    connectDevices();

    createAudioPatches();

    checkEstablishedAudioPatches();

    // Unregister the devices FIRST, starting with sink & ensure ports are not available any more
    disconnectUplinkSinkDevice();
    disconnectDownlinkSourceDevice();

    checkAudioPatchesRemoved();

    releaseAudioPatches();

    ///
    /// Third iteration: remove patches first
    ///
    connectDevices();

    createAudioPatches();

    checkEstablishedAudioPatches();

    releaseAudioPatches();

    checkAudioPatchesRemoved();

    // Unregister the devices & ensure ports are not available any more
    disconnectDownlinkSourceDevice();
    disconnectUplinkSinkDevice();
}

static const std::vector<FullDuplexAudioPatchTestParams> gFullDuplexAudioPatchTestParams = {
    {
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE"},
        USE_SW_BRIDGING
    },
    {
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
          .ext.device.address = "hfp_client_out_hw"},
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE"},
        USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        FullDuplexAudioPatchTest,
        ::testing::ValuesIn(gFullDuplexAudioPatchTestParams)
        );


using AudioModeBridgingTest = AudioPolicyTestBase<FullDuplexAudioPatchTestParams>;

TEST_P(AudioModeBridgingTest, UsingAudioMode)
{
    audio_port expectedUplinkSourcePort = std::get<0>(GetParam());
    audio_port expectedUplinkSinkPort = std::get<1>(GetParam());

    audio_port expectedDownlinkSourcePort = std::get<2>(GetParam());
    audio_port expectedDownlinkSinkPort = std::get<3>(GetParam());
    bool useSwBridging = std::get<4>(GetParam());


    // Register the devices & ensure ports are not available
    audio_port uplinkSinkPort;
    audio_port downlinkSourcePort;
    audio_port downlinkSinkPort {};
    audio_port uplinkSourcePort {};

    ASSERT_EQ(OK, findPort(expectedDownlinkSinkPort, downlinkSinkPort))
            << "Could not find downlink sink port: "
            << expectedDownlinkSinkPort.ext.device.address;

    ASSERT_EQ(OK, findPort(expectedUplinkSourcePort, uplinkSourcePort))
            << "Could not find uplink source port: "
            << expectedUplinkSourcePort.ext.device.address;

    auto connectRxTxDevices = [&]() {
        ASSERT_TRUE(connectPort(expectedUplinkSinkPort, uplinkSinkPort))
                << "Could not connect port: " << expectedUplinkSinkPort.ext.device.address;
        ASSERT_TRUE(connectPort(expectedDownlinkSourcePort, downlinkSourcePort))
                << "Could not connect port: " << expectedDownlinkSourcePort.ext.device.address;
    };
    auto checkEstablishedUplinkPatch = [&]() {
        checkEstablishedPatch(
                    uplinkSourcePort, uplinkSinkPort, useSwBridging, AUDIO_STREAM_PATCH);
    };

    auto checkEstablishedDownlinkPatch = [&]() {
        checkEstablishedPatch(
                    downlinkSourcePort, downlinkSinkPort, useSwBridging, AUDIO_STREAM_VOICE_CALL);
    };
    auto checkEstablishedPatches = [&]() {
        checkEstablishedDownlinkPatch();
        checkEstablishedUplinkPatch();
    };

    auto checkReleasedUplinkPatch = [&]() {
        checkPatchRemoved(uplinkSourcePort, uplinkSinkPort);
    };
    auto checkReleasedDownlinkPatch = [&]() {
        checkPatchRemoved(downlinkSourcePort, downlinkSinkPort);
    };
    auto checkReleasedPatches = [&]() {
        checkReleasedDownlinkPatch();
        checkReleasedUplinkPatch();
    };
    auto disconnectTxSinkDevice = [&]() {
        disconnectPort(uplinkSinkPort);
    };
    auto disconnectRxSourceDevice = [&]() {
        disconnectPort(downlinkSourcePort);
    };

    ///
    /// First iteration: change mode first to release the patch, disconnect device after
    ///
    connectRxTxDevices();

    // Switch to voice call mode
    changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // While patch established, disconnect DL Sink Port
    disconnectPort(downlinkSinkPort);
    checkReleasedDownlinkPatch();
    checkEstablishedUplinkPatch();

    // Reconnect DL Sink Port
    ASSERT_TRUE(connectPort(expectedDownlinkSinkPort, downlinkSinkPort));
    checkEstablishedPatches();

    // Swich back to normal mode
    changeMode(AUDIO_MODE_NORMAL);

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectTxSinkDevice();
    disconnectRxSourceDevice();

    ///
    /// Second iteration: disconnect sink device first to release the patch, change mode after
    ///
    connectRxTxDevices();

    // Switch to voice call mode
    changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectTxSinkDevice();
    disconnectRxSourceDevice();

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Swich back to normal mode
    changeMode(AUDIO_MODE_NORMAL);

    ///
    /// Third iteration: disconnect source device first to release the patch, change mode after
    ///
    connectRxTxDevices();

    // Switch to voice call mode
    changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectRxSourceDevice();
    disconnectTxSinkDevice();

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Swich back to normal mode
    changeMode(AUDIO_MODE_NORMAL);
}

static const std::vector<FullDuplexAudioPatchTestParams> gAudioModeBridgingTestParams = {
    {
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE"},
        USE_SW_BRIDGING
    },
    {
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
          .ext.device.address = "hfp_client_out_hw"},
        { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX,
          .ext.device.address = "hfp_client_in_hw"},
        { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
          .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE"},
        USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        AudioModeBridgingTest,
        ::testing::ValuesIn(gAudioModeBridgingTestParams)
        );
