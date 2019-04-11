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

using AudioPatchTestParams =
    std::tuple<const audio_port /*sourcePort*/,
               const audio_port /*sinkPort*/,
               bool /*useSwBridging, if false use HW bridging*/>;

class AudioPatchBridgingTest : public ::testing::TestWithParam<AudioPatchTestParams> {};

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
    bool expectUsingSwBridging = std::get<2>(GetParam());

    audio_port sourcePort {};
    audio_port sinkPort {};

    struct audio_patch audioPatch;
    audio_patch_handle_t audioPatchHandle = AUDIO_PATCH_HANDLE_NONE;

    auto connectDevice = [&]() {
        ASSERT_TRUE(Helper::connectPort(expectedSourcePort, sourcePort));

        ASSERT_EQ(OK, Helper::findPort(expectedSinkPort, sinkPort))
                << "Could not find port: " << expectedSinkPort.ext.device.address;
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
    auto checkAudioPatchEstablished = [&]() {
        if (audioPatchHandle != AUDIO_PATCH_HANDLE_NONE) {
            audio_patch curAudioPatch;
            EXPECT_EQ(OK, Helper::getPatchByHandle(audioPatchHandle, curAudioPatch))
                    << "Audio Patch between source "
                    << expectedSourcePort.ext.device.address << " and sink "
                    << expectedSinkPort.ext.device.address << " not found";
            std::cerr << Helper::dumpPatch(curAudioPatch);

            if (expectUsingSwBridging) {
                // Ensure SW Bridging is enabled : must find a mix port at source 1 of each patches
                // by Internal Audio Policy convention shared with AudioFlinger
                EXPECT_EQ(curAudioPatch.num_sources, 2u)
                        << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curAudioPatch.num_sinks, 1u) << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curAudioPatch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                EXPECT_EQ(curAudioPatch.sources[1].role, AUDIO_PORT_ROLE_SOURCE);
            } else {
                EXPECT_EQ(curAudioPatch.num_sources, 1u) << "Not a HW Bridging";
                EXPECT_EQ(curAudioPatch.num_sinks, 1u) << "Not a HW Bridging";
            }
            EXPECT_EQ(curAudioPatch.sources[0].type, expectedSourcePort.type);
            EXPECT_EQ(curAudioPatch.sources[0].role, expectedSourcePort.role);
            EXPECT_EQ(curAudioPatch.sources[0].ext.device.type, expectedSourcePort.ext.device.type);
            EXPECT_EQ(curAudioPatch.sinks[0].type, expectedSinkPort.type);
            EXPECT_EQ(curAudioPatch.sinks[0].role, expectedSinkPort.role);
            EXPECT_EQ(curAudioPatch.sinks[0].ext.device.type, expectedSinkPort.ext.device.type);
        }
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
    auto checkAudioPatchRemoved = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            audio_patch patch = patches[i];
            EXPECT_NE(audioPatchHandle, patch.id);
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
                EXPECT_NE(patch.sources[0].ext.device.type, expectedSourcePort.ext.device.type);
                EXPECT_NE(patch.sources[0].ext.device.type, expectedSourcePort.ext.device.type);
            }
        }
    };
    auto disconnectDevice = [&]() {
        Helper::disconnectPort(sourcePort);
    };

    ///
    /// First iteration: release the patch first, then disconnect device
    ///
    // Register the device & ensure ports are not available
    connectDevice();

    // Build the patch
    createAudioPatch();

    checkAudioPatchEstablished();

    releaseAudioPatch();

    // Ensure HW or SW Bridging is disabled
    checkAudioPatchRemoved();

    // Unregister the devices & ensure ports are not available any more
    disconnectDevice();

    ///
    /// Second iteration: disconnect device before releasing the patch
    ///
    connectDevice();
    createAudioPatch();
    checkAudioPatchEstablished();
    disconnectDevice();
    checkAudioPatchRemoved();
    releaseAudioPatch();
}

static const std::vector<AudioPatchTestParams> gAudioPatchTestParams = {
    { // FMSwBridging
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS02_USAGE_OEM"},
      USE_SW_BRIDGING
    },
    { // FMHwridging
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_HW"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS02_USAGE_OEM"},
      USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        AudioPatchBridgingTest,
        ::testing::ValuesIn(gAudioPatchTestParams)
        );

using AudioModeBridgingTest = ::testing::TestWithParam<AudioPatchTestParams>;

TEST_P(AudioModeBridgingTest, UsingAudioMode)
{
    audio_port expectedSourcePort = std::get<0>(GetParam());
    audio_port expectedSinkPort = std::get<1>(GetParam());
    bool expectUsingSwBridging = std::get<2>(GetParam());

    // Register the devices & ensure ports are not available
    audio_port txSinkPort;
    audio_port rxSourcePort;

    auto connectRxTxDevices = [&]() {
        return Helper::connectPort(expectedSinkPort, txSinkPort) &&
                Helper::connectPort(expectedSourcePort, rxSourcePort);
    };
    auto checkEstablishedPatches = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        EXPECT_GE(numPatches, 2u);

        bool uplinkPatchFound = false;
        bool downlinkPatchFound = false;
        for (uint32_t i = 0; i < numPatches; i++) {
            audio_patch patch = patches[i];

            std::cout << Helper::dumpPatch(patch) << std::endl;

            if (patch.sources[0].ext.device.type == rxSourcePort.ext.device.type) {
                // It is the downlink patch
                if (expectUsingSwBridging) {
                    EXPECT_EQ(patch.num_sources, 2u) << "Not a SW Bridge, not follow convention";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a SW Bridge, not follow convention";
                    EXPECT_EQ(patch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                    EXPECT_EQ(patch.sources[1].role, AUDIO_PORT_ROLE_SOURCE);
                } else {
                    EXPECT_EQ(patch.num_sources, 1u) << "Not a HW Bridge";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a HW Bridge";
                }
                EXPECT_EQ(patch.sources[0].type, rxSourcePort.type);
                EXPECT_EQ(patch.sources[0].role, rxSourcePort.role);
                EXPECT_EQ(patch.sinks[0].type, AUDIO_PORT_TYPE_DEVICE);
                EXPECT_EQ(patch.sinks[0].role, AUDIO_PORT_ROLE_SINK);
                downlinkPatchFound = true;
            } else if (patch.sinks[0].ext.device.type == txSinkPort.ext.device.type) {
                // It is the uplink patch
                if (expectUsingSwBridging) {
                    EXPECT_EQ(patch.num_sources, 2u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a SW Bridging, not follow convention";
                    EXPECT_EQ(patch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                    EXPECT_EQ(patch.sources[1].role, AUDIO_PORT_ROLE_SOURCE);
                } else {
                    EXPECT_EQ(patch.num_sources, 1u) << "Not a HW Bridging";
                    EXPECT_EQ(patch.num_sinks, 1u) << "Not a HW Bridging";
                }
                EXPECT_EQ(patch.sources[0].type, AUDIO_PORT_TYPE_DEVICE);
                EXPECT_EQ(patch.sources[0].role, AUDIO_PORT_ROLE_SOURCE);
                EXPECT_EQ(patch.sinks[0].type, txSinkPort.type);
                EXPECT_EQ(patch.sinks[0].role, txSinkPort.role);
                uplinkPatchFound = true;
            }
        }
        EXPECT_TRUE(downlinkPatchFound) << " Downlink AudioPatch missing to connect Rx Source Port "
                                        << expectedSourcePort.ext.device.address;
        EXPECT_TRUE(uplinkPatchFound) << " Uplink AudioPatch missing to connect Tx Sink Port "
                                      << expectedSinkPort.ext.device.address;
    };

    auto checkReleasedPatches = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            audio_patch patch = patches[i];
            EXPECT_NE(patch.sources[0].ext.device.type, rxSourcePort.ext.device.type);
            EXPECT_NE(patch.sinks[0].ext.device.type, txSinkPort.ext.device.type);
        }
    };
    auto disconnectTxSinkDevice = [&]() {
        Helper::disconnectPort(txSinkPort);
    };
    auto disconnectRxSourceDevice = [&]() {
        Helper::disconnectPort(rxSourcePort);
    };

    ///
    /// First iteration: change mode first to release the patch, disconnect device after
    ///
    ASSERT_TRUE(connectRxTxDevices());

    // Switch to voice call mode
    Helper::changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // Swich back to normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectTxSinkDevice();
    disconnectRxSourceDevice();

    ///
    /// Second iteration: disconnect sink device first to release the patch, change mode after
    ///
    ASSERT_TRUE(connectRxTxDevices());

    // Switch to voice call mode
    Helper::changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectTxSinkDevice();
    disconnectRxSourceDevice();

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Swich back to normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    ///
    /// Third iteration: disconnect source device first to release the patch, change mode after
    ///
    ASSERT_TRUE(connectRxTxDevices());

    // Switch to voice call mode
    Helper::changeMode(AUDIO_MODE_IN_CALL);

    // Ensure SW Bridging is enabled
    checkEstablishedPatches();

    // Unregister the devices & ensure ports are not available any more
    disconnectRxSourceDevice();
    disconnectTxSinkDevice();

    // Ensure SW Bridging is disabled
    checkReleasedPatches();

    // Swich back to normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);
}

static const std::vector<AudioPatchTestParams> gAudioPatchUsingAudioModeBridgingTestParams = {
    {
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX, .ext.device.address = "hfp_client_out"},
      USE_SW_BRIDGING
    },
    {
      { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = "hfp_client_in_hw"},
      { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
        .ext.device.address = "hfp_client_out_hw"},
       USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        AudioModeBridgingTest,
        ::testing::ValuesIn(gAudioPatchUsingAudioModeBridgingTestParams)
        );

using FullDuplexAudioPatchTestParams =
    std::tuple<const audio_port /*uplinkSourcePort*/,
               const audio_port /*uplinkSinkPort*/,
               const audio_port /*downlinkSourcePort*/,
               const audio_port /*downSinkPort*/,
               bool /*useSwBridging, if false use HW bridging*/>;

using FullDuplexAudioPatchTest = ::testing::TestWithParam<FullDuplexAudioPatchTestParams>;

TEST_P(FullDuplexAudioPatchTest, UsingCreateAudioPatch)
{
    status_t ret;
    audio_port expectedUplinkSourcePort = std::get<0>(GetParam());
    audio_port expectedUplinkSinkPort = std::get<1>(GetParam());

    audio_port expectedDownlinkSourcePort = std::get<2>(GetParam());
    audio_port expectedDownlinkSinkPort = std::get<3>(GetParam());
    bool expectUsingSwBridging = std::get<4>(GetParam());


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
        ASSERT_TRUE(Helper::connectPort(expectedUplinkSinkPort, uplinkSinkPort));
        ASSERT_TRUE(Helper::connectPort(expectedDownlinkSourcePort, downlinkSourcePort));

        ASSERT_EQ(OK, Helper::findPort(expectedDownlinkSinkPort, downlinkSinkPort))
                << "Could not find downlink sink port: "
                << expectedDownlinkSinkPort.ext.device.address;

        ASSERT_EQ(OK, Helper::findPort(expectedUplinkSourcePort, uplinkSourcePort))
                << "Could not find uplink source port: "
                << expectedUplinkSourcePort.ext.device.address;
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

        if (downlinkPatchHandle != AUDIO_PATCH_HANDLE_NONE &&
                uplinkPatchHandle != AUDIO_PATCH_HANDLE_NONE) {
            audio_patch curUlPatch;
            EXPECT_EQ(OK, Helper::getPatchByHandle(uplinkPatchHandle, curUlPatch))
                    << " Uplink AudioPatch missing to connect Source Port "
                    << expectedUplinkSourcePort.ext.device.address
                    << " to Sink Port " << expectedUplinkSinkPort.ext.device.address;
            std::cerr << Helper::dumpPatch(curUlPatch);

            if (expectUsingSwBridging) {
                // Ensure SW Bridging is enabled : must find a mix port at source 1 of
                // each patches by Internal Audio Policy convention shared with AudioFlinger
                EXPECT_EQ(curUlPatch.num_sources, 2u) << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curUlPatch.num_sinks, 1u) << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curUlPatch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                EXPECT_EQ(curUlPatch.sources[1].role, AUDIO_PORT_ROLE_SOURCE);
            } else {
                EXPECT_EQ(curUlPatch.num_sources, 1u) << "Not a HW Bridge";
                EXPECT_EQ(curUlPatch.num_sinks, 1u) << "Not a HW Bridge";
            }
            EXPECT_EQ(curUlPatch.sources[0].type, expectedUplinkSourcePort.type);
            EXPECT_EQ(curUlPatch.sources[0].role, expectedUplinkSourcePort.role);
            EXPECT_EQ(curUlPatch.sources[0].ext.device.type,
                      expectedUplinkSourcePort.ext.device.type);

            EXPECT_EQ(curUlPatch.sinks[0].type, uplinkSinkPort.type);
            EXPECT_EQ(curUlPatch.sinks[0].role, uplinkSinkPort.role);
            EXPECT_EQ(curUlPatch.sinks[0].ext.device.type, uplinkSinkPort.ext.device.type);

            audio_patch curDlPatch;
            EXPECT_EQ(OK, Helper::getPatchByHandle(downlinkPatchHandle, curDlPatch))
                    << " Uplink AudioPatch missing to connect Source Port "
                    << expectedUplinkSourcePort.ext.device.address
                    << " to Sink Port " << expectedUplinkSinkPort.ext.device.address;
            std::cerr << Helper::dumpPatch(curDlPatch);

            if (expectUsingSwBridging) {
                // Ensure SW Bridging is enabled : must find a mix port at source 1 of
                // each patches by Internal Audio Policy convention shared with AudioFlinger
                EXPECT_EQ(curDlPatch.num_sources, 2u) << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curDlPatch.num_sinks, 1u) << "Not a SW Bridge, not follow convention";
                EXPECT_EQ(curDlPatch.sources[1].type, AUDIO_PORT_TYPE_MIX);
                EXPECT_EQ(curDlPatch.sources[1].role, expectedUplinkSourcePort.role);
            } else {
                EXPECT_EQ(curDlPatch.num_sources, 1u) << "Not a HW Bridge";
                EXPECT_EQ(curDlPatch.num_sinks, 1u) << "Not a HW Bridge";
            }
            EXPECT_EQ(curDlPatch.sources[0].type, downlinkSourcePort.type);
            EXPECT_EQ(curDlPatch.sources[0].role, downlinkSourcePort.role);
            EXPECT_EQ(curDlPatch.sources[0].ext.device.type, downlinkSourcePort.ext.device.type);

            EXPECT_EQ(curDlPatch.sinks[0].type, downlinkSinkPort.type);
            EXPECT_EQ(curDlPatch.sinks[0].role, downlinkSinkPort.role);
            EXPECT_EQ(curDlPatch.sinks[0].ext.device.type, downlinkSinkPort.ext.device.type);
        }
    };
    auto disconnectUplinkSinkDevice = [&]() {
        Helper::disconnectPort(uplinkSinkPort);
    };
    auto disconnectDownlinkSourceDevice = [&]() {
        Helper::disconnectPort(downlinkSourcePort);
    };
    auto checkAudioPatchesRemoved = [&]() {
        struct audio_patch *patches = nullptr;
        unsigned int numPatches = 0;
        EXPECT_EQ(OK, Helper::getPatches(patches, numPatches)) << "Could not list patches";
        for (uint32_t i = 0; i < numPatches; i++) {
            audio_patch patch = patches[i];
            if (patch.sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
                EXPECT_NE(patch.sources[0].ext.device.type,
                          expectedUplinkSourcePort.ext.device.type);
                EXPECT_NE(patch.sources[0].ext.device.type, downlinkSourcePort.ext.device.type);
            }
            if (patch.sinks[0].type == AUDIO_PORT_TYPE_DEVICE) {
                EXPECT_NE(patch.sinks[0].ext.device.type, uplinkSinkPort.ext.device.type);
                EXPECT_NE(patch.sinks[0].ext.device.type, downlinkSinkPort.ext.device.type);
            }
        }
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
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS04_USAGE_VOICE"},
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
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS04_USAGE_VOICE"},
      USE_HW_BRIDGING
    },
};

INSTANTIATE_TEST_CASE_P(
        AudioPatchTest,
        FullDuplexAudioPatchTest,
        ::testing::ValuesIn(gFullDuplexAudioPatchTestParams)
        );
