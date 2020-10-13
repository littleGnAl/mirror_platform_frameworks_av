/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "AudioPolicyTestBase.hpp"

#include <gtest/gtest.h>

using namespace android;

using InvalidateTrackTestParams =
    std::tuple<const audio_attributes_t /*renderingAttributes*/,
        bool /*invalidationExpected*/>;

class SetPhoneStateInvalidateTrackTest : public AudioPolicyTestBase<InvalidateTrackTestParams>
{
public:
    void SetUp() override
    {
        AudioPolicyTestBase::SetUp();
        ASSERT_EQ(OK, findPort(mExpectedDownlinkSinkPort, mDownlinkSinkPort))
                << "Could not find downlink sink port: "
                << mExpectedDownlinkSinkPort.ext.device.address;

        ASSERT_EQ(OK, findPort(mExpectedUplinkSourcePort, mUplinkSourcePort))
                << "Could not find uplink source port: "
                << mExpectedUplinkSourcePort.ext.device.address;

        connectCallDevices();
    }

    void connectCallDevices() {
        ASSERT_TRUE(connectPort(mExpectedUplinkSinkPort, mUplinkSinkPort))
                << "Could not connect port: " << mExpectedUplinkSinkPort.ext.device.address;
        ASSERT_TRUE(connectPort(mExpectedDownlinkSourcePort, mDownlinkSourcePort))
                << "Could not connect port: " << mExpectedDownlinkSourcePort.ext.device.address;
    }

    void checkEstablishedUplinkPatch() {
        checkEstablishedPatch(mUplinkSourcePort, mUplinkSinkPort, mUseSwBridging,
                              AUDIO_STREAM_PATCH);
    }

    void checkEstablishedDownlinkPatch() {
        checkEstablishedPatch(mDownlinkSourcePort, mDownlinkSinkPort, mUseSwBridging,
                              AUDIO_STREAM_VOICE_CALL);
    }

    void checkCallEstablished() {
        checkEstablishedDownlinkPatch();
        checkEstablishedUplinkPatch();
    }
    void checkReleasedUplinkPatch() {
        checkPatchRemoved(mUplinkSourcePort, mUplinkSinkPort);
    }
    void checkReleasedDownlinkPatch() {
        checkPatchRemoved(mDownlinkSourcePort, mDownlinkSinkPort);
    }
    void checkCallReleased() {
        checkReleasedDownlinkPatch();
        checkReleasedUplinkPatch();
    }

    void disconnectCallDevices() {
        disconnectPort(mUplinkSinkPort);
        disconnectPort(mDownlinkSourcePort);
    }

    void TearDown() override
    {
        disconnectCallDevices();
        AudioPolicyTestBase::TearDown();
    }

public:
    audio_port mUplinkSinkPort;
    audio_port mDownlinkSourcePort;
    audio_port mDownlinkSinkPort {};
    audio_port mUplinkSourcePort {};

    audio_port mExpectedUplinkSourcePort = {
        .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_BUILTIN_MIC, .ext.device.address = "bottom" };
    audio_port mExpectedUplinkSinkPort = {
        .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
        .ext.device.address = "hfp_client_out_hw" };
    audio_port mExpectedDownlinkSourcePort = {
        .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX,
        .ext.device.address = "hfp_client_in_hw" };
    audio_port mExpectedDownlinkSinkPort = {
        .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS03_PHONE" };
    bool mUseSwBridging = false;
};

TEST_P(SetPhoneStateInvalidateTrackTest, SetPhoneStateInvalidateTrack)
{
    const audio_attributes_t attributes = std::get<0>(GetParam());
    const bool invalidationExpected = std::get<1>(GetParam());

    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  android::toString(attributes);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  android::toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    // Check routed port
    audio_port routedDevicePort;
    playbackRoutedPortId = audioTrack->getRoutedDeviceId();
    EXPECT_EQ(NO_ERROR, getPortById(playbackRoutedPortId, routedDevicePort))
            << "Failed to identify port for playback by attributes: "
            <<  android::toString(attributes)
            << " routed on port " << playbackRoutedPortId;

    // Check Patch
    EXPECT_TRUE(checkPatch(audioTrack->getOutput(), playbackRoutedPortId))
            << "No patch found involving mix port " << audioTrack->getOutput()
            << " and device port " << playbackRoutedPortId;

    // Starts the voice call
    changeMode(AUDIO_MODE_IN_CALL);
    checkCallEstablished();

    EXPECT_EQ(invalidationExpected, audioTrack->waitForNewIAudioTrack())
            << "Timeout waiting for NEW_IAUDIO_TRACK event";

    // Stops the voice call
    changeMode(AUDIO_MODE_NORMAL);
    checkCallReleased();

    EXPECT_EQ(invalidationExpected, audioTrack->waitForNewIAudioTrack())
            << "Timeout waiting for NEW_IAUDIO_TRACK event";

    // Stop tracks
    audioTrack->stop();
}

//
// SetPhoneState Tracks Invalidation:
//
// When a call starts, APM forces reevaluating accessibility routing
// AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY
//
INSTANTIATE_TEST_CASE_P(
        InvalidateTracks,
        SetPhoneStateInvalidateTrackTest,
        ::testing::Values(
            InvalidateTrackTestParams({attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            InvalidateTrackTestParams({attributes_initializer(AUDIO_USAGE_ALARM), false}),
            InvalidateTrackTestParams(
                {attributes_initializer(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY), true}),
            InvalidateTrackTestParams({attributes_initializer(AUDIO_USAGE_NOTIFICATION), false}),
            InvalidateTrackTestParams(
                    {attributes_initializer(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE), false}),
            InvalidateTrackTestParams(
                    {attributes_initializer(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE), false}),
            InvalidateTrackTestParams(
                    {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), false}),
            InvalidateTrackTestParams({attributes_initializer(AUDIO_USAGE_GAME), false}),
            InvalidateTrackTestParams({attributes_initializer(AUDIO_USAGE_ASSISTANT), false})
            )
        );


//
// SetForceUse Tracks Invalidation:
// force client reconnection to reevaluate flag AUDIO_FLAG_AUDIBILITY_ENFORCED
// usage "For System":
//      -AUDIO_USAGE_ASSISTANCE_SONIFICATION
//      -AUDIO_FLAG_AUDIBILITY_ENFORCED
//
using SetForceUseInvalidateTracksTestParams =
std::tuple<std::pair<const audio_attributes_t /*player1Attributes*/, bool /*invalidationExpected*/>,
std::pair<const audio_attributes_t /*player2Attributes*/, bool /*invalidationExpected*/>>;

class SetForceUseInvalidateTracksTest :
        public AudioPolicyTestBase<SetForceUseInvalidateTracksTestParams>
{
public:
    void SetUp() override
    {
        AudioPolicyTestBase::SetUp();
    }

    void TearDown() override
    {
        ///
        /// Restore force use for system
        ///
        ASSERT_EQ(OK, AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM, mInitialSystemConfig))
                << "Failed to restore config " << mInitialSystemConfig
                << " for use " << AUDIO_POLICY_FORCE_FOR_SYSTEM;
        AudioPolicyTestBase::TearDown();
    }

private:
    const audio_policy_forced_cfg_t mInitialSystemConfig =
                AudioSystem::getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM);
};

TEST_P(SetForceUseInvalidateTracksTest, DualPlayer)
{
    status_t ret = OK;
    audio_policy_forced_cfg_t config = AUDIO_POLICY_FORCE_NONE;

    const audio_attributes_t aaPlayer1 = std::get<0>(GetParam()).first;
    const bool invalidationExpectedForPlayer1 = std::get<0>(GetParam()).second;

    const audio_attributes_t aaPlayer2 = std::get<1>(GetParam()).first;
    const bool invalidationExpectedForPlayer2 = std::get<1>(GetParam()).second;

    ///
    /// BE CAREFULL:
    /// getOutput will filter AUDIO_FLAG_AUDIBILITY_ENFORCED if AUDIO_POLICY_FORCE_FOR_SYSTEM
    /// has not been set to AUDIO_POLICY_FORCE_SYSTEM_ENFORCED
    ///
    if ((aaPlayer1.flags & AUDIO_FLAG_AUDIBILITY_ENFORCED) == AUDIO_FLAG_AUDIBILITY_ENFORCED ||
            (aaPlayer1.flags & AUDIO_FLAG_AUDIBILITY_ENFORCED) == AUDIO_FLAG_AUDIBILITY_ENFORCED) {
        ASSERT_EQ(OK, AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM,
                                               AUDIO_POLICY_FORCE_SYSTEM_ENFORCED))
                << "Failed to set config " << config << " for use "
                << AUDIO_POLICY_FORCE_FOR_SYSTEM;
    }

    ///
    /// Start player 1
    ///
    std::unique_ptr<AudioTrackTest> audioTrack1 = std::make_unique<AudioTrackTest>(aaPlayer1);
    ASSERT_EQ(OK, audioTrack1->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  android::toString(aaPlayer1);

    audio_port_handle_t playback1RoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack1->playSine(playback1RoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  android::toString(aaPlayer1);

    EXPECT_TRUE(audioTrack1->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    ///
    /// Start player 2
    ///
    std::unique_ptr<AudioTrackTest> audioTrack2 = std::make_unique<AudioTrackTest>(aaPlayer2);
    ASSERT_EQ(OK, audioTrack2->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  android::toString(aaPlayer2);

    audio_port_handle_t playback2RoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack2->playSine(playback2RoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  android::toString(aaPlayer2);

    EXPECT_TRUE(audioTrack2->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    ///
    /// SetForceUse toggle
    ///
    // Toggle AUDIO_POLICY_FORCE_FOR_SYSTEM to force invalidateTracks
    config = (AudioSystem::getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_NONE ?
                AUDIO_POLICY_FORCE_SYSTEM_ENFORCED : AUDIO_POLICY_FORCE_NONE);

    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM, config);
    ASSERT_EQ(OK, ret)
            << "Failed to set config " << config << " for use " << AUDIO_POLICY_FORCE_FOR_SYSTEM;

    EXPECT_EQ(invalidationExpectedForPlayer1, audioTrack1->waitForNewIAudioTrack())
            << "Timeout waiting for EVENT_NEW_IAUDIOTRACK event";

    EXPECT_EQ(invalidationExpectedForPlayer2, audioTrack2->waitForNewIAudioTrack())
            << "Timeout waiting for EVENT_NEW_IAUDIOTRACK event";

    ///
    /// Stop player 1
    ///
    audioTrack1->stop();

    ///
    /// Stop player 2
    ///
    audioTrack2->stop();
}

INSTANTIATE_TEST_CASE_P(
        InvalidateTracks,
        SetForceUseInvalidateTracksTest,
        ::testing::Values(
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_MEDIA), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ALARM), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_NOTIFICATION), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_GAME), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANT), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), true},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), true},
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), true}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer_flags(AUDIO_FLAG_AUDIBILITY_ENFORCED), true},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer_flags(AUDIO_FLAG_AUDIBILITY_ENFORCED), true},
               {attributes_initializer_flags(AUDIO_FLAG_AUDIBILITY_ENFORCED), true}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer_flags(AUDIO_FLAG_AUDIBILITY_ENFORCED), true},
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), true}),
            SetForceUseInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ALARM), false},
               {attributes_initializer(AUDIO_USAGE_MEDIA), false})
            )
        );

//
// StartAudioSource Tracks Invalidation
//
// force reevaluating accessibility routing when ringtone or alarm starts
// if (followsSameRouting(clientAttr, attributes_initializer(AUDIO_USAGE_ALARM))) {
//    invalidateAttributes(attributes_initializer(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY));
//}
//
using StartAudioSourceInvalidateTracksTestParams =
std::tuple<const audio_attributes_t /*playerAttributes*/, bool /*invalidationExpected*/,
const audio_attributes_t /*audioSourceAttributes*/,
const audio_port /*sourcePort*/>;

class StartAudioSourceInvalidateTracksTest :
        public AudioPolicyTestBase<StartAudioSourceInvalidateTracksTestParams>
{
public:
    void SetUp() override
    {
        AudioPolicyTestBase::SetUp();
    }

    void TearDown() override
    {
        AudioPolicyTestBase::TearDown();
    }
};

TEST_P(StartAudioSourceInvalidateTracksTest, SinglePlayerSingleAudioSource)
{
    status_t ret = OK;

    const audio_attributes_t aaPlayer = std::get<0>(GetParam());
    const bool invalidationExpectedForPlayer = std::get<1>(GetParam());
    const audio_attributes_t aaAudioSource = std::get<2>(GetParam());
    const audio_port expectedSourcePort = std::get<3>(GetParam());

    ///
    /// Start player
    ///
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(aaPlayer);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  android::toString(aaPlayer);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  android::toString(aaPlayer);

    EXPECT_TRUE(audioTrack->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    ///
    /// Start Audio Source
    ///
    audio_port sourcePort {};

    // Register the device & ensure ports are available
    auto connectSourcePort = [&]() {
        ASSERT_TRUE(connectPort(expectedSourcePort, sourcePort))
                << "Could not connect port: " << dumpPort(expectedSourcePort);
    };
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
                                            &aaAudioSource,
                                            &sourcePortHandle);
        EXPECT_EQ(OK, ret) << "AudioSystem::startAudioSource for source "
                           << sourcePort.ext.device.address << " failed";
    };
    connectAudioSource();

    EXPECT_EQ(invalidationExpectedForPlayer, audioTrack->waitForNewIAudioTrack())
            << "Timeout waiting for EVENT_NEW_IAUDIOTRACK event";

    ///
    /// Stop Audio Source
    ///
    auto releaseAudioSource = [&]() {
        EXPECT_NE(sourcePortHandle, AUDIO_PORT_HANDLE_NONE);
        if (sourcePortHandle != AUDIO_PORT_HANDLE_NONE) {
            ret = AudioSystem::stopAudioSource(sourcePortHandle);
            EXPECT_EQ(OK, ret) << "AudioSystem::stopAudioSource for handle "
                               <<  sourcePortHandle << " failed";
        }
    };
    releaseAudioSource();
    disconnectPort(sourcePort);

    ///
    /// Stop player
    ///
    audioTrack->stop();
}

INSTANTIATE_TEST_CASE_P(
        InvalidateTracks,
        StartAudioSourceInvalidateTracksTest,
        ::testing::Values(
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_MEDIA), false,
                attributes_initializer(AUDIO_USAGE_MEDIA),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_MEDIA), false,
                attributes_initializer(AUDIO_USAGE_ALARM),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), false,
                attributes_initializer(AUDIO_USAGE_MEDIA),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), false,
                attributes_initializer(AUDIO_USAGE_ALARM),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_NOTIFICATION), false,
                attributes_initializer(AUDIO_USAGE_MEDIA),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_NOTIFICATION), false,
                attributes_initializer(AUDIO_USAGE_ALARM),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_NOTIFICATION), false,
                attributes_initializer(AUDIO_USAGE_MEDIA),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}}),
            StartAudioSourceInvalidateTracksTestParams(
               {attributes_initializer(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY), true,
                attributes_initializer(AUDIO_USAGE_ALARM),
                { .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
                  .ext.device.type = AUDIO_DEVICE_IN_FM_TUNER, .ext.device.address = "FM_SW"}})
            )
        );
