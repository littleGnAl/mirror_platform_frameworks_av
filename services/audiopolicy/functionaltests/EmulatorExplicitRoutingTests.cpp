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

//
// @todo: adapt these test for the target, use test params and moves params to the right files
//

#include <gtest/gtest.h>

#include "AudioTrackTest.hpp"
#include "AudioTestParams.hpp"
#include "Helper.hpp"
#include "policy.h"

using namespace android;

/**
 * @brief FilteringExpliciRoutingTest
 * Allow playing output to default output device when during uplink playback
 * Change the current behavior of AudioPolicyManager during incall music playback to
 * allow apps that want to play audio with AUDIO_STREAM_MUSIC to default device to route
 * the audio to the default device chosen by the engine (and not the one forced by the
 * ongoing incall music routing). The current behavior still plays the audio to the
 * default output device, which will be set to the TELEPHONY_TX device whenever there is
 * ongoing uplink playback. This change will only affect a case in which uplink playback
 * is in progress and another app tries to play audio using the music stream at that
 * time.
 *
 * Test: Tested manually that the behavior described in the bug is fixed and that both
 * apps can play audio to two different output devices.
 * Bug: 111467967.
 */
TEST(FilteringExpliciRoutingTest, FilteringExpliciRouting)
{
    // Register the devices & ensure ports are not available
    audio_port expectedSinkPort {
        .role = AUDIO_PORT_ROLE_SINK,
        .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
        .ext.device.address = "hfp_client_out"
    };
    audio_port btHfpSinkPort;
    ASSERT_TRUE(Helper::connectPort(expectedSinkPort, btHfpSinkPort));

    audio_port expectedSourcePort {
        .role = AUDIO_PORT_ROLE_SOURCE,
        .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX,
        .ext.device.address = "hfp_client_in"
    };
    audio_port btHfpSourcePort;
    ASSERT_TRUE(Helper::connectPort(expectedSourcePort, btHfpSourcePort));

    audio_stream_type_t stream1 = AUDIO_STREAM_MUSIC;
    audio_devices_t type1 = AUDIO_DEVICE_OUT_TELEPHONY_TX;
    std::string address1 = "hfp_client_out";
    audio_port expectedRoutedPort1;

    audio_stream_type_t stream2 = AUDIO_STREAM_MUSIC;
    audio_devices_t type2 = AUDIO_DEVICE_OUT_BUS;
    std::string address2 = "BUS00_MEDIA";
    audio_port expectedRoutedPort2;

    Helper::getPort(type1, address1, expectedRoutedPort1);

    Helper::getPort(type2, address2, expectedRoutedPort2);

    // Swich to in call mode
    Helper::changeMode(AUDIO_MODE_IN_CALL);

    // Launch track1
    std::unique_ptr<AudioTrackTest> audioTrack1;
    Helper::launchPlayer(audioTrack1, stream1, expectedRoutedPort1.id, expectedRoutedPort1.id);

    // Launch track2
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, stream2, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort2.id);

    audioTrack1->stop();
    audioTrack2->stop();

    // Swich back to in normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    // Unregister the devices & ensure ports are not available any more
    Helper::disconnectPort(btHfpSinkPort);
    Helper::disconnectPort(btHfpSourcePort);
}

TEST(FilteringExpliciRoutingTest2, FilteringExplicitRouting)
{
    audio_stream_type_t stream1 = AUDIO_STREAM_MUSIC;
    audio_devices_t type1 = AUDIO_DEVICE_OUT_TELEPHONY_TX;
    std::string address1 = "hfp_client_out";
    audio_port expectedRoutedPort1;

    audio_stream_type_t stream2 = AUDIO_STREAM_MUSIC;
    audio_devices_t type2 = AUDIO_DEVICE_OUT_BUS;
    std::string address2 = "BUS00_MEDIA";
    audio_port expectedRoutedPort2;

    Helper::getPort(type2, address2, expectedRoutedPort2);

    // Launch track2
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, stream2, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort2.id);

    // Register the devices & ensure ports are not available
    audio_port expectedSinkPort {
        .role = AUDIO_PORT_ROLE_SINK,
        .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_OUT_TELEPHONY_TX,
        .ext.device.address = "hfp_client_out"
    };
    audio_port btHfpSinkPort;
    ASSERT_TRUE(Helper::connectPort(expectedSinkPort, btHfpSinkPort));

    // To be able to switch the mode, we need also an Rx Device
    audio_port expectedSourcePort {
        .role = AUDIO_PORT_ROLE_SOURCE,
        .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX,
        .ext.device.address = "hfp_client_in"
    };
    audio_port btHfpSourcePort;
    ASSERT_TRUE(Helper::connectPort(expectedSourcePort, btHfpSourcePort));

    Helper::getPort(type1, address1, expectedRoutedPort1);

    // Swich to in call mode
    Helper::changeMode(AUDIO_MODE_IN_CALL);

    // Launch track1
    std::unique_ptr<AudioTrackTest> audioTrack1;
    Helper::launchPlayer(audioTrack1, stream1, expectedRoutedPort1.id, expectedRoutedPort1.id);

    audioTrack1->stop();
    audioTrack2->stop();

    // Swich back to in normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    // Unregister the devices & ensure ports are not available any more
    Helper::disconnectPort(btHfpSinkPort);
    Helper::disconnectPort(btHfpSourcePort);
}
