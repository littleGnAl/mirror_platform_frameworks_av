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
 * @brief TEST for non regression of Bug: 109640706
 * "audiopolicy: fix VoIP and system sound routing concurrency"
 *
 * 1 - The route declared in configuration file shall be a mix:
 *
 *  <route type="mix" sink="bus4_usage_voice"
 *          sources="mixport_bus4_usage_voice_output,mixport_bus3_usage_system_direct_output"/>
 *
 *  It means Output profile for system will also accept to be routed on bus4_usage_voice
 * Music Output profile will not, so the device assigned will remain the same
 *
 * AudioTrack1 (stream type VOICE_CALL) follows a strategy with higher prio than AudioTrack2 (stream
 * type SYSTEM_SOUND).
 * The getNewOutputDevices will consider the strategy for voice call stream first when evaluating
 * the device for AudioTrack2.
 * If AudioTrack1 is started, evaluation of stream on same HwModule leads to select the device of
 * AudioTrack1 for AudioTrack2.
 * As the route is declared, bus4_usage_call is supported by the profile for SystemSound.
 *
 * AudioTrack3 (stream type music) does not support the sink BUS04_USAGE_VOICE, so will not
 * be routed to bus4_usage_call device.
 */
TEST(RoutingConcurrencyTest, RoutingConcurrency)
{
    audio_stream_type_t stream1 = AUDIO_STREAM_VOICE_CALL;
    audio_devices_t type1 = AUDIO_DEVICE_OUT_BUS;
    std::string address1 = "BUS04_USAGE_VOICE";
    audio_port expectedRoutedPort1;

    audio_stream_type_t stream2 = AUDIO_STREAM_SYSTEM;
    audio_devices_t type2 = AUDIO_DEVICE_OUT_BUS;
    std::string address2 = "BUS03_USAGE_SYSTEM";
    audio_port expectedRoutedPort2;

    audio_stream_type_t stream3 = AUDIO_STREAM_MUSIC;
    audio_devices_t type3 = AUDIO_DEVICE_OUT_BUS;
    std::string address3 = "BUS00_USAGE_MAIN";
    audio_port expectedRoutedPort3;

    Helper::getPort(type1, address1, expectedRoutedPort1);
    Helper::getPort(type2, address2, expectedRoutedPort2);
    Helper::getPort(type3, address3, expectedRoutedPort3);

    // Now do the same with only the track, not the mode change to ensure the rule
    // isAnyStreamActiveOnSameModule works and the check of supportsPatch as well
    // Launch track1
    std::unique_ptr<AudioTrackTest> audioTrack1;
    Helper::launchPlayer(audioTrack1, stream1, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort1.id);

    // Launch track2
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, stream2, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort1.id);

    // Launch track3  -> shall not be routed as not supporting BUS04_USAGE_VOICE device
    std::unique_ptr<AudioTrackTest> audioTrack3;
    Helper::launchPlayer(audioTrack3, stream3, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort3.id,
                         false /*shallBeRouted*/);

    // Check the port of audioTrack1 is the same
    audio_port_handle_t inCommPort = audioTrack1->getRoutedDeviceId();
    EXPECT_EQ(audioTrack1->getRoutedDeviceId(), expectedRoutedPort1.id)
            << "voice stream track routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort1) << "\n"
            << ", got: " << Helper::dumpPort(inCommPort);

    audioTrack1->stop();

    // Check the port of audioTrack2 again
    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort2.id)) << "Timeout for Device cb";
    audio_port_handle_t normalPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(normalPort, expectedRoutedPort2.id)
            << "track2 (while no active stream call) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort2) << "\n"
            << ", got: " <<Helper::dumpPort(normalPort);

    // Check Track 2 patch (really routed)
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort2.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort2.id;

    // Check the port of audioTrack3 again
    EXPECT_TRUE(audioTrack3->waitForDeviceCb(expectedRoutedPort3.id)) << "Timeout for Device cb";
    audio_port_handle_t notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "track3 (while no active stream call) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " <<Helper::dumpPort(notificationPort);

    // Check Track 3 patch (Now track 3 shall be routed)
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    audioTrack2->stop();
    audioTrack3->stop();
}

TEST(RoutingConcurrencyTest3, RoutingConcurrency)
{
    audio_stream_type_t stream1 = AUDIO_STREAM_VOICE_CALL;
    audio_devices_t type1 = AUDIO_DEVICE_OUT_BUS;
    std::string address1 = "BUS04_USAGE_VOICE";
    audio_port expectedRoutedPort1;

    audio_stream_type_t stream2 = AUDIO_STREAM_SYSTEM;
    audio_devices_t type2 = AUDIO_DEVICE_OUT_BUS;
    std::string address2 = "BUS03_USAGE_SYSTEM";
    audio_port expectedRoutedPort2;

    audio_stream_type_t stream3 = AUDIO_STREAM_MUSIC;
    audio_devices_t type3 = AUDIO_DEVICE_OUT_BUS;
    std::string address3 = "BUS00_USAGE_MAIN";
    audio_port expectedRoutedPort3;


    Helper::getPort(type1, address1, expectedRoutedPort1);
    Helper::getPort(type2, address2, expectedRoutedPort2);
    Helper::getPort(type3, address3, expectedRoutedPort3);

    // Launch track2
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, stream2, AUDIO_PORT_HANDLE_NONE,expectedRoutedPort2.id);

    // Launch track3  -> shall not be routed as not supporting BUS04_USAGE_VOICE device
    std::unique_ptr<AudioTrackTest> audioTrack3;
    Helper::launchPlayer(audioTrack3, stream3, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort3.id);


    // Now launch track1, track 2 and track 3 will remain on their respective device
    std::unique_ptr<AudioTrackTest> audioTrack1;
    Helper::launchPlayer(audioTrack1, stream1, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort1.id);

    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort2.id)) << "Timeout for Device cb";
    EXPECT_TRUE(audioTrack3->waitForDeviceCb(expectedRoutedPort3.id)) << "Timeout for Device cb";
    audio_port_handle_t normalPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(normalPort, expectedRoutedPort2.id)
            << "track2 (stream call started after) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort2) << "\n"
            << ", got: " <<Helper::dumpPort(normalPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort2.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort2.id;

    audio_port_handle_t notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "track3 (stream call started after) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " <<Helper::dumpPort(notificationPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    // Stop again track1 (with voice stream)
    audioTrack1->stop();

    // Check the port of audioTrack2 again
    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort2.id)) << "Timeout for Device cb";
    normalPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(normalPort, expectedRoutedPort2.id)
            << "track2 (while no active stream call) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort2) << "\n"
            << ", got: " <<Helper::dumpPort(normalPort);

    // Check Track 2 patch (really routed)
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort2.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort2.id;

    // Check the port of audioTrack3 again
    EXPECT_TRUE(audioTrack3->waitForDeviceCb(expectedRoutedPort3.id)) << "Timeout for Device cb";
    notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "track3 (while no active stream call) routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " <<Helper::dumpPort(notificationPort);

    // Check Track 3 patch (Now track 3 shall be routed)
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    audioTrack2->stop();
    audioTrack3->stop();
}

/**
 * @brief TEST same test as previous but using android mode change instead of VOICE stream
 * to cover all the conditions within getNewOutputDevices
 */
TEST(RoutingConcurrency2Test, RoutingConcurrency)
{
    audio_devices_t type1 = AUDIO_DEVICE_OUT_BUS;
    std::string address1 = "BUS04_USAGE_VOICE";
    audio_port expectedRoutedPort1;

    /**
     * During voip call, system stream to be routed on same backend as voice downlink
     * (ensure engine configuration file match this test), out of call on SystemSound bus
     */
    audio_stream_type_t stream2 = AUDIO_STREAM_SYSTEM;
    audio_devices_t type2 = AUDIO_DEVICE_OUT_BUS;
    std::string address2 = "BUS03_USAGE_SYSTEM";
    audio_port expectedRoutedPort2;

    audio_stream_type_t stream3 = AUDIO_STREAM_MUSIC;
    audio_devices_t type3 = AUDIO_DEVICE_OUT_BUS;
    std::string address3 = "BUS00_USAGE_MAIN";
    audio_port expectedRoutedPort3;

    Helper::getPort(type1, address1, expectedRoutedPort1);
    Helper::getPort(type2, address2, expectedRoutedPort2);
    Helper::getPort(type3, address3, expectedRoutedPort3);


     // Launch track2 out of call first
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, stream2, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort2.id);

    // Launch track3 out of call first
    std::unique_ptr<AudioTrackTest> audioTrack3;
    Helper::launchPlayer(audioTrack3, stream3, AUDIO_PORT_HANDLE_NONE, expectedRoutedPort3.id);

    // Swich to in comm mode
    Helper::changeMode(AUDIO_MODE_IN_COMMUNICATION);

    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort1.id)) << "Timeout for Device cb";
    audio_port_handle_t inCommPort = audioTrack2->getRoutedDeviceId();

    EXPECT_EQ(inCommPort, expectedRoutedPort1.id)
            << "In communication routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort1) << "\n"
            << ", got: " << Helper::dumpPort(inCommPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort1.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort1.id;

    audio_port_handle_t notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "In communication routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " << Helper::dumpPort(notificationPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    // Swich back to in normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    // Check the port of audioTrack2 again
    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort2.id)) << "Timeout for Device cb";
    audio_port_handle_t normalPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(normalPort, expectedRoutedPort2.id)
            << "NORMAL MODE routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort2) << "\n"
            << ", got: " << Helper::dumpPort(normalPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort2.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort2.id;


    notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "NORMAL MODE routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " <<Helper::dumpPort(notificationPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    // Swich to in comm mode
    Helper::changeMode(AUDIO_MODE_IN_COMMUNICATION);

    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort1.id)) << "Timeout for Device cb";
    inCommPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(inCommPort, expectedRoutedPort1.id)
            << "In communication routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort1) << "\n"
            << ", got: " << Helper::dumpPort(inCommPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort1.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort1.id;

    notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "NORMAL MODE routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " << Helper::dumpPort(notificationPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    // Swich back to in normal mode
    Helper::changeMode(AUDIO_MODE_NORMAL);

    // Check the port of audioTrack2 again
    EXPECT_TRUE(audioTrack2->waitForDeviceCb(expectedRoutedPort2.id)) << "Timeout for Device cb";
    normalPort = audioTrack2->getRoutedDeviceId();
    EXPECT_EQ(normalPort, expectedRoutedPort2.id)
            << "NORMAL MODE routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort2) << "\n"
            << ", got: " << Helper::dumpPort(normalPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack2->getOutput(), expectedRoutedPort2.id))
            << "No patch found involving mix port " << audioTrack2->getOutput()
            << " and device port " << expectedRoutedPort2.id;

    notificationPort = audioTrack3->getRoutedDeviceId();
    EXPECT_EQ(notificationPort, expectedRoutedPort3.id)
            << "NORMAL MODE routing device does not match expected port \n"
            << "expected: " << Helper::dumpPort(expectedRoutedPort3) << "\n"
            << ", got: " << Helper::dumpPort(notificationPort);
    EXPECT_TRUE(Helper::checkPatch(audioTrack3->getOutput(), expectedRoutedPort3.id))
            << "No patch found involving mix port " << audioTrack3->getOutput()
            << " and device port " << expectedRoutedPort3.id;

    audioTrack2->stop();
    audioTrack3->stop();
}
