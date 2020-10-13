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
// @todo: adapt these test for the Emulator and moves params to the right files
//

#include <gtest/gtest.h>

#include "Helper.hpp"

using namespace android;

using SelectedOutputDeviceTestParams =
std::tuple<const audio_devices_t /* devices to add, none if any */, audio_usage_t,
audio_output_flags_t, audio_mode_t, audio_devices_t /* expected routed device */>;

class SelectedOutputDeviceTest : public ::testing::TestWithParam<SelectedOutputDeviceTestParams> {
protected:
    void SetUp() override
    {
        Helper::waitEndOfActiveStreams();
    }

    void getOutputForAttrAndCheckDevice(const audio_attributes_t &attr,
                                        audio_devices_t device);
};

void SelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(const audio_attributes_t &attr,
                                                              audio_devices_t device )
{
    std::unique_ptr<AudioTrackTest> test = std::make_unique<AudioTrackTest>(attr);
    ASSERT_EQ(OK, test->createTrack()) << "Failed to create AudioTrack";

    audio_port_handle_t returnedPortId = test->getRoutedDeviceId();
    std::cout << "- returnedPortId " << returnedPortId << std::endl;
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, returnedPortId);

    // check port config
    audio_port portConfig;
    status_t status = Helper::getPortById(returnedPortId, portConfig);
    ASSERT_EQ(NO_ERROR, status) << "Could not find port with id=" << returnedPortId;
    ASSERT_EQ(AUDIO_PORT_TYPE_DEVICE, portConfig.type)
            << "Wrong port type selected, expecting " << AUDIO_PORT_TYPE_DEVICE << ", got "
            << portConfig.type;
    std::string deviceLiteral(toString(portConfig.ext.device.type));
    std::string expectedDeviceLiteral(toString(device));;
    ASSERT_EQ(device, portConfig.ext.device.type)
            << "Wrong device selected for output, expecting type=0x" << std::hex << device << " ("
            << expectedDeviceLiteral << "), got type=0x" << portConfig.ext.device.type
            << " (" << deviceLiteral << ")";

    test->stop();
}

TEST_P(SelectedOutputDeviceTest, Output)
{
    audio_attributes_t attr = {};
    attr.usage = std::get<1>(GetParam());
    attr.content_type = AUDIO_CONTENT_TYPE_UNKNOWN;
    attr.flags = std::get<2>(GetParam());
    audio_mode_t mode = std::get<3>(GetParam());
    audio_devices_t addedDevice = std::get<0>(GetParam());
    audio_devices_t expectedDevice = std::get<4>(GetParam());

    std::string addedDeviceLiteral(toString(addedDevice));
    if (addedDevice != AUDIO_DEVICE_NONE) {
        status_t ret = AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::setDeviceConnectionState(device: "
                                 << addedDeviceLiteral.c_str()
                                 << ", state: AVAILABLE, address: none) failed: " << ret;
    }

    Helper::changeMode(mode);
    getOutputForAttrAndCheckDevice(attr, expectedDevice);

    if (addedDevice != AUDIO_DEVICE_NONE) {
        status_t ret = AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::setDeviceConnectionState(device: "
                                 << addedDeviceLiteral.c_str()
                                 << ", state: UNAVAILABLE, address: none) failed: " << ret;
    }
}

class CreatedAudioPatchTest : public ::testing::TestWithParam<SelectedOutputDeviceTestParams> {
protected:
    void SetUp() override
    {
        Helper::waitEndOfActiveStreams();
    }
    void getOutputForAttrAndCheckAudioPatch(const audio_attributes_t &attr,
                                            audio_devices_t devices);
};

void CreatedAudioPatchTest::getOutputForAttrAndCheckAudioPatch(const audio_attributes_t &attr,
                                                               audio_devices_t device)
{
    std::unique_ptr<AudioTrackTest> test = std::make_unique<AudioTrackTest>(attr);
    ASSERT_EQ(OK, test->createTrack()) << "Failed to create AudioTrack";

    audio_port_handle_t returnedPortId = test->getRoutedDeviceId();
    std::cout << "- returnedPortId " << returnedPortId << std::endl;
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, returnedPortId);

    // check port config
    audio_port portConfig;
    status_t status = Helper::getPortById(returnedPortId, portConfig);
    ASSERT_EQ(NO_ERROR, status) << "Could not find port with id=" << returnedPortId;
    ASSERT_EQ(AUDIO_PORT_TYPE_DEVICE, portConfig.type)
            << "Wrong port type selected, expecting " << AUDIO_PORT_TYPE_DEVICE << ", got "
            << portConfig.type;

    test->playSine(returnedPortId);

    EXPECT_TRUE(test->waitForDeviceCb()) << "Timeout on Device cb";

    // get io handle
    audio_io_handle_t ioHandle = test->getOutput();
    ASSERT_NE(AUDIO_IO_HANDLE_NONE, ioHandle) << "Incorrect I/O Handle";

    // Check Patch
    // If no expected routed port, just ensure, the routed device and the track are really
    // connected through an audio patch
    EXPECT_TRUE(Helper::checkPatch(ioHandle, device)) << "No patch involving mix=" << ioHandle
                                                      << " and device port id=" << device;
    test->stop();
}

TEST_P(CreatedAudioPatchTest, Output)
{
    audio_attributes_t attr = {};
    attr.usage = std::get<1>(GetParam());
    attr.content_type = AUDIO_CONTENT_TYPE_UNKNOWN;
    attr.flags = std::get<2>(GetParam());
    audio_mode_t mode = std::get<3>(GetParam());
    audio_devices_t addedDevice = std::get<0>(GetParam());
    audio_devices_t expectedDevice = std::get<4>(GetParam());

    std::string addedDeviceLiteral(toString(addedDevice));
    if (addedDevice != AUDIO_DEVICE_NONE) {
        status_t ret = AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::setDeviceConnectionState(device: "
                                 << addedDeviceLiteral.c_str()
                                 << ", state: AVAILABLE, address: none) failed: " << ret;
    }

    Helper::changeMode(mode);
    getOutputForAttrAndCheckAudioPatch(attr, expectedDevice);

    if (addedDevice != AUDIO_DEVICE_NONE) {
        status_t ret = AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::setDeviceConnectionState(device: "
                                 << addedDeviceLiteral.c_str()
                                 << ", state: UNAVAILABLE, address: none) failed: " << ret;
    }
}

#define MY_WIRED_HEADSET AUDIO_DEVICE_OUT_USB_HEADSET

INSTANTIATE_TEST_CASE_P(
        EarpieceSpeaker,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),

            // Ringtone Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_RINGTONE,
                                           AUDIO_DEVICE_OUT_SPEAKER),

            // InCall Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),

            // InCommunication Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_COMMUNICATION,
                                           AUDIO_DEVICE_OUT_EARPIECE)

            )
        );

INSTANTIATE_TEST_CASE_P(
        EarpieceSpeaker,
        CreatedAudioPatchTest,
        ::testing::Values(
            // Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER)
        )
    );

INSTANTIATE_TEST_CASE_P(
        Headset,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // Headset - Normal Mode
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET)
            )
        );

INSTANTIATE_TEST_CASE_P(
        Headset,
        CreatedAudioPatchTest,
        ::testing::Values(
            // Headset - Normal Mode
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET | AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET | AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET),
            SelectedOutputDeviceTestParams(MY_WIRED_HEADSET, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           MY_WIRED_HEADSET)
            )
        );

INSTANTIATE_TEST_CASE_P(
        A2dpSpeaker,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // A2DP Speaker - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER),
            // A2DP Speaker - In Call Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE)
            )
        );

INSTANTIATE_TEST_CASE_P(
        A2dpHeadphones,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // A2DP Headphones - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            // A2DP Headphones - In Call Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE)
            )
        );

INSTANTIATE_TEST_CASE_P(
        ScoHeadset,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // SCO Headset - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER)
            )
        );

INSTANTIATE_TEST_CASE_P(
        ScoCarkit,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // SCO Headset - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER)
            )
        );

// Hearing Aid
// Not able to test without real devices
#if 0
INSTANTIATE_TEST_CASE_P(
        HearingAid,
        SelectedOutputDeviceTest,
        ::testing::Values(
            // HaeringAid - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_HEARING_AID, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_HEARING_AID)
            )
        );
#endif

/* Test setForceUse */
class ForceScoSelectedOutputDeviceTest : public SelectedOutputDeviceTest  {
protected:
    void getOutputForAttrAndCheckDevice(const audio_attributes_t &attr,
                                        audio_devices_t device);
};

void ForceScoSelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(
        const audio_attributes_t &attr, audio_devices_t device)
{
    SelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(attr, device);
}

TEST_P(ForceScoSelectedOutputDeviceTest, Output)
{
    audio_attributes_t attr = {};
    attr.usage = std::get<1>(GetParam());
    attr.content_type = AUDIO_CONTENT_TYPE_UNKNOWN;
    attr.flags = std::get<2>(GetParam());
    audio_mode_t mode = std::get<3>(GetParam());
    audio_devices_t addedDevice = std::get<0>(GetParam());
    audio_devices_t expectedDevice = std::get<4>(GetParam());

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }

    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_COMMUNICATION,
                                      AUDIO_POLICY_FORCE_BT_SCO);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING,
                                      AUDIO_POLICY_FORCE_BT_SCO);
    Helper::changeMode(mode);
    getOutputForAttrAndCheckDevice(attr, expectedDevice);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_COMMUNICATION,
                                      AUDIO_POLICY_FORCE_NONE);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING,
                                      AUDIO_POLICY_FORCE_NONE);

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }
}

INSTANTIATE_TEST_CASE_P(
        ScoHeadset,
        ForceScoSelectedOutputDeviceTest,
        ::testing::Values(
            // SCO Headset - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            // SCO Headset - InCall Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET)
            )
        );

INSTANTIATE_TEST_CASE_P(
        ScoCarkit,
        ForceScoSelectedOutputDeviceTest,
        ::testing::Values(
            // SCO Carkit - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            // SCO Carkit - InCall Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT)
            )
        );

class ForceNoBtA2dpSelectedOutputDeviceTest : public SelectedOutputDeviceTest  {
protected:
    void getOutputForAttrAndCheckDevice(const audio_attributes_t &attr,
                                        audio_devices_t device);
};

void ForceNoBtA2dpSelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(
        const audio_attributes_t &attr,  audio_devices_t device)
{
    SelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(attr, device);
}

TEST_P(ForceNoBtA2dpSelectedOutputDeviceTest, Output)
{
    audio_attributes_t attr = {};
    attr.usage = std::get<1>(GetParam());
    attr.content_type = AUDIO_CONTENT_TYPE_UNKNOWN;
    attr.flags = std::get<2>(GetParam());
    audio_mode_t mode = std::get<3>(GetParam());
    audio_devices_t addedDevice = std::get<0>(GetParam());
    audio_devices_t expectedDevice = std::get<4>(GetParam());

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }

    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NO_BT_A2DP);
    Helper::changeMode(mode);
    getOutputForAttrAndCheckDevice(attr, expectedDevice);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NONE);

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }
}

INSTANTIATE_TEST_CASE_P(
        A2dpSpeaker,
        ForceNoBtA2dpSelectedOutputDeviceTest,
        ::testing::Values(
            // A2DP Speaker - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER)
            )
        );

INSTANTIATE_TEST_CASE_P(
        A2dpHeadphones,
        ForceNoBtA2dpSelectedOutputDeviceTest,
        ::testing::Values(
            // A2DP Headphones - Normal Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_EARPIECE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER)
            )
        );

class ForceSpeakerSelectedOutputDeviceTest : public SelectedOutputDeviceTest  {
protected:
    void getOutputForAttrAndCheckDevice(const audio_attributes_t &attr,
                                        audio_devices_t device);
};

void ForceSpeakerSelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(
        const audio_attributes_t &attr, audio_devices_t device)
{
    SelectedOutputDeviceTest::getOutputForAttrAndCheckDevice(attr, device);
}

TEST_P(ForceSpeakerSelectedOutputDeviceTest, Output)
{
    audio_attributes_t attr = {};
    attr.usage = std::get<1>(GetParam());
    attr.content_type = AUDIO_CONTENT_TYPE_UNKNOWN;
    attr.flags = std::get<2>(GetParam());
    audio_mode_t mode = std::get<3>(GetParam());
    audio_devices_t addedDevice = std::get<0>(GetParam());
    audio_devices_t expectedDevice = std::get<4>(GetParam());

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }

    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_SPEAKER);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_COMMUNICATION,
                                      AUDIO_POLICY_FORCE_SPEAKER);
    Helper::changeMode(mode);
    getOutputForAttrAndCheckDevice(attr, expectedDevice);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NONE);
    AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_COMMUNICATION,
                                      AUDIO_POLICY_FORCE_NONE);

    if (addedDevice != AUDIO_DEVICE_NONE) {
        AudioSystem::setDeviceConnectionState(
                    addedDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "", "",
                    AUDIO_FORMAT_DEFAULT);
    }
}


INSTANTIATE_TEST_CASE_P(
        EarpeiceSpeaker,
        ForceSpeakerSelectedOutputDeviceTest,
        ::testing::Values(
            // InCall Mode
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_NONE, AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            // InCall Mode while BT SCO
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_IN_CALL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            // Normal while A2DP
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_MEDIA,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ALARM,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_SPEAKER_SAFE),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANCE_SONIFICATION,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES),
            SelectedOutputDeviceTestParams(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                                           AUDIO_USAGE_ASSISTANT,
                                           AUDIO_OUTPUT_FLAG_NONE, AUDIO_MODE_NORMAL,
                                           AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES)
            )
        );
