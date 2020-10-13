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

#include "AudioTestParams.hpp"
#include "Helper.hpp"

#include <gtest/gtest.h>
#include <private/android_filesystem_config.h>

using namespace android;

static int resetVolumeIndex(int indexMin, int indexMax)
{
    return (indexMax + indexMin) / 2;
}

static void incrementVolumeIndex(int &index, int indexMin, int indexMax)
{
    index = (index + 1 > indexMax) ? resetVolumeIndex(indexMin, indexMax) : ++index;
}

class DeviceConnectionTest : public ::testing::TestWithParam<DeviceConnectionTestParams> {};

TEST_P(DeviceConnectionTest, DeviceConnectionState)
{
    status_t ret;
    audio_devices_t type = std::get<0>(GetParam());
    audio_policy_dev_state_t state = std::get<3>(GetParam());
    std::string address = std::get<2>(GetParam());
    std::string name = std::get<1>(GetParam());
    audio_mode_t mode = std::get<4>(GetParam());

    audio_port devicePort;
    ASSERT_TRUE(Helper::connectAndCheckDevice(type, state, address, name, devicePort));

    // Swich to requested mode
    ret = AudioSystem::setMode(mode);
    EXPECT_EQ(ret, NO_ERROR) << "AudioSystem::setMode failed: " << ret;

    ret = AudioSystem::setPhoneState(mode, AID_AUDIOSERVER);
    EXPECT_EQ(ret, NO_ERROR) << "AudioSystem::setPhoneState failed: " << ret;

    if (state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE) {
        // Why? because if previous test is playing, the disconnection of device has cleared
        // the preferred device but strategy is still active and device selected will be the one
        // on the active client on the output.
        Helper::waitEndOfActiveStreams();

        audio_port_handle_t routedPort;
        // Try a playback or capture according to the device type
        if (audio_is_output_devices(type)) {
            Helper::playbackOnExplicitDevice(devicePort, routedPort);
        } else if (audio_is_input_device(type)) {
            Helper::captureFromExplicitDevice(devicePort, routedPort);
        }
        EXPECT_EQ(devicePort.id, routedPort)
                << "Explicit Routing for Device " << name << " failed\n"
                << "Routed on " << Helper::dumpPort(routedPort) << "\n"
                << "Expecting " << Helper::dumpPort(devicePort);
    }
    // Swich back to normal mode
    ret = AudioSystem::setMode(AUDIO_MODE_NORMAL);
    EXPECT_EQ(ret, NO_ERROR) << "AudioSystem::setMode(mode AUDIO_MODE_NORMAL) failed: " << ret;

    ret = AudioSystem::setPhoneState(AUDIO_MODE_NORMAL, AID_AUDIOSERVER);
    EXPECT_EQ(ret, NO_ERROR) << "AudioSystem::setPhoneState(mode: AUDIO_MODE_NORMAL) failed: "
                             << ret;
}

/**
 * @brief DynamicAddressInputDevice
 * This test aims to test connection / disconnection of input device with unknown device address.
 * Only the type is declared in the primary audio policy configuration file.
 */
INSTANTIATE_TEST_CASE_P(
        DynamicAddressInputDevice,
        DeviceConnectionTest,
        ::testing::ValuesIn(AudioTestParams::getDynamicAddressInputDeviceTestParams())
        );

/**
 * @brief DynamicAddressOutputDevice
 * This test aims to test connection / disconnection of output device with unknown device address.
 * Only the type is declared in the primary audio policy configuration file.
 */
INSTANTIATE_TEST_CASE_P(
        DynamicAddressOutputDevice,
        DeviceConnectionTest,
        ::testing::ValuesIn(AudioTestParams::getDynamicAddressOutputDeviceTestParams())
        );

/**
 * @brief DeclaredAddressInputDevice
 * This test aims to test connection / disconnection of input declared device with known device
 * address.
 * The address in the test must be in the primary audio policy configuration file.
 */
INSTANTIATE_TEST_CASE_P(
        DeclaredAddressInputDevice,
        DeviceConnectionTest,
        ::testing::ValuesIn(AudioTestParams::getDeclaredAddressInputDeviceTestParams())
        );

/**
 * @brief DeclaredAddressOutputDevice
 * This test aims to test connection / disconnection of output declared device with known device
 * address.
 * The address in the test must be in the primary audio policy configuration file.
 */
INSTANTIATE_TEST_CASE_P(
        DeclaredAddressOutputDevice,
        DeviceConnectionTest,
        ::testing::ValuesIn(AudioTestParams::getDeclaredAddressOutputDeviceTestParams())
        );
