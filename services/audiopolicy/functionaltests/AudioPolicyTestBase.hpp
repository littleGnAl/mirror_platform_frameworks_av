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

#pragma once

#include "Helper.hpp"

#include <gtest/gtest.h>

#include <vector>

template<class Param>
class AudioPolicyTestBase : public ::testing::TestWithParam<Param>, public Helper
{
public:
    void SetUp() override
    {
        mBackupedPorts = getAvailablePorts();

        // Test uses telephony devices, if more than one available, policy takes the first
        // To prevent from doubt, disconnect all
        // TODO: change APM to select the best telephony port (the one that could avoid SW bridge?)
        disconnectTelephonyDevices();
    }

    void disconnectTelephonyDevices()
    {
        for (const auto& port : mBackupedPorts) {
            if ((port.type == AUDIO_PORT_TYPE_DEVICE) &&
                    (port.ext.device.type == AUDIO_DEVICE_IN_TELEPHONY_RX ||
                     port.ext.device.type == AUDIO_DEVICE_OUT_TELEPHONY_TX)) {
                disconnectPort(port);
            }
        }
    }

    void TearDown() override
    {
        // Re-connect initially available port
        for (const auto &port : mBackupedPorts) {
            if (port.type != AUDIO_PORT_TYPE_DEVICE) {
                continue;
            }
            audio_port connectedPort;
            ASSERT_TRUE(connectPort(port, connectedPort))
                    << "Could not (re)connect port " << port.name << ", @: "
                    << port.ext.device.address;
        }
        // Disconnect all ports that were connected during test session
        for (const auto &port : getAvailablePorts()) {
            // Cannot rely on ID since the test may disconnect/reconnect and id would change
            if (port.type != AUDIO_PORT_TYPE_DEVICE) {
                continue;
            }
            auto foundPort = std::find_if(std::begin(mBackupedPorts), std::end(mBackupedPorts),
                                          [&port](const auto& backupedPort) {
                return (port.role == backupedPort.role) && (port.type == backupedPort.type) &&
                        (port.ext.device.type == backupedPort.ext.device.type) &&
                        (strncmp(port.ext.device.address,
                                 backupedPort.ext.device.address,
                                 AUDIO_DEVICE_MAX_ADDRESS_LEN) == 0);
            });
            if (foundPort == std::end(mBackupedPorts)) {
                std::cout << "GUSTAVE removing port " << dumpPort(port) << std::endl;
                disconnectPort(port);
            }
        }
    }

public:
    std::vector<audio_port> mBackupedPorts;
};
