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

#include <system/audio.h>
#include <system/audio_effect-base.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <media/AudioAttributes.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioContainers.h>
#include <media/AudioEffect.h>
#include <media/AudioRecord.h>
#include <media/AudioSystem.h>
#include <media/AudioTrack.h>
#include <media/DeviceDescriptorBase.h>
#include <media/TypeConverter.h>

#include <audio_utils/sndfile.h>

#include <iostream>
#include <map>
#include <math.h>
#include <memory>
#include <string>
#include <vector>

#include "policy.h"

#include "AudioTrackTest.hpp"
#include "AudioRecordTest.hpp"

static const bool USE_SW_BRIDGING = true;
static const bool USE_HW_BRIDGING = false;

class Helper
{
public:
    static void changeMode(audio_mode_t mode);

    static bool connectPort(const audio_port &portToConnect, audio_port &connectedPort);

    static std::vector<audio_port> getAvailablePorts();

    static bool isPortConnected(const audio_port &port);

    static bool disconnectPort(const audio_port &portToConnect);

    static bool connectAndCheckDevice(audio_devices_t type, audio_policy_dev_state_t state,
                                      const std::string &address, const std::string &name,
                                      audio_port &devicePort);

    static std::string getPortInfo(audio_port_handle_t portId);

    static android::status_t getPortById(const audio_port_handle_t& portId,
                                         audio_port& portConfig);

    static std::string dumpPortConfig(const audio_port_config &port);

    static std::string dumpPort(const audio_port &port);

    static std::string dumpPort(audio_port_handle_t port);

    static std::string dumpPatch(const audio_patch &patch);

    static std::string toString(audio_devices_t type);

    static std::string toString(const audio_attributes_t &attributes);

    static android::status_t findPort(const audio_port &expectedPort, audio_port &foundPort);

    static android::status_t findPort(audio_port_role_t role, audio_port_type_t type,
                                      audio_devices_t deviceType,
                                      const std::string &address, audio_port &foundPort);

    static void getPort(audio_devices_t type, const std::string &address, audio_port &port);

    static android::status_t getPatchByHandle(audio_patch_handle_t handle, audio_patch &patch);

    static android::status_t getPatches(struct audio_patch *&patches, unsigned int &numPatches);

    static bool checkPatch(audio_io_handle_t mixHandle, audio_port_handle_t portId);

    static bool checkPatch(audio_io_handle_t mixHandle, audio_devices_t deviceType);

    static android::status_t getPatchForOutputMix(audio_io_handle_t mixHandle, audio_patch &patch);

    static android::status_t getPatchForInputMix(audio_io_handle_t mixHandle, audio_patch &patch);

    static bool patchInvolvesDeviceTypes(const audio_patch &patch, audio_devices_t deviceTypes);

    static bool patchInvolvesSinkDevicePort(const audio_patch &patch,
                                            audio_port_handle_t sinkPortId);

    static bool patchInvolvesSourceDevicePort(const audio_patch &patch,
                                              audio_port_handle_t sourcePortId);

    static void checkEstablishedPatch(const audio_patch &patch, const audio_port &sourcePort,
                                      const audio_port &sinkPort,
                                      bool useSwBridge, audio_stream_type_t streamType);

    static bool checkEstablishedPatch(const audio_patch_handle_t &audioPatchHandle,
                                      const audio_port &sourcePort, const audio_port &sinkPort,
                                      bool useSwBridge, audio_stream_type_t streamType);
    static void checkEstablishedPatch(const audio_port &sourcePort, const audio_port &sinkPort,
                                      bool useSwBridge, audio_stream_type_t streamType);

    static void checkPatchRemoved(
            const audio_port &sourcePort, const audio_port &sinkPort,
            const audio_patch_handle_t &audioPatchHandle = AUDIO_PATCH_HANDLE_NONE);

    static void waitEndOfActiveStreams();

    static android::product_strategy_t getStrategyByName(const std::string &name);

    static std::string getStrategyInfo(android::product_strategy_t psId);

    static std::string dumpProductStrategy(android::product_strategy_t psId, bool oneline = false);

    static std::string dumpProductStrategies();

    static void launchPlayer(std::unique_ptr<AudioTrackTest> &audioTrack,
                             android::product_strategy_t strategy,
                             audio_stream_type_t stream,
                             audio_port_handle_t explicitRoutingPortId,
                             audio_port_handle_t expectedRoutingPortId,
                             bool shallBeRouted = true);


    static void launchPlayer(std::unique_ptr<AudioTrackTest> &audioTrack,
                             audio_stream_type_t stream,
                             audio_port_handle_t explicitRoutingPortId,
                             audio_port_handle_t expectedRoutingPortId,
                             bool shallBeRouted = true);

    static std::string dumpVolumeGroups();

    static android::StreamTypeVector getVolumeGroupsStreams(android::volume_group_t groupId);

    static std::vector<audio_attributes_t> getVolumeGroupsAttributes(
            android::volume_group_t groupId);

    static android::status_t getAudioVolumeGroups(android::AudioVolumeGroupVector &groups);

    static const std::vector<audio_usage_t> mAndroidUsages;

    static android::status_t setEffectParameter(const android::sp<android::AudioEffect>& effect,
                                                int32_t param, uint32_t paramSizeMax,
                                                void *pValue, uint32_t valueSize);

    static android::status_t getEffectParameter(const android::sp<android::AudioEffect>& effect,
                                                int32_t param, uint32_t paramSizeMax, void *pValue,
                                                uint32_t valueSize);

    static void playbackOnExplicitDevice(const audio_port &explicitDevicePort,
                                         audio_port_handle_t &routedPort);

    static void captureFromExplicitDevice(const audio_port &explicitDevicePort,
                                          audio_port_handle_t &routedPort);

    static bool isPublicStrategy(const android::AudioProductStrategy &strategy);
};
