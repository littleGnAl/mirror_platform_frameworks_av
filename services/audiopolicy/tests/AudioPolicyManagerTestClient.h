/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <map>
#include <set>

#include <system/audio.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include "AudioPolicyTestClient.h"

namespace android {

class AudioPolicyManagerTestClient : public AudioPolicyTestClient {
public:
    // AudioPolicyClientInterface implementation
    audio_module_handle_t loadHwModule(const char* name) override {
        if (!mAllowedModuleNames.empty() && !mAllowedModuleNames.count(name)) {
            return AUDIO_MODULE_HANDLE_NONE;
        }
        return mNextModuleHandle++;
    }

    status_t openOutput(audio_module_handle_t module,
                        audio_io_handle_t *output,
                        audio_config_t * /*halConfig*/,
                        audio_config_base_t * /*mixerConfig*/,
                        const sp<DeviceDescriptorBase>& /*device*/,
                        uint32_t * /*latencyMs*/,
                        audio_output_flags_t /*flags*/) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }
        *output = mNextIoHandle++;
        return NO_ERROR;
    }

    audio_io_handle_t openDuplicateOutput(audio_io_handle_t /*output1*/,
                                          audio_io_handle_t /*output2*/) override {
        audio_io_handle_t id = mNextIoHandle++;
        return id;
    }

    status_t openInput(audio_module_handle_t module,
                       audio_io_handle_t *input,
                       audio_config_t * /*config*/,
                       audio_devices_t * /*device*/,
                       const String8 & /*address*/,
                       audio_source_t /*source*/,
                       audio_input_flags_t /*flags*/) override {
        if (module >= mNextModuleHandle) {
            ALOGE("%s: Module handle %d has not been allocated yet (next is %d)",
                  __func__, module, mNextModuleHandle);
            return BAD_VALUE;
        }
        *input = mNextIoHandle++;
        return NO_ERROR;
    }

    status_t createAudioPatch(const struct audio_patch *patch,
                              audio_patch_handle_t *handle,
                              int /*delayMs*/) override {
        auto iter = mActivePatches.find(*handle);
        if (iter != mActivePatches.end()) {
            mActivePatches.erase(*handle);
        }
        *handle = mNextPatchHandle++;
        mActivePatches.insert(std::make_pair(*handle, *patch));
        return NO_ERROR;
    }

    status_t releaseAudioPatch(audio_patch_handle_t handle,
                               int /*delayMs*/) override {
        if (mActivePatches.erase(handle) != 1) {
            if (handle >= mNextPatchHandle) {
                ALOGE("%s: Patch handle %d has not been allocated yet (next is %d)",
                      __func__, handle, mNextPatchHandle);
            } else {
                ALOGE("%s: Attempt to release patch %d twice", __func__, handle);
            }
            return BAD_VALUE;
        }
        return NO_ERROR;
    }

    void onAudioPortListUpdate() override {
        ++mAudioPortListUpdateCount;
    }

    status_t setDeviceConnectedState(const struct audio_port_v7 *port,
                                     media::DeviceConnectedState state) override {
        if (state == media::DeviceConnectedState::CONNECTED) {
            mConnectedDevicePorts.push_back(*port);
        } else if (state == media::DeviceConnectedState::DISCONNECTED){
            mDisconnectedDevicePorts.push_back(*port);
        }
        return NO_ERROR;
    }

    // Helper methods for tests
    size_t getActivePatchesCount() const { return mActivePatches.size(); }

    const struct audio_patch *getLastAddedPatch() const {
        if (mActivePatches.empty()) {
            return nullptr;
        }
        auto it = --mActivePatches.end();
        return &it->second;
    };

    audio_module_handle_t peekNextModuleHandle() const { return mNextModuleHandle; }

    void swapAllowedModuleNames(std::set<std::string>&& names = {}) {
        mAllowedModuleNames.swap(names);
    }

    size_t getAudioPortListUpdateCount() const { return mAudioPortListUpdateCount; }

    virtual void addSupportedFormat(audio_format_t /* format */) {}

    void onRoutingUpdated() override {
        mRoutingUpdatedUpdateCount++;
    }

    void resetRoutingUpdatedCounter() {
        mRoutingUpdatedUpdateCount = 0;
    }

    size_t getRoutingUpdatedCounter() const {
        return mRoutingUpdatedUpdateCount;
    }

    void onVolumeRangeInitRequest() override {

    }

    status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs __unused) override {
        return NO_ERROR;
    }

    size_t getConnectedDevicePortCount() const {
        return mConnectedDevicePorts.size();
    }

    const struct audio_port_v7 *getLastConnectedDevicePort() const {
        if (mConnectedDevicePorts.empty()) {
            return nullptr;
        }
        auto it = --mConnectedDevicePorts.end();
        return &(*it);
    }

    size_t getDisconnectedDevicePortCount() const {
        return mDisconnectedDevicePorts.size();
    }

    const struct audio_port_v7 *getLastDisconnectedDevicePort() const {
        if (mDisconnectedDevicePorts.empty()) {
            return nullptr;
        }
        auto it = --mDisconnectedDevicePorts.end();
        return &(*it);
    }

private:
    audio_module_handle_t mNextModuleHandle = AUDIO_MODULE_HANDLE_NONE + 1;
    audio_io_handle_t mNextIoHandle = AUDIO_IO_HANDLE_NONE + 1;
    audio_patch_handle_t mNextPatchHandle = AUDIO_PATCH_HANDLE_NONE + 1;
    std::map<audio_patch_handle_t, struct audio_patch> mActivePatches;
    std::set<std::string> mAllowedModuleNames;
    size_t mAudioPortListUpdateCount = 0;
    size_t mRoutingUpdatedUpdateCount = 0;
    std::vector<struct audio_port_v7> mConnectedDevicePorts;
    std::vector<struct audio_port_v7> mDisconnectedDevicePorts;
};

} // namespace android
