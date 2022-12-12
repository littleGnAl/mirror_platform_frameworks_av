/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/EffectHalInterface.h>

#include <aidl/android/hardware/audio/core/BpModule.h>

namespace android {

class DeviceHalAidl final : public DeviceHalInterface {
  public:
    // Sets the value of 'devices' to a bitmask of 1 or more values of audio_devices_t.
    virtual status_t getSupportedDevices(uint32_t *devices);

    // Check to see if the audio hardware interface has been initialized.
    virtual status_t initCheck();

    // Set the audio volume of a voice call. Range is between 0.0 and 1.0.
    virtual status_t setVoiceVolume(float volume) {
        // TODO
        mVoiceVolume = volume;
        ALOGE("%s override me %f", __func__, volume);
        return OK;
    }

    // Set the audio volume for all audio activities other than voice call.
    virtual status_t setMasterVolume(float volume) {
        // TODO
        mMasterVolume = volume;
        ALOGE("%s override me %f", __func__, volume);
        return OK;
    }

    // Get the current master volume value for the HAL.
    virtual status_t getMasterVolume(float *volume) {
        // TODO
        *volume = mMasterVolume;
        ALOGE("%s override me %f", __func__, *volume);
        return OK;
    }

    // Called when the audio mode changes.
    virtual status_t setMode(audio_mode_t mode) {
        // TODO
        ALOGE("%s override me %u", __func__, mode);
        return OK;
    }

    // Muting control.
    virtual status_t setMicMute(bool state) {
        // TODO
        mMicMute = state;
        ALOGE("%s override me %d", __func__, state);
        return OK;
    }
    virtual status_t getMicMute(bool *state) {
        // TODO
        *state = mMicMute;
        ALOGE("%s override me %d", __func__, *state);
        return OK;
    }
    virtual status_t setMasterMute(bool state) {
        // TODO
        mMasterMute = state;
        ALOGE("%s override me %d", __func__, state);
        return OK;
    }
    virtual status_t getMasterMute(bool *state) {
        // TODO
        *state = mMasterMute;
        ALOGE("%s override me %d", __func__, *state);
        return OK;
    }

    // Set global audio parameters.
    virtual status_t setParameters(const String8& kvPairs) {
        // TODO
        ALOGE("%s override me %s", __func__, kvPairs.c_str());
        return OK;
    }

    // Get global audio parameters.
    virtual status_t getParameters(const String8& keys, String8 *values) {
        // TODO
        ALOGE("%s override me %s %s", __func__, keys.c_str(), values->c_str());
        return OK;
    }

    // Returns audio input buffer size according to parameters passed.
    virtual status_t getInputBufferSize(const struct audio_config *config,
            size_t *size) {
        // TODO
        ALOGE("%s override me %p %zu", __func__, config, *size);
        return OK;
    }

    // Creates and opens the audio hardware output stream. The stream is closed
    // by releasing all references to the returned object.
    virtual status_t openOutputStream(audio_io_handle_t handle, audio_devices_t devices,
                                      audio_output_flags_t flags, struct audio_config* config,
                                      const char* address, sp<StreamOutHalInterface>* outStream) {
        ALOGE("%s override me %d %u %u %p %s %p", __func__, handle, devices, flags, config, address,
              outStream);
        return OK;
    }

    // Creates and opens the audio hardware input stream. The stream is closed
    // by releasing all references to the returned object.
    virtual status_t openInputStream(audio_io_handle_t handle, audio_devices_t devices,
                                     struct audio_config* config, audio_input_flags_t flags,
                                     const char* address, audio_source_t source,
                                     audio_devices_t outputDevice, const char* outputDeviceAddress,
                                     sp<StreamInHalInterface>* inStream) {
        ALOGE("%s override me %d %u %u %u %p %s %s %p %d", __func__, handle, devices, outputDevice,
              flags, config, address, outputDeviceAddress, inStream, source);
        return OK;
    }

    // Returns whether createAudioPatch and releaseAudioPatch operations are supported.
    virtual status_t supportsAudioPatches(bool* supportsPatches) {
        *supportsPatches = true;
        return OK;
    }

    // Creates an audio patch between several source and sink ports.
    virtual status_t createAudioPatch(unsigned int num_sources,
                                      const struct audio_port_config* sources,
                                      unsigned int num_sinks, const struct audio_port_config* sinks,
                                      audio_patch_handle_t* patch) {
        ALOGE("%s override me %d %p %d %p %p", __func__, num_sources, sources, num_sinks, sinks,
              patch);
        return OK;
    }

    // Releases an audio patch.
    virtual status_t releaseAudioPatch(audio_patch_handle_t patch) {
        ALOGE("%s override me patch %d", __func__, patch);
        return OK;
    }

    // Set audio port configuration.
    virtual status_t setAudioPortConfig(const struct audio_port_config* config) {
        ALOGE("%s override me config %p", __func__, config);
        return OK;
    }

    // List microphones
    virtual status_t getMicrophones(std::vector<media::MicrophoneInfo>* microphones) {
        ALOGE("%s override me microphones %p", __func__, microphones);
        return OK;
    }

    status_t addDeviceEffect(audio_port_handle_t device, sp<EffectHalInterface> effect)  {
        if (!effect) {
            return BAD_VALUE;
        }
        // TODO
        ALOGE("%s override me device %d", __func__, device);
        return OK;
    }
    status_t removeDeviceEffect(audio_port_handle_t device, sp<EffectHalInterface> effect) {
        if (!effect) {
            return BAD_VALUE;
        }
        // TODO
        ALOGE("%s override me device %d", __func__, device);
        return OK;
    }

    status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType __unused,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos __unused) override {
        // TODO: Implement the HAL query.
        return OK;
    }

    int32_t getAAudioMixerBurstCount() override { return 0; }
    int32_t getAAudioHardwareBurstMinUsec() override { return 0; }

    error::Result<audio_hw_sync_t> getHwAvSync() { return base::unexpected(INVALID_OPERATION); }

    status_t dump(int __unused, const Vector<String16>& __unused) { return OK; };

  private:
    friend class DevicesFactoryHalAidl;
    std::shared_ptr<::aidl::android::hardware::audio::core::IModule> mCore;
    float mMasterVolume, mVoiceVolume;
    bool mMasterMute, mMicMute;

    // Can not be constructed directly by clients.
    explicit DeviceHalAidl(
            const std::shared_ptr<::aidl::android::hardware::audio::core::IModule>& core)
        : mCore(core) {}

    // The destructor automatically closes the device.
    virtual ~DeviceHalAidl();
};

} // namespace android
