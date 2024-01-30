/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <AudioFlinger.h>
#include <aidl/android/hardware/audio/core/BnConfig.h>
#include <aidl/android/hardware/audio/core/BnModule.h>
#include <aidl/android/hardware/audio/effect/BnFactory.h>
#include <android-base/logging.h>
#include <android/binder_interface_utils.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/media/IAudioPolicyService.h>
#include <fakeservicemanager/FakeServiceManager.h>
#include <fuzzbinder/libbinder_driver.h>
#include <fuzzbinder/random_binder.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/IAudioFlinger.h>
#include <service/AudioPolicyService.h>

using namespace android;
using namespace android::binder;
using android::fuzzService;
using namespace ::aidl::android::media::audio::common;

[[clang::no_destroy]] static std::once_flag gSmOnce;
sp<FakeServiceManager> gFakeServiceManager;

class ConfigMock : public ::aidl::android::hardware::audio::core::BnConfig {
private:
    ndk::ScopedAStatus getSurroundSoundConfig(
            ::aidl::android::hardware::audio::core::SurroundSoundConfig*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getEngineConfig(
            aidl::android::media::audio::common::AudioHalEngineConfig*) override {
        return ndk::ScopedAStatus::ok();
    }
};

class FactoryMock : public ::aidl::android::hardware::audio::effect::BnFactory {
    ::ndk::ScopedAStatus queryEffects(
            const std::optional<::aidl::android::media::audio::common::AudioUuid>&,
            const std::optional<::aidl::android::media::audio::common::AudioUuid>&,
            const std::optional<::aidl::android::media::audio::common::AudioUuid>&,
            std::vector<::aidl::android::hardware::audio::effect::Descriptor>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus queryProcessing(
            const std::optional<::aidl::android::hardware::audio::effect::Processing::Type>&,
            std::vector<::aidl::android::hardware::audio::effect::Processing>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus createEffect(
            const ::aidl::android::media::audio::common::AudioUuid&,
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ::ndk::ScopedAStatus destroyEffect(
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
};

class ModuleMock : public ::aidl::android::hardware::audio::core::BnModule {
  public:
    ModuleMock() {
        // Device ports
        auto outDevice =
                createPort(/* PortId */ 0, /* Name */ "Default",
                           /* Flags */ 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE,
                           /* isInput */ false,
                           createDeviceExt(
                                   /* DeviceType */ AudioDeviceType::OUT_DEFAULT,
                                   /* Flags */ AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE));
        mPorts.push_back(outDevice);
        auto inDevice = createPort(/* PortId */ 1, /* Name */ "Default",
                                   /* Flags */ 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE,
                                   /* isInput */ true,
                                   createDeviceExt(
                                           /* DeviceType */ AudioDeviceType::IN_DEFAULT,
                                           /* Flags */ 0));
        mPorts.push_back(outDevice);
    }

  private:
    ndk::ScopedAStatus setModuleDebug(
            const ::aidl::android::hardware::audio::core::ModuleDebug&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getTelephony(
            std::shared_ptr<::aidl::android::hardware::audio::core::ITelephony>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetooth(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetooth>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothA2dp(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothA2dp>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothLe(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothLe>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus connectExternalDevice(
            const ::aidl::android::media::audio::common::AudioPort&,
            ::aidl::android::media::audio::common::AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus disconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPatches(
            std::vector<::aidl::android::hardware::audio::core::AudioPatch>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPort(int32_t,
                                    ::aidl::android::media::audio::common::AudioPort*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPortConfigs(
            std::vector<::aidl::android::media::audio::common::AudioPortConfig>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPorts(
            std::vector<::aidl::android::media::audio::common::AudioPort>* _aidl_return) override {
        *_aidl_return = mPorts;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutes(
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutesForAudioPort(
            int32_t, std::vector<::aidl::android::hardware::audio::core::AudioRoute>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openInputStream(const OpenInputStreamArguments&,
                                       OpenInputStreamReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openOutputStream(const OpenOutputStreamArguments&,
                                        OpenOutputStreamReturn*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSupportedPlaybackRateFactors(SupportedPlaybackRateFactors*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPatch(const ::aidl::android::hardware::audio::core::AudioPatch&,
                                     ::aidl::android::hardware::audio::core::AudioPatch*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPortConfig(
            const ::aidl::android::media::audio::common::AudioPortConfig&,
            ::aidl::android::media::audio::common::AudioPortConfig*, bool*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPatch(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus resetAudioPortConfig(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMasterMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMasterVolume(float*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterVolume(float) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMicMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicrophones(
            std::vector<::aidl::android::media::audio::common::MicrophoneInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateAudioMode(::aidl::android::media::audio::common::AudioMode) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenRotation(ScreenRotation) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenState(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getSoundDose(
            std::shared_ptr<::aidl::android::hardware::audio::core::sounddose::ISoundDose>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus generateHwAvSyncId(int32_t*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(
            const std::vector<std::string>&,
            std::vector<::aidl::android::hardware::audio::core::VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setVendorParameters(
            const std::vector<::aidl::android::hardware::audio::core::VendorParameter>&,
            bool) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus addDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getMmapPolicyInfos(
            ::aidl::android::media::audio::common::AudioMMapPolicyType,
            std::vector<::aidl::android::media::audio::common::AudioMMapPolicyInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus supportsVariableLatency(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getAAudioMixerBurstCount(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAAudioHardwareBurstMinUsec(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus prepareToDisconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }

    AudioPortExt createDeviceExt(AudioDeviceType devType, int32_t flags) {
        AudioPortDeviceExt deviceExt;
        deviceExt.device.type.type = devType;
        deviceExt.flags = flags;
        return AudioPortExt::make<AudioPortExt::Tag::device>(deviceExt);
    }
    ::aidl::android::media::audio::common::AudioPort createPort(int32_t id, const std::string& name,
                                                                int32_t flags, bool isInput,
                                                                const AudioPortExt& ext) {
        ::aidl::android::media::audio::common::AudioPort port;
        port.id = id;
        port.name = name;
        port.flags = isInput ? AudioIoFlags::make<AudioIoFlags::Tag::input>(flags)
                             : AudioIoFlags::make<AudioIoFlags::Tag::output>(flags);
        port.ext = ext;
        return port;
    }

    std::vector<::aidl::android::media::audio::common::AudioPort> mPorts;
};

bool addService(const String16& serviceName, const sp<FakeServiceManager>& fakeServiceManager,
                FuzzedDataProvider& fdp) {
    sp<IBinder> binder = getRandomBinder(&fdp);
    if (binder == nullptr) {
        return false;
    }
    CHECK_EQ(NO_ERROR, fakeServiceManager->addService(serviceName, binder));
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    std::call_once(gSmOnce, [&] {
        /* Create a FakeServiceManager instance and add required services */
        gFakeServiceManager = sp<FakeServiceManager>::make();
        setDefaultServiceManager(gFakeServiceManager);
    });
    gFakeServiceManager->clear();

    for (const char* service : {"activity", "sensor_privacy", "permission", "scheduling_policy",
                                "batterystats", "media.metrics"}) {
        if (!addService(String16(service), gFakeServiceManager, fdp)) {
            return 0;
        }
    }

    auto configService = ndk::SharedRefBase::make<ConfigMock>();
    CHECK_EQ(NO_ERROR, AServiceManager_addService(configService.get()->asBinder().get(),
                                                  "android.hardware.audio.core.IConfig/default"));

    auto factoryService = ndk::SharedRefBase::make<FactoryMock>();
    CHECK_EQ(NO_ERROR,
             AServiceManager_addService(factoryService.get()->asBinder().get(),
                                        "android.hardware.audio.effect.IFactory/default"));

    auto moduleService = ndk::SharedRefBase::make<ModuleMock>();
    CHECK_EQ(NO_ERROR, AServiceManager_addService(moduleService.get()->asBinder().get(),
                                                  "android.hardware.audio.core.IModule/default"));

    // Disable creating thread pool for fuzzer instance of audio flinger and audio policy services
    AudioSystem::setCanCreateThreadPool(false);

    const auto audioFlinger = sp<AudioFlinger>::make();
    const auto afAdapter = sp<AudioFlingerServerAdapter>::make(audioFlinger);
    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(
                     String16(IAudioFlinger::DEFAULT_SERVICE_NAME), IInterface::asBinder(afAdapter),
                     false /* allowIsolated */, IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT));

    const auto audioPolicyService = sp<AudioPolicyService>::make();
    CHECK_EQ(NO_ERROR,
             gFakeServiceManager->addService(String16("media.audio_policy"), audioPolicyService,
                                             false /* allowIsolated */,
                                             IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT));

    // Initialise the services and enable creation of thread pool for future use
    AudioSystem::get_audio_flinger();
    AudioSystem::get_audio_policy_service();
    AudioSystem::setCanCreateThreadPool(true);

    sp<IBinder> audioFlingerServiceBinder =
            gFakeServiceManager->getService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME));
    sp<media::IAudioFlingerService> audioFlingerService =
            interface_cast<media::IAudioFlingerService>(audioFlingerServiceBinder);

    fuzzService(media::IAudioFlingerService::asBinder(audioFlingerService), std::move(fdp));

    return 0;
}
