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

#include <map>
#include <memory>
#define LOG_TAG "FactoryHal"

#include <algorithm>
#include <array>
#include <cstddef>
#include <dlfcn.h>
#include <utility>

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android/binder_manager.h>
#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <hidl/Status.h>
#include <utils/Log.h>

#include "include/media/audiohal/AudioHalVersionInfo.h"
#include "include/media/audiohal/FactoryHal.h"

namespace android::detail {

namespace {

using ::android::detail::AudioHalVersionInfo;
using aidl::android::hardware::audio::effect::IFactory;

// The pair of the interface's package name and the interface name,
// e.g. <"android.hardware.audio", "IDevicesFactory"> for HIDL, <"android.hardware.audio.core",
// "IModule"> for AIDL.
// Splitting is used for easier construction of versioned names (FQNs).
using InterfaceName = std::pair<std::string, std::string>;

/**
 * Supported HAL versions, from most recent to least recent.
 * This list need to keep sync with AudioHalVersionInfo.VERSIONS in
 * media/java/android/media/AudioHalVersionInfo.java.
 */
static const std::array<AudioHalVersionInfo, 5> sAudioHALVersions = {
    // TODO: remove this comment for AIDL 1.0
    AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, 1, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 7, 1),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 7, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 6, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 5, 0),
    AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 4, 0),
};

static const std::map<AudioHalVersionInfo::Type, InterfaceName> sDevicesHALInterfaces = {
        {AudioHalVersionInfo::Type::AIDL, std::make_pair("android.hardware.audio.core", "IModule")},
        {AudioHalVersionInfo::Type::HIDL,
         std::make_pair("android.hardware.audio", "IDevicesFactory")},
};

static const std::map<AudioHalVersionInfo::Type, InterfaceName> sEffectsHALInterfaces = {
        {AudioHalVersionInfo::Type::AIDL,
         std::make_pair("android.hardware.audio.effect", "IFactory")},
        {AudioHalVersionInfo::Type::HIDL,
         std::make_pair("android.hardware.audio.effect", "IEffectsFactory")},
};

bool createHalService(const AudioHalVersionInfo& version, bool isDevice, void** rawInterface) {
    const std::string libName = "libaudiohal@" + version.toVersionString() + ".so";
    const std::string factoryFunctionName =
            isDevice ? "createIDevicesFactory" : "createIEffectsFactory";
    constexpr int dlMode = RTLD_LAZY;
    void* handle = nullptr;
    dlerror(); // clear
    handle = dlopen(libName.c_str(), dlMode);
    if (handle == nullptr) {
        const char* error = dlerror();
        ALOGE("Failed to dlopen %s: %s", libName.c_str(),
                error != nullptr ? error : "unknown error");
        return false;
    }
    void* (*factoryFunction)();
    *(void **)(&factoryFunction) = dlsym(handle, factoryFunctionName.c_str());
    if (!factoryFunction) {
        const char* error = dlerror();
        ALOGE("Factory function %s not found in library %s: %s",
                factoryFunctionName.c_str(), libName.c_str(),
                error != nullptr ? error : "unknown error");
        dlclose(handle);
        return false;
    }
    *rawInterface = (*factoryFunction)();
    ALOGW_IF(!*rawInterface, "Factory function %s from %s returned nullptr",
            factoryFunctionName.c_str(), libName.c_str());
    return true;
}

bool hasAidlHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    const std::string name = interface.first + "." + interface.second + "/default";
    auto factory =
            IFactory::fromBinder(ndk::SpAIBinder(AServiceManager_checkService(name.c_str())));
    if (factory == nullptr) {
        ALOGE("%s Service %s doesn't exist", __func__, name.c_str());
        return false;
    }

    int versionNumber = 0, expect = version.getMajorVersion();
    if (!factory->getInterfaceVersion(&versionNumber).isOk() || versionNumber != expect) {
        ALOGE("%s version mismatch, expecting %d actual %d", __func__, versionNumber, expect);
        return false;
    }
    return true;
}

bool hasHidlHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    using ::android::hidl::manager::V1_0::IServiceManager;
    sp<IServiceManager> sm = ::android::hardware::defaultServiceManager();
    if (!sm) {
        ALOGE("Failed to obtain HIDL ServiceManager");
        return false;
    }
    // Since audio HAL doesn't support multiple clients, avoid instantiating
    // the interface right away. Instead, query the transport type for it.
    using ::android::hardware::Return;
    using Transport = IServiceManager::Transport;
    const std::string fqName =
            interface.first + "@" + version.toVersionString() + "::" + interface.second;
    const std::string instance = "default";
    Return<Transport> transport = sm->getTransport(fqName, instance);
    if (!transport.isOk()) {
        ALOGE("Failed to obtain transport type for %s/%s: %s",
                fqName.c_str(), instance.c_str(), transport.description().c_str());
        return false;
    }
    return transport != Transport::EMPTY;
}

bool hasHalService(const InterfaceName& interface, const AudioHalVersionInfo& version) {
    auto halType = version.getType();
    if (halType == AudioHalVersionInfo::Type::AIDL) {
        return hasAidlHalService(interface, version);
    } else if (version.getType() == AudioHalVersionInfo::Type::HIDL) {
        return hasHidlHalService(interface, version);
    } else {
        ALOGE("HalType not supported %s", version.toString().c_str());
        return false;
    }
}

}  // namespace

void *createPreferredImpl(bool isDevice) {
    auto findMostRecentVersion = [&]() {
        return std::find_if(sAudioHALVersions.begin(), sAudioHALVersions.end(),
                            [&](const auto& v) {
                                auto type = v.getType();
                                auto iface = isDevice ? sDevicesHALInterfaces.find(type)
                                                      : sEffectsHALInterfaces.find(type);
                                return hasHalService(iface->second, v);
                            });
    };

    auto ifaceVersionIt = findMostRecentVersion();
    auto siblingVersionIt = findMostRecentVersion();
    if (ifaceVersionIt != sAudioHALVersions.end() &&
        siblingVersionIt != sAudioHALVersions.end() &&
        // same major version
        ifaceVersionIt->getMajorVersion() == siblingVersionIt->getMajorVersion()) {
        void* rawInterface;
        if (createHalService(std::max(*ifaceVersionIt, *siblingVersionIt), isDevice,
                             &rawInterface)) {
            return rawInterface;
        }
    }
    return nullptr;
}

}  // namespace android::detail
