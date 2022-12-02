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


#define LOG_TAG "FactoryHal"

#include <algorithm>
#include <array>
#include <dlfcn.h>
#include <utility>

#include <android/hidl/manager/1.0/IServiceManager.h>
#include <hidl/ServiceManagement.h>
#include <hidl/Status.h>
#include <utils/Log.h>

#include "include/media/audiohal/FactoryHal.h"

namespace android::detail {

namespace {

using android::media::AudioHalVersion;

/**
 * Supported HAL versions, from most recent to least recent.
 * This list need to keep sync with AudioHalVersionInfo.VERSIONS in
 * media/java/android/media/AudioHalVersionInfo.java.
 */
static const std::array<AudioHalVersionInfo, 6> sAudioHALVersions = {
    AudioHalVersionInfo(AudioHalVersion::Type::AIDL, 1, 0),
    AudioHalVersionInfo(AudioHalVersion::Type::HIDL, 7, 1),
    AudioHalVersionInfo(AudioHalVersion::Type::HIDL, 7, 0),
    AudioHalVersionInfo(AudioHalVersion::Type::HIDL, 6, 0),
    AudioHalVersionInfo(AudioHalVersion::Type::HIDL, 5, 0),
    AudioHalVersionInfo(AudioHalVersion::Type::HIDL, 4, 0),
};

bool createHalService(const AudioHalVersionInfo& version, const std::string& interface,
        void** rawInterface) {
    const std::string libName = "libaudiohal@" + version.toVersionString() + ".so";
    const std::string factoryFunctionName = "create" + interface;
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

bool hasAidlHalService(const std::string& package, const AudioHalVersionInfo& version,
                       const std::string& interface) {
    const std::string fqName = package + "@" + version.toVersionString() + "::" + interface;
    ALOGW("AIDL HAL not implemented yet: %s", fqName.c_str());
    return false;
}

bool hasHidlHalService(const std::string& package, const AudioHalVersionInfo& version,
                       const std::string& interface) {
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
    const std::string fqName = package + "@" + version.toVersionString() + "::" + interface;
    const std::string instance = "default";
    Return<Transport> transport = sm->getTransport(fqName, instance);
    if (!transport.isOk()) {
        ALOGE("Failed to obtain transport type for %s/%s: %s",
                fqName.c_str(), instance.c_str(), transport.description().c_str());
        return false;
    }
    return transport != Transport::EMPTY;
}

bool hasHalService(const std::string& package, const AudioHalVersionInfo& version,
                   const std::string& interface) {

    auto halType = version.getType();
    if (halType == AudioHalVersion::Type::AIDL) {
        return hasAidlHalService(package, version, interface);
    } else if (version.getType() == AudioHalVersion::Type::HIDL) {
        return hasHidlHalService(package, version, interface);
    } else {
        ALOGE("HalType not supported %s", version.toString().c_str());
        return false;
    }
}

}  // namespace

void* createPreferredImpl(const InterfaceName& iface, const InterfaceName& siblingIface) {
    auto findMostRecentVersion = [](const InterfaceName& iface) {
        return std::find_if(
                detail::sAudioHALVersions.begin(), detail::sAudioHALVersions.end(),
                [&](const auto& v) { return hasHalService(iface.first, v, iface.second); });
    };
    auto ifaceVersionIt = findMostRecentVersion(iface);
    auto siblingVersionIt = findMostRecentVersion(siblingIface);
    if (ifaceVersionIt != detail::sAudioHALVersions.end() &&
        siblingVersionIt != detail::sAudioHALVersions.end() &&
        // same major version
        ifaceVersionIt->getMajorVersion() == siblingVersionIt->getMajorVersion()) {
        void* rawInterface;
        if (createHalService(std::max(*ifaceVersionIt, *siblingVersionIt), iface.second,
                             &rawInterface)) {
            return rawInterface;
        }
    }
    return nullptr;
}

}  // namespace android::detail
