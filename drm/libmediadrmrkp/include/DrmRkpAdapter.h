/*
 * Copyright (C) 2023 The Android Open Source Project
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

#ifndef DRM_RKP_ADAPTER_H_
#define DRM_RKP_ADAPTER_H_

#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <aidl/android/hardware/drm/IDrmPlugin.h>
#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>
#include <map>
#include <memory>
#include <string>

using ::aidl::android::hardware::drm::CryptoSchemes;
using ::aidl::android::hardware::drm::IDrmPlugin;
using ::aidl::android::hardware::drm::IDrmFactory;

namespace android::mediadrm {
static std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>> getDrmRemotelyProvisionedComponents(const std::string& in_appPackageName) {
    std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>> comps;
    AServiceManager_forEachDeclaredInstance(
        IDrmFactory::descriptor, static_cast<void*>(&comps),
        [](const char* instance, void* context) {
            auto fullName = std::string(IDrmFactory::descriptor) + "/" + std::string(instance);
            auto factory = IDrmFactory::fromBinder(
                    ::ndk::SpAIBinder(AServiceManager_waitForService(fullName.c_str())));
            if (factory == nullptr) {
                ALOGE("not found IDrmFactory. Instance name:[%s]", fullName.c_str());
                return;
            }


            ALOGI("found IDrmFactory. Instance name:[%s]", fullName.c_str());
            CryptoSchemes schemes{};
            auto status = factory->getSupportedCryptoSchemes(&schemes);
            if (!status.isOk()) {
                ALOGE("getSupportedCryptoSchemes failed with error code %d", status.getServiceSpecificError());
                return;
            }

            if (schemes.uuid.empty()) {
                ALOGW("IDrmFactory Instance [%s] has empty supported schemes", fullName.c_str());
                return;
            }

            std::shared_ptr<IDrmPlugin> mDrm;
            status = factory->createDrmPlugin(schemes.uuids[0], in_appPackageName, &mDrm);
            if (!status.isOk()) {
                ALOGE("createDrmPlugin failed with error code %d", status.getServiceSpecificError());
                return;
            }

            std::shared_ptr<IRemotelyProvisionedComponent> comp = std::make_shared<DrmRemotelyProvisionedComponent>(mDrm);
            std::string compName = "DrmRemotelyProvisionedComponent_" + std::string(instance);
            static_cast<std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>>*>(context)[compName] = comp;
        });
    return comps;
}
} // namespace android::mediadrm

#endif  // DRM_RKP_ADAPTER_H_