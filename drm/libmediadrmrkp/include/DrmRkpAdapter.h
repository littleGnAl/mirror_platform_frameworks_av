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

#include <aidl/android/hardware/security/keymint/BnRemotelyProvisionedComponent.h>
#include <map>
#include <string>

namespace android::mediadrm {
using IRemotelyProvisionedComponent =
        ::aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
std::map<std::string, std::shared_ptr<IRemotelyProvisionedComponent>>
getDrmRemotelyProvisionedComponents();
}  // namespace android::mediadrm

#endif  // DRM_RKP_ADAPTER_H_