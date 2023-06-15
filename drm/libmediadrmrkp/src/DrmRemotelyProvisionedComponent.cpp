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

#define LOG_TAG "DrmRemotelyProvisionedComponent"
#include "DrmRemotelyProvisionedComponent.h"
#include <log/log.h>

namespace android::mediadrm {
DrmRemotelyProvisionedComponent::DrmRemotelyProvisionedComponent(std::shared_ptr<IDrmPlugin> drm)
    : mDrm(drm) {}
ScopedAStatus DrmRemotelyProvisionedComponent::getHardwareInfo(RpcHardwareInfo* info) {
    info->versionNumber = 3;
    info->rpcAuthorName = "<property vendor>";
    info->supportedEekCurve = RpcHardwareInfo::CURVE_NONE;
    info->supportedNumKeysInCsr = RpcHardwareInfo::MIN_SUPPORTED_NUM_KEYS_IN_CSR;
    info->uniqueId = "<property description>";
    return ScopedAStatus::ok();
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateEcdsaP256KeyPair(bool, MacedPublicKey*,
                                                                        std::vector<uint8_t>*) {
    return ScopedAStatus(AStatus_fromExceptionCode(EX_UNSUPPORTED_OPERATION));
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequest(
        bool, const std::vector<MacedPublicKey>&, const std::vector<uint8_t>&,
        const std::vector<uint8_t>&, DeviceInfo*, ProtectedData*, std::vector<uint8_t>*) {
    return ScopedAStatus(AStatus_fromExceptionCode(EX_UNSUPPORTED_OPERATION));
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequestV2(
        const std::vector<MacedPublicKey>&, const std::vector<uint8_t>& challenge,
        std::vector<uint8_t>* csr) {
    // extract csr using setPropertyByteArray/getPropertyByteArray
    auto status = mDrm->setPropertyByteArray("certificateSigningRequestChallenge", challenge);
    if (!status.isOk()) {
        ALOGE("setPropertyByteArray certificateSigningRequestChallenge failed with error code %d",
              status.getServiceSpecificError());
        return status;
    }

    status = mDrm->getPropertyByteArray("certificateSigningRequest", csr);
    if (!status.isOk()) {
        ALOGE("getPropertyByteArray certificateSigningRequest failed with error code %d",
              status.getServiceSpecificError());
        return status;
    }

    return ScopedAStatus::ok();
}
}  // namespace android::mediadrm