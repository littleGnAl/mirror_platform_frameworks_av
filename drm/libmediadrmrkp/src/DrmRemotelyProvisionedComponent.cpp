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

#include "DrmRemotelyProvisionedComponent.h"

namespace android::mediadrm {
ScopedAStatus DrmRemotelyProvisionedComponent::getHardwareInfo(RpcHardwareInfo* info) override {
    info->versionNumber = 3;
    info->rpcAuthorName = "<property vendor>";
    info->supportedEekCurve = RpcHardwareInfo::CURVE_25519;
    info->uniqueId = "<property description>";
    return ScopedAStatus::ok();
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateEcdsaP256KeyPair(bool testMode, MacedPublicKey* macedPublicKey,
                                        std::vector<uint8_t>* privateKeyHandle) override {
    return ScopedAStatus(AStatus_fromExceptionCode(EX_UNSUPPORTED_OPERATION));
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequest(bool testMode,
                                            const std::vector<MacedPublicKey>& keysToSign,
                                            const std::vector<uint8_t>& endpointEncCertChain,
                                            const std::vector<uint8_t>& challenge,
                                            DeviceInfo* deviceInfo, ProtectedData* protectedData,
                                            std::vector<uint8_t>* keysToSignMac) override {
    return ScopedAStatus(AStatus_fromExceptionCode(EX_UNSUPPORTED_OPERATION));
}

ScopedAStatus DrmRemotelyProvisionedComponent::generateCertificateRequestV2(const std::vector<MacedPublicKey>& keysToSign,
                                            const std::vector<uint8_t>& challenge,
                                            std::vector<uint8_t>* csr) override {
    // extract csr using setPropertyByteArray/getPropertyByteArray
    auto status = mDrm->setPropertyByteArray("certificateSigningRequestChallenge", challenge);
    if (!status.isOk()) {
        ALOGE("setPropertyByteArray certificateSigningRequestChallenge failed with error code %d", status.getServiceSpecificError());
        return status;
    }

    status = mDrm->getPropertyByteArray("certificateSigningRequest", csr);
    if (!status.isOk()) {
        ALOGE("getPropertyByteArray certificateSigningRequest failed with error code %d", status.getServiceSpecificError());
        return status;
    }
    
    return ScopedAStatus::ok();
}

std::string DrmRemotelyProvisionedComponent::getDrmPropertyString(const std::string& in_propertyName) const {
    std::string ret = "";
    auto status = mDrm->getPropertyString(in_propertyName, &ret);
    if (!status.isOk()) {
        ALOGE("getPropertyString failed with error code %d", status.getServiceSpecificError());
        return;
    }
    return ret;
}
}