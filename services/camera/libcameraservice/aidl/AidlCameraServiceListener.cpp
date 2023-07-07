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

#include <aidl/AidlCameraServiceListener.h>
#include <aidl/AidlUtils.h>
#include <aidl/android/frameworks/cameraservice/common/Status.h>
#include <aidl/android/frameworks/cameraservice/service/CameraStatusAndId.h>

namespace android::frameworks::cameraservice::service::implementation {

using ::android::hardware::cameraservice::utils::conversion::aidl::convertCameraStatusToAidl;
// VNDK classes
using SCameraStatusAndId = ::aidl::android::frameworks::cameraservice::service::CameraStatusAndId;
using SStatus = ::aidl::android::frameworks::cameraservice::common::Status;

binder::Status AidlCameraServiceListener::onStatusChanged(
        int32_t status, const ::android::String16& cameraId) {
    SCameraDeviceStatus sStatus = convertCameraStatusToAidl(status);
    std::string sCameraId = String8(cameraId).string();
    auto ret = mBase->onStatusChanged(sStatus, sCameraId);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onStatusChanged")
    return binder::Status::ok();
}

binder::Status AidlCameraServiceListener::onPhysicalCameraStatusChanged(
        int32_t status, const ::android::String16& cameraId,
        const ::android::String16& physicalCameraId) {
    SCameraDeviceStatus sStatus = convertCameraStatusToAidl(status);
    std::string sCameraId = String8(cameraId).string();
    std::string sPhysicalCameraId = String8(physicalCameraId).string();

    auto ret = mBase->onPhysicalCameraStatusChanged(sStatus, sCameraId, sPhysicalCameraId);
    LOG_STATUS_ERROR_IF_NOT_OK(ret, "onPhysicalCameraStatusChanged")
    return binder::Status::ok();
}

::android::binder::Status AidlCameraServiceListener::onTorchStatusChanged(
    int32_t, const ::android::String16&) {
  // We don't implement onTorchStatusChanged
  return binder::Status::ok();
}

::android::binder::Status AidlCameraServiceListener::onTorchStrengthLevelChanged(
    const ::android::String16&, int32_t) {
    // We don't implement onTorchStrengthLevelChanged
    return binder::Status::ok();
}
status_t AidlCameraServiceListener::linkToDeath(const sp<DeathRecipient>& recipient, void* cookie,
                                                uint32_t flags) {
    return mDeathPipe.linkToDeath(recipient, cookie, flags);
}
status_t AidlCameraServiceListener::unlinkToDeath(const wp<DeathRecipient>& recipient, void* cookie,
                                                  uint32_t flags,
                                                  wp<DeathRecipient>* outRecipient) {
    return mDeathPipe.unlinkToDeath(recipient, cookie, flags, outRecipient);
}

} // namespace android::frameworks::cameraservice::service::implementation
