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

#ifndef METRICS_ERROR_H
#define METRICS_ERROR_H

#include <mediadrm/IDrm.h>
#include <sys/random.h>
#include <map>
#include <mutex>

namespace android {

// Keep enums in sync with frameworks/proto_logging/stats/enums/media/drm/enums.proto

enum {
    ENUM_DRM_UNKNOWN = 0,
    ENUM_DRM_NO_LICENSE = 1,
    ENUM_DRM_LICENSE_EXPIRED = 2,
    ENUM_DRM_RESOURCE_BUSY = 3,
    ENUM_DRM_INSUFFICIENT_OUTPUT_PROTECTION = 4,
    ENUM_DRM_SESSION_NOT_OPENED = 5,
    ENUM_DRM_CANNOT_HANDLE = 6,
    ENUM_DRM_INSUFFICIENT_SECURITY = 7,
    ENUM_DRM_FRAME_TOO_LARGE = 8,
    ENUM_DRM_SESSION_LOST_STATE = 9,
    ENUM_DRM_CERTIFICATE_MALFORMED = 10,
    ENUM_DRM_CERTIFICATE_MISSING = 11,
    ENUM_DRM_CRYPTO_LIBRARY = 12,
    ENUM_DRM_GENERIC_OEM = 13,
    ENUM_DRM_GENERIC_PLUGIN = 14,
    ENUM_DRM_INIT_DATA = 15,
    ENUM_DRM_KEY_NOT_LOADED = 16,
    ENUM_DRM_LICENSE_PARSE = 17,
    ENUM_DRM_LICENSE_POLICY = 18,
    ENUM_DRM_LICENSE_RELEASE = 19,
    ENUM_DRM_LICENSE_REQUEST_REJECTED = 20,
    ENUM_DRM_LICENSE_RESTORE = 21,
    ENUM_DRM_LICENSE_STATE = 22,
    ENUM_DRM_MEDIA_FRAMEWORK = 23,
    ENUM_DRM_PROVISIONING_CERTIFICATE = 24,
    ENUM_DRM_PROVISIONING_CONFIG = 25,
    ENUM_DRM_PROVISIONING_PARSE = 26,
    ENUM_DRM_PROVISIONING_REQUEST_REJECTED = 27,
    ENUM_DRM_PROVISIONING_RETRY = 28,
    ENUM_DRM_RESOURCE_CONTENTION = 29,
    ENUM_DRM_SECURE_STOP_RELEASE = 30,
    ENUM_DRM_STORAGE_READ = 31,
    ENUM_DRM_STORAGE_WRITE = 32,
    ENUM_DRM_ZERO_SUBSAMPLES = 33,
    ENUM_DRM_INVALID_STATE = 34,
    ENUM_BAD_VALUE = 35,
    ENUM_DRM_NOT_PROVISIONED = 36,
    ENUM_DRM_DEVICE_REVOKED = 37,
    ENUM_DRM_DECRYPT = 38,
    ENUM_DEAD_OBJECT = 39,
};

struct SessionContext {
    std::string mNonce, mObjNonce, mVersion;
    DrmPlugin::SecurityLevel mTargetSecurityLevel;
    DrmPlugin::SecurityLevel mActualSecurityLevel;
};

class MetricsErrored {
  public:
    MetricsErrored();

    virtual ~MetricsErrored();

    void reportMediaDrmErrored(const std::string name, const DrmStatus& error_code, const char* api,
                               const std::string scheme, const std::array<int64_t, 2> uuid,
                               const IDrmFrontend frontend, const std::string objNonce,
                               const std::string version = "", const std::string sesNonce = "",
                               int actualSecurityLevel = 0) const;

    DrmStatus generateNonce(std::string* out, size_t size, const char* api,
                                        const std::string scheme, const std::array<int64_t, 2> uuid,
                                        const IDrmFrontend frontend);
 
    static const std::map<std::array<int64_t, 2>, std::string> kUuidSchemeMap;

  private:
    DISALLOW_EVIL_CONSTRUCTORS(MetricsErrored);
};

}  // namespace android

#endif  // METRICS_ERROR_H
