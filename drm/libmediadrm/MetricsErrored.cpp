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

// #define LOG_NDEBUG 0
#define LOG_TAG "MetricsErrored"

#include <media/MediaMetrics.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/base64.h>
#include <mediadrm/MetricsErrored.h>

namespace android {

MetricsErrored::MetricsErrored() {}

MetricsErrored::~MetricsErrored() {}

int MediaErrorToEnum(status_t err) {
#define ERROR_BAD_VALUE (BAD_VALUE)
#define ERROR_DEAD_OBJECT (DEAD_OBJECT)
#define STATUS_CASE(status) \
    case ERROR_##status: \
        return ENUM_##status

    switch (err) {
        STATUS_CASE(DRM_UNKNOWN);
        STATUS_CASE(DRM_NO_LICENSE);
        STATUS_CASE(DRM_LICENSE_EXPIRED);
        STATUS_CASE(DRM_RESOURCE_BUSY);
        STATUS_CASE(DRM_INSUFFICIENT_OUTPUT_PROTECTION);
        STATUS_CASE(DRM_SESSION_NOT_OPENED);
        STATUS_CASE(DRM_CANNOT_HANDLE);
        STATUS_CASE(DRM_INSUFFICIENT_SECURITY);
        STATUS_CASE(DRM_FRAME_TOO_LARGE);
        STATUS_CASE(DRM_SESSION_LOST_STATE);
        STATUS_CASE(DRM_CERTIFICATE_MALFORMED);
        STATUS_CASE(DRM_CERTIFICATE_MISSING);
        STATUS_CASE(DRM_CRYPTO_LIBRARY);
        STATUS_CASE(DRM_GENERIC_OEM);
        STATUS_CASE(DRM_GENERIC_PLUGIN);
        STATUS_CASE(DRM_INIT_DATA);
        STATUS_CASE(DRM_KEY_NOT_LOADED);
        STATUS_CASE(DRM_LICENSE_PARSE);
        STATUS_CASE(DRM_LICENSE_POLICY);
        STATUS_CASE(DRM_LICENSE_RELEASE);
        STATUS_CASE(DRM_LICENSE_REQUEST_REJECTED);
        STATUS_CASE(DRM_LICENSE_RESTORE);
        STATUS_CASE(DRM_LICENSE_STATE);
        STATUS_CASE(DRM_MEDIA_FRAMEWORK);
        STATUS_CASE(DRM_PROVISIONING_CERTIFICATE);
        STATUS_CASE(DRM_PROVISIONING_CONFIG);
        STATUS_CASE(DRM_PROVISIONING_PARSE);
        STATUS_CASE(DRM_PROVISIONING_REQUEST_REJECTED);
        STATUS_CASE(DRM_PROVISIONING_RETRY);
        STATUS_CASE(DRM_RESOURCE_CONTENTION);
        STATUS_CASE(DRM_SECURE_STOP_RELEASE);
        STATUS_CASE(DRM_STORAGE_READ);
        STATUS_CASE(DRM_STORAGE_WRITE);
        STATUS_CASE(DRM_ZERO_SUBSAMPLES);
        STATUS_CASE(DRM_INVALID_STATE);
        STATUS_CASE(BAD_VALUE);
        STATUS_CASE(DRM_NOT_PROVISIONED);
        STATUS_CASE(DRM_DEVICE_REVOKED);
        STATUS_CASE(DRM_DECRYPT);
        STATUS_CASE(DEAD_OBJECT);
#undef ERROR_BAD_VALUE
#undef ERROR_DEAD_OBJECT
#undef STATUS_CASE
    }
    return ENUM_DRM_UNKNOWN;
}

void MetricsErrored::reportMediaDrmErrored(std::string name,
        const DrmStatus& error_code, const char* api,
        const std::string scheme, const std::array<int64_t, 2> uuid, const IDrmFrontend frontend,
        const std::string objNonce, const std::string version, const std::string sesNonce,
        int actualSecurityLevel) const {

    mediametrics_handle_t handle(mediametrics_create(name.c_str()));
    mediametrics_setCString(handle, "scheme", scheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", uuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", uuid[1]);
    mediametrics_setInt32(handle, "frontend", frontend);
    mediametrics_setCString(handle, "object_nonce", objNonce.c_str());
    mediametrics_setCString(handle, "version", version.c_str());
    mediametrics_setCString(handle, "session_nonce", sesNonce.c_str());
    mediametrics_setInt32(handle, "security_level", actualSecurityLevel);
    mediametrics_setCString(handle, "api", api);
    mediametrics_setInt32(handle, "error_code", MediaErrorToEnum(error_code));
    mediametrics_setInt32(handle, "cdm_err", error_code.getCdmErr());
    mediametrics_setInt32(handle, "oem_err", error_code.getOemErr());
    mediametrics_setInt32(handle, "error_context", error_code.getContext());
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

DrmStatus MetricsErrored::generateNonce(std::string* out, size_t size, const char* api,
                                        const std::string scheme, const std::array<int64_t, 2> uuid,
                                        const IDrmFrontend frontend) {
    std::vector<uint8_t> buf(size);
    ssize_t bytes = getrandom(buf.data(), size, GRND_NONBLOCK);
    if (bytes < size) {
        ALOGE("getrandom failed: %d", errno);
        reportMediaDrmErrored("mediadrm.errored", ERROR_DRM_RESOURCE_BUSY, api, scheme, uuid, frontend, "", "");
        return ERROR_DRM_RESOURCE_BUSY;
    }
    android::AString tmp;
    encodeBase64(buf.data(), size, &tmp);
    out->assign(tmp.c_str());
    return OK;
}

const std::map<std::array<int64_t, 2>, std::string> MetricsErrored::kUuidSchemeMap {
        {{(int64_t)0x6DD8B3C345F44A68, (int64_t)0xBF3A64168D01A4A6}, "ABV DRM (MoDRM)"},
        {{(int64_t)0xF239E769EFA34850, (int64_t)0x9C16A903C6932EFB},
         "Adobe Primetime DRM version 4"},
        {{(int64_t)0x616C746963617374, (int64_t)0x2D50726F74656374}, "Alticast"},
        {{(int64_t)0x94CE86FB07FF4F43, (int64_t)0xADB893D2FA968CA2}, "Apple FairPlay"},
        {{(int64_t)0x279FE473512C48FE, (int64_t)0xADE8D176FEE6B40F}, "Arris Titanium"},
        {{(int64_t)0x3D5E6D359B9A41E8, (int64_t)0xB843DD3C6E72C42C}, "ChinaDRM"},
        {{(int64_t)0x3EA8778F77424BF9, (int64_t)0xB18BE834B2ACBD47}, "Clear Key AES-128"},
        {{(int64_t)0xBE58615B19C44684, (int64_t)0x88B3C8C57E99E957}, "Clear Key SAMPLE-AES"},
        {{(int64_t)0xE2719D58A985B3C9, (int64_t)0x781AB030AF78D30E}, "Clear Key DASH-IF"},
        {{(int64_t)0x644FE7B5260F4FAD, (int64_t)0x949A0762FFB054B4}, "CMLA (OMA DRM)"},
        {{(int64_t)0x37C332587B994C7E, (int64_t)0xB15D19AF74482154}, "Commscope Titanium V3"},
        {{(int64_t)0x45D481CB8FE049C0, (int64_t)0xADA9AB2D2455B2F2}, "CoreCrypt"},
        {{(int64_t)0xDCF4E3E362F15818, (int64_t)0x7BA60A6FE33FF3DD}, "DigiCAP SmartXess"},
        {{(int64_t)0x35BF197B530E42D7, (int64_t)0x8B651B4BF415070F}, "DivX DRM Series 5"},
        {{(int64_t)0x80A6BE7E14484C37, (int64_t)0x9E70D5AEBE04C8D2}, "Irdeto Content Protection"},
        {{(int64_t)0x5E629AF538DA4063, (int64_t)0x897797FFBD9902D4},
         "Marlin Adaptive Streaming Simple Profile V1.0"},
        {{(int64_t)0x9A04F07998404286, (int64_t)0xAB92E65BE0885F95}, "Microsoft PlayReady"},
        {{(int64_t)0x6A99532D869F5922, (int64_t)0x9A91113AB7B1E2F3}, "MobiTV DRM"},
        {{(int64_t)0xADB41C242DBF4A6D, (int64_t)0x958B4457C0D27B95}, "Nagra MediaAccess PRM 3.0"},
        {{(int64_t)0x1F83E1E86EE94F0D, (int64_t)0xBA2F5EC4E3ED1A66}, "SecureMedia"},
        {{(int64_t)0x992C46E6C4374899, (int64_t)0xB6A050FA91AD0E39}, "SecureMedia SteelKnot"},
        {{(int64_t)0xA68129D3575B4F1A, (int64_t)0x9CBA3223846CF7C3},
         "Synamedia/Cisco/NDS VideoGuard DRM"},
        {{(int64_t)0xAA11967FCC014A4A, (int64_t)0x8E99C5D3DDDFEA2D}, "Unitend DRM (UDRM)"},
        {{(int64_t)0x9A27DD82FDE24725, (int64_t)0x8CBC4234AA06EC09}, "Verimatrix VCAS"},
        {{(int64_t)0xB4413586C58CFFB0, (int64_t)0x94A5D4896C1AF6C3}, "Viaccess-Orca DRM (VODRM)"},
        {{(int64_t)0x793B79569F944946, (int64_t)0xA94223E7EF7E44B4}, "VisionCrypt"},
        {{(int64_t)0x1077EFECC0B24D02, (int64_t)0xACE33C1E52E2FB4B}, "W3C Common PSSH box"},
        {{(int64_t)0xEDEF8BA979D64ACE, (int64_t)0xA3C827DCD51D21ED}, "Widevine Content Protection"},
};

}  // namespace android