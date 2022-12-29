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

// #define LOG_NDEBUG 0
#define LOG_TAG "DrmMetricsLogger"

#include <media/MediaMetrics.h>
#include <mediadrm/DrmHal.h>
#include <mediadrm/DrmMetricsLogger.h>
#include <mediadrm/DrmUtils.h>

namespace android {

DrmMetricsLogger::DrmMetricsLogger(IDrmFrontend frontend) {
    mImpl = sp<DrmHal>::make();
    mFrontend = frontend;
    mObjNonceMsb = getrandom((void*)msbObjBuffer, 8, GRND_NONBLOCK);
    mObjNonceLsb = getrandom((void*)lsbObjBuffer, 8, GRND_NONBLOCK);
    ssize_t bytes = getrandom(&mObjNonceMsb, sizeof(mObjNonceMsb), GRND_NONBLOCK);
    if (bytes < sizeof(mObjNonceMsb)) {
        ALOGE("getrandom failed: %d", errno);
        mInitCheck = ERROR_DRM_RESOURCE_BUSY;
    }
}

DrmMetricsLogger::~DrmMetricsLogger() {}

DrmStatus DrmMetricsLogger::initCheck() const {
    DrmStatus status = mImpl->initCheck();
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_UNKNOWN);
    }
    return status;
}

DrmStatus DrmMetricsLogger::isCryptoSchemeSupported(const uint8_t uuid[16], const String8& mimeType,
                                                    DrmPlugin::SecurityLevel securityLevel,
                                                    bool* result) {
    DrmStatus status = mImpl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_IS_CRYPTO_SCHEME_SUPPORTED);
    }
    return status;
}

DrmStatus DrmMetricsLogger::createPlugin(const uint8_t uuid[16], const String8& appPackageName) {
    for (int i = 0; i < 16; i++) {
        muuid[i] = uuid[i];
    }
    DrmStatus status = mImpl->createPlugin(uuid, appPackageName);
    if (status == OK) {
        reportMediaDrmCreated();
    } else {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_CREATE_PLUGIN, true);
    }
    return status;
}

DrmStatus DrmMetricsLogger::destroyPlugin() {
    DrmStatus status = mImpl->destroyPlugin();
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_DESTROY_PLUGIN);
    }
    return status;
}

DrmStatus DrmMetricsLogger::openSession(DrmPlugin::SecurityLevel securityLevel,
                                        Vector<uint8_t>& sessionId) {
    DrmStatus status = mImpl->openSession(securityLevel, sessionId);
    int64_t msbSesBuffer[8], lsbSesBuffer[8];
    mSesNonceMsb = getrandom((void*)msbSesBuffer, 8, GRND_NONBLOCK);
    mSesNonceLsb = getrandom((void*)lsbSesBuffer, 8, GRND_NONBLOCK);
    mSessionMap[&sessionId] = {mSesNonceMsb, mSesNonceLsb};
    if (status == OK) {
        mTargetSecurityLevel = securityLevel;
        mActualSecurityLevel = DrmMetricsLogger::getSecurityLevel(sessionId, &securityLevel);
        reportMediaDrmOpenSession();
    } else {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_OPEN_SESSION, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::closeSession(Vector<uint8_t> const& sessionId) {
    Vector<uint8_t> temp = sessionId;
    mSessionMap.erase(&temp);
    DrmStatus status = mImpl->closeSession(sessionId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_CLOSE_SESSION, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getKeyRequest(Vector<uint8_t> const& sessionId,
                                          Vector<uint8_t> const& initData, String8 const& mimeType,
                                          DrmPlugin::KeyType keyType,
                                          KeyedVector<String8, String8> const& optionalParameters,
                                          Vector<uint8_t>& request, String8& defaultUrl,
                                          DrmPlugin::KeyRequestType* keyRequestType) {
    DrmStatus status =
            mImpl->getKeyRequest(sessionId, initData, mimeType, keyType, optionalParameters,
                                 request, defaultUrl, keyRequestType);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_KEY_REQUEST, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                               Vector<uint8_t> const& response,
                                               Vector<uint8_t>& keySetId) {
    DrmStatus status = mImpl->provideKeyResponse(sessionId, response, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_PROVIDE_KEY_RESPONSE,
                              false, sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeKeys(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeKeys(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_KEYS);
    }
    return status;
}

DrmStatus DrmMetricsLogger::restoreKeys(Vector<uint8_t> const& sessionId,
                                        Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->restoreKeys(sessionId, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_RESTORE_KEYS, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                           KeyedVector<String8, String8>& infoMap) const {
    DrmStatus status = mImpl->queryKeyStatus(sessionId, infoMap);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_QUERY_KEY_STATUS, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getProvisionRequest(String8 const& certType,
                                                String8 const& certAuthority,
                                                Vector<uint8_t>& request, String8& defaultUrl) {
    DrmStatus status = mImpl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROVISION_REQUEST);
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideProvisionResponse(Vector<uint8_t> const& response,
                                                     Vector<uint8_t>& certificate,
                                                     Vector<uint8_t>& wrappedKey) {
    DrmStatus status = mImpl->provideProvisionResponse(response, certificate, wrappedKey);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_PROVIDE_PROVISION_RESPONSE);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    DrmStatus status = mImpl->getSecureStops(secureStops);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOPS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    DrmStatus status = mImpl->getSecureStopIds(secureStopIds);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOP_IDS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getSecureStop(Vector<uint8_t> const& ssid,
                                          Vector<uint8_t>& secureStop) {
    DrmStatus status = mImpl->getSecureStop(ssid, secureStop);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURE_STOP);
    }
    return status;
}

DrmStatus DrmMetricsLogger::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    DrmStatus status = mImpl->releaseSecureStops(ssRelease);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_RELEASE_SECURE_STOPS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::removeSecureStop(Vector<uint8_t> const& ssid) {
    DrmStatus status = mImpl->removeSecureStop(ssid);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_SECURE_STOP);
    }
    return status;
}
DrmStatus DrmMetricsLogger::removeAllSecureStops() {
    DrmStatus status = mImpl->removeAllSecureStops();
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_ALL_SECURE_STOPS);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getHdcpLevels(DrmPlugin::HdcpLevel* connectedLevel,
                                          DrmPlugin::HdcpLevel* maxLevel) const {
    DrmStatus status = mImpl->getHdcpLevels(connectedLevel, maxLevel);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_HDCP_LEVELS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getNumberOfSessions(uint32_t* currentSessions,
                                                uint32_t* maxSessions) const {
    DrmStatus status = mImpl->getNumberOfSessions(currentSessions, maxSessions);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_NUMBER_OF_SESSIONS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                             DrmPlugin::SecurityLevel* level) const {
    DrmStatus status = mImpl->getSecurityLevel(sessionId, level);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_SECURITY_LEVEL,
                              false, sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    DrmStatus status = mImpl->getOfflineLicenseKeySetIds(keySetIds);
    if (status != OK) {
        reportMediaDrmErrored(
                status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_OFFLINE_LICENSE_KEY_SET_IDS);
    }
    return status;
}
DrmStatus DrmMetricsLogger::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeOfflineLicense(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_REMOVE_OFFLINE_LICENSE);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getOfflineLicenseState(
        Vector<uint8_t> const& keySetId, DrmPlugin::OfflineLicenseState* licenseState) const {
    DrmStatus status = mImpl->getOfflineLicenseState(keySetId, licenseState);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_GET_OFFLINE_LICENSE_STATE);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getPropertyString(String8 const& name, String8& value) const {
    DrmStatus status = mImpl->getPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROPERTY_STRING);
    }
    return status;
}
DrmStatus DrmMetricsLogger::getPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t>& value) const {
    DrmStatus status = mImpl->getPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_GET_PROPERTY_BYTE_ARRAY);
    }
    return status;
}
DrmStatus DrmMetricsLogger::setPropertyString(String8 const& name, String8 const& value) const {
    DrmStatus status = mImpl->setPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SET_PROPERTY_STRING);
    }
    return status;
}
DrmStatus DrmMetricsLogger::setPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t> const& value) const {
    DrmStatus status = mImpl->setPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_SET_PROPERTY_BYTE_ARRAY);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    DrmStatus status = mImpl->getMetrics(consumer);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_METRICS);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setCipherAlgorithm(Vector<uint8_t> const& sessionId,
                                               String8 const& algorithm) {
    DrmStatus status = mImpl->setCipherAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SET_CIPHER_ALGORITHM,
                              false, sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setMacAlgorithm(Vector<uint8_t> const& sessionId,
                                            String8 const& algorithm) {
    DrmStatus status = mImpl->setMacAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SET_MAC_ALGORITHM,
                              false, sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->encrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_ENCRYPT, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->decrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_DECRYPT, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                 Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->sign(sessionId, keyId, message, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_SIGN, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                   Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                                   bool& match) {
    DrmStatus status = mImpl->verify(sessionId, keyId, message, signature, match);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GENERIC_VERIFY, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                                    Vector<uint8_t> const& message,
                                    Vector<uint8_t> const& wrappedKey, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SIGN_RSA, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setListener(const sp<IDrmClient>& listener) {
    DrmStatus status = mImpl->setListener(listener);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SET_LISTENER);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime, bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, required);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_REQUIRES_SECURE_DECODER);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime,
                                                  DrmPlugin::SecurityLevel securityLevel,
                                                  bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, securityLevel, required);
    if (status != OK) {
        reportMediaDrmErrored(status,
                              util::MEDIA_DRM_ERRORED__API__DRM_API_REQUIRES_SECURE_DECODER_LEVEL);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPlaybackId(Vector<uint8_t> const& sessionId,
                                          const char* playbackId) {
    DrmStatus status = mImpl->setPlaybackId(sessionId, playbackId);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_SET_PLAYBACK_ID, false,
                              sessionId);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    DrmStatus status = mImpl->getLogMessages(logs);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_LOG_MESSAGES);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    DrmStatus status = mImpl->getSupportedSchemes(schemes);
    if (status != OK) {
        reportMediaDrmErrored(status, util::MEDIA_DRM_ERRORED__API__DRM_API_GET_SUPPORTED_SCHEMES);
    }
    return status;
}

void DrmMetricsLogger::reportMediaDrmCreated() const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm_created"));
    uint64_t uuid2[2] = {};
    std::memcpy(uuid2, muuid, sizeof(uuid2));
    mediametrics_setInt64(handle, "uuid_msb", static_cast<int64_t>(be64toh(uuid2[0])));
    mediametrics_setInt64(handle, "uuid_lsb", static_cast<int64_t>(be64toh(uuid2[1])));
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmOpenSession() const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm_session"));
    mediametrics_setInt64(handle, "obj_nonce_msb", mObjNonceMsb);
    mediametrics_setInt64(handle, "obj_nonce_lsb", mObjNonceLsb);
    mediametrics_setInt64(handle, "ses_nonce_msb", mSesNonceMsb);
    mediametrics_setInt64(handle, "ses_nonce_lsb", mSesNonceLsb);
    mediametrics_setInt64(handle, "target_seucrity_level", mTargetSecurityLevel);
    mediametrics_setInt64(handle, "actual_seucrity_level", mActualSecurityLevel);
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmErrored(DrmStatus error_code, int32_t API_Value, bool uuid,
                                             Vector<uint8_t> sessionId) const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm_err"));
    mediametrics_setInt64(handle, "obj_nonce_msb", mObjNonceMsb);
    mediametrics_setInt64(handle, "obj_nonce_lsb", mObjNonceLsb);
    if (!sessionId.empty()) {
        mediametrics_setInt64(handle, "ses_nonce_msb", mSessionMap.at(&sessionId)[0]);
        mediametrics_setInt64(handle, "ses_nonce_lsb", mSessionMap.at(&sessionId)[1]);
    }
    if (uuid) {
        uint64_t uuid2[2] = {};
        std::memcpy(uuid2, muuid, sizeof(uuid2));
        mediametrics_setInt64(handle, "uuid_msb", static_cast<int64_t>(be64toh(uuid2[0])));
        mediametrics_setInt64(handle, "uuid_lsb", static_cast<int64_t>(be64toh(uuid2[1])));
    }
    mediametrics_setInt64(handle, "error_code", error_code);
    mediametrics_setInt64(handle, "api", API_Value);
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

}  // namespace android