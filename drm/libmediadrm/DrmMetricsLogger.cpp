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

namespace {

std::vector<uint8_t> toStdVec(Vector<uint8_t> const& sessionId) {
    auto sessionKey = sessionId.array();
    std::vector<uint8_t> vec(sessionKey, sessionKey + sessionId.size());
    return vec;
}

}  // namespace

DrmMetricsLogger::DrmMetricsLogger(IDrmFrontend frontend)
    : mImpl(sp<DrmHal>::make()), mUuid(), mObjNonce(), mFrontend(frontend) {}

DrmMetricsLogger::~DrmMetricsLogger() {}

int DrmPluginSecurityLevelToJavaSecurityLevel(DrmPlugin::SecurityLevel securityLevel) {
#define STATUS_CASE(status) \
    case DrmPlugin::k##status: \
        return J##status

    switch (securityLevel) {
        STATUS_CASE(SecurityLevelUnknown);
        STATUS_CASE(SecurityLevelSwSecureCrypto);
        STATUS_CASE(SecurityLevelSwSecureDecode);
        STATUS_CASE(SecurityLevelHwSecureCrypto);
        STATUS_CASE(SecurityLevelHwSecureDecode);
        STATUS_CASE(SecurityLevelHwSecureAll);
        STATUS_CASE(SecurityLevelMax);
#undef STATUS_CASE
    }
    return static_cast<int>(securityLevel);
}


DrmStatus DrmMetricsLogger::initCheck() const {
    DrmStatus status = mImpl->initCheck();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::isCryptoSchemeSupported(const uint8_t uuid[IDRM_UUID_SIZE],
                                                    const String8& mimeType,
                                                    DrmPlugin::SecurityLevel securityLevel,
                                                    bool* result) {
    DrmStatus status = mImpl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::createPlugin(const uint8_t uuid[IDRM_UUID_SIZE],
                                         const String8& appPackageName) {
    std::memcpy(mUuid.data(), uuid, IDRM_UUID_SIZE);
    mUuid[0] = betoh64(mUuid[0]);
    mUuid[1] = betoh64(mUuid[1]);
    if (mMetricsError.kUuidSchemeMap.count(mUuid)) {
        mScheme = mMetricsError.kUuidSchemeMap.at(mUuid);
    } else {
        mScheme = "Other";
    }
    if (mMetricsError.generateNonce(&mObjNonce, kNonceSize, __func__, mScheme, mUuid, mFrontend) !=
        OK) {
        return ERROR_DRM_RESOURCE_BUSY;
    }
    DrmStatus status = mImpl->createPlugin(uuid, appPackageName);
    if (status == OK) {
        String8 version8;
        if (getPropertyString(String8("version"), version8) == OK) {
            mVersion = version8.string();
        }
        reportMediaDrmCreated();
    } else {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::destroyPlugin() {
    DrmStatus status = mImpl->destroyPlugin();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::openSession(DrmPlugin::SecurityLevel securityLevel,
                                        Vector<uint8_t>& sessionId) {
    SessionContext ctx{};
    if (mMetricsError.generateNonce(&ctx.mNonce, kNonceSize, __func__, mScheme, mUuid, mFrontend) !=
        OK) {
        return ERROR_DRM_RESOURCE_BUSY;
    }
    DrmStatus status = mImpl->openSession(securityLevel, sessionId);
    if (status == OK) {
        std::vector<uint8_t> sessionKey = toStdVec(sessionId);
        ctx.mTargetSecurityLevel = securityLevel;
        if (getSecurityLevel(sessionId, &ctx.mActualSecurityLevel) != OK) {
            ctx.mActualSecurityLevel = DrmPlugin::kSecurityLevelUnknown;
        }
        ctx.mObjNonce = mObjNonce;
        if (!mVersion.empty()) {
            ctx.mVersion = mVersion;
        }
        {
            const std::lock_guard<std::mutex> lock(mSessionMapMutex);
            mSessionMap.insert({sessionKey, ctx});
        }
        reportMediaDrmSessionOpened(sessionKey);
    } else {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::closeSession(Vector<uint8_t> const& sessionId) {
    std::vector<uint8_t> sid = toStdVec(sessionId);
    DrmStatus status = mImpl->closeSession(sessionId);
    if (status == OK) {
        const std::lock_guard<std::mutex> lock(mSessionMapMutex);
        mSessionMap.erase(sid);
    } else {
        // TODO(b/275729711): reclaim sessions that failed to close
        reportMediaDrmErrored(status, __func__, sid);
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
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                               Vector<uint8_t> const& response,
                                               Vector<uint8_t>& keySetId) {
    DrmStatus status = mImpl->provideKeyResponse(sessionId, response, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeKeys(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeKeys(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::restoreKeys(Vector<uint8_t> const& sessionId,
                                        Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->restoreKeys(sessionId, keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                           KeyedVector<String8, String8>& infoMap) const {
    DrmStatus status = mImpl->queryKeyStatus(sessionId, infoMap);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getProvisionRequest(String8 const& certType,
                                                String8 const& certAuthority,
                                                Vector<uint8_t>& request, String8& defaultUrl) {
    DrmStatus status = mImpl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::provideProvisionResponse(Vector<uint8_t> const& response,
                                                     Vector<uint8_t>& certificate,
                                                     Vector<uint8_t>& wrappedKey) {
    DrmStatus status = mImpl->provideProvisionResponse(response, certificate, wrappedKey);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    DrmStatus status = mImpl->getSecureStops(secureStops);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    DrmStatus status = mImpl->getSecureStopIds(secureStopIds);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecureStop(Vector<uint8_t> const& ssid,
                                          Vector<uint8_t>& secureStop) {
    DrmStatus status = mImpl->getSecureStop(ssid, secureStop);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    DrmStatus status = mImpl->releaseSecureStops(ssRelease);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeSecureStop(Vector<uint8_t> const& ssid) {
    DrmStatus status = mImpl->removeSecureStop(ssid);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeAllSecureStops() {
    DrmStatus status = mImpl->removeAllSecureStops();
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getHdcpLevels(DrmPlugin::HdcpLevel* connectedLevel,
                                          DrmPlugin::HdcpLevel* maxLevel) const {
    DrmStatus status = mImpl->getHdcpLevels(connectedLevel, maxLevel);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getNumberOfSessions(uint32_t* currentSessions,
                                                uint32_t* maxSessions) const {
    DrmStatus status = mImpl->getNumberOfSessions(currentSessions, maxSessions);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                             DrmPlugin::SecurityLevel* level) const {
    DrmStatus status = mImpl->getSecurityLevel(sessionId, level);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    DrmStatus status = mImpl->getOfflineLicenseKeySetIds(keySetIds);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    DrmStatus status = mImpl->removeOfflineLicense(keySetId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getOfflineLicenseState(
        Vector<uint8_t> const& keySetId, DrmPlugin::OfflineLicenseState* licenseState) const {
    DrmStatus status = mImpl->getOfflineLicenseState(keySetId, licenseState);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getPropertyString(String8 const& name, String8& value) const {
    DrmStatus status = mImpl->getPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t>& value) const {
    DrmStatus status = mImpl->getPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPropertyString(String8 const& name, String8 const& value) const {
    DrmStatus status = mImpl->setPropertyString(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t> const& value) const {
    DrmStatus status = mImpl->setPropertyByteArray(name, value);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    DrmStatus status = mImpl->getMetrics(consumer);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::setCipherAlgorithm(Vector<uint8_t> const& sessionId,
                                               String8 const& algorithm) {
    DrmStatus status = mImpl->setCipherAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::setMacAlgorithm(Vector<uint8_t> const& sessionId,
                                            String8 const& algorithm) {
    DrmStatus status = mImpl->setMacAlgorithm(sessionId, algorithm);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->encrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    DrmStatus status = mImpl->decrypt(sessionId, keyId, input, iv, output);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                 Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->sign(sessionId, keyId, message, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                   Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                                   bool& match) {
    DrmStatus status = mImpl->verify(sessionId, keyId, message, signature, match);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                                    Vector<uint8_t> const& message,
                                    Vector<uint8_t> const& wrappedKey, Vector<uint8_t>& signature) {
    DrmStatus status = mImpl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::setListener(const sp<IDrmClient>& listener) {
    DrmStatus status = mImpl->setListener(listener);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime, bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, required);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime,
                                                  DrmPlugin::SecurityLevel securityLevel,
                                                  bool* required) const {
    DrmStatus status = mImpl->requiresSecureDecoder(mime, securityLevel, required);
    if (status != OK) {
        reportMediaDrmErrored(status, "requiresSecureDecoderLevel");
    }
    return status;
}

DrmStatus DrmMetricsLogger::setPlaybackId(Vector<uint8_t> const& sessionId,
                                          const char* playbackId) {
    DrmStatus status = mImpl->setPlaybackId(sessionId, playbackId);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__, toStdVec(sessionId));
    }
    return status;
}

DrmStatus DrmMetricsLogger::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    DrmStatus status = mImpl->getLogMessages(logs);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

DrmStatus DrmMetricsLogger::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    DrmStatus status = mImpl->getSupportedSchemes(schemes);
    if (status != OK) {
        reportMediaDrmErrored(status, __func__);
    }
    return status;
}

void DrmMetricsLogger::reportMediaDrmCreated() const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm.created"));
    mediametrics_setCString(handle, "scheme", mScheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    mediametrics_setCString(handle, "version", mVersion.c_str());
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmSessionOpened(const std::vector<uint8_t>& sessionId) const {
    mediametrics_handle_t handle(mediametrics_create("mediadrm.session_opened"));
    mediametrics_setCString(handle, "scheme", mScheme.c_str());
    mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    mediametrics_setInt32(handle, "frontend", mFrontend);
    mediametrics_setCString(handle, "version", mVersion.c_str());
    mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    const std::lock_guard<std::mutex> lock(mSessionMapMutex);
    auto it = mSessionMap.find(sessionId);
    if (it != mSessionMap.end()) {
        mediametrics_setCString(handle, "session_nonce", it->second.mNonce.c_str());
        mediametrics_setInt32(handle, "requested_security_level",
                    DrmPluginSecurityLevelToJavaSecurityLevel(it->second.mTargetSecurityLevel));
        mediametrics_setInt32(handle, "opened_security_level",
                    DrmPluginSecurityLevelToJavaSecurityLevel(it->second.mActualSecurityLevel));
    }
    mediametrics_selfRecord(handle);
    mediametrics_delete(handle);
}

void DrmMetricsLogger::reportMediaDrmErrored(const DrmStatus& error_code, const char* api,
                                             const std::vector<uint8_t>& sessionId) const {
    // mediametrics_handle_t handle(mediametrics_create("mediadrm.errored"));
    // mediametrics_setCString(handle, "scheme", mScheme.c_str());
    // mediametrics_setInt64(handle, "uuid_msb", mUuid[0]);
    // mediametrics_setInt64(handle, "uuid_lsb", mUuid[1]);
    // mediametrics_setInt32(handle, "frontend", mFrontend);
    // mediametrics_setCString(handle, "version", mVersion.c_str());
    // mediametrics_setCString(handle, "object_nonce", mObjNonce.c_str());
    // if (!sessionId.empty()) {
    //     const std::lock_guard<std::mutex> lock(mSessionMapMutex);
    //     auto it = mSessionMap.find(sessionId);
    //     if (it != mSessionMap.end()) {
    //         mediametrics_setCString(handle, "session_nonce", it->second.mNonce.c_str());
    //         mediametrics_setInt32(handle, "security_level",
    //                     DrmPluginSecurityLevelToJavaSecurityLevel(it->second.mActualSecurityLevel));
    //     }
    // }
    // mediametrics_setCString(handle, "api", api);
    // mediametrics_setInt32(handle, "error_code", MediaErrorToEnum(error_code));
    // mediametrics_setInt32(handle, "cdm_err", error_code.getCdmErr());
    // mediametrics_setInt32(handle, "oem_err", error_code.getOemErr());
    // mediametrics_setInt32(handle, "error_context", error_code.getContext());
    // mediametrics_selfRecord(handle);
    // mediametrics_delete(handle);
    if (!sessionId.empty()) {
        const std::lock_guard<std::mutex> lock(mSessionMapMutex);
        auto it = mSessionMap.find(sessionId);
        if (it != mSessionMap.end()) {
            mMetricsError.reportMediaDrmErrored(
                    "mediadrm.errored", error_code, api, mScheme, mUuid, mFrontend, mObjNonce,
                    mVersion, it->second.mNonce,
                    DrmPluginSecurityLevelToJavaSecurityLevel(it->second.mActualSecurityLevel));
        }
    } else {
        mMetricsError.reportMediaDrmErrored("mediadrm.errored", error_code, api, mScheme, mUuid, mFrontend, mObjNonce,
                                mVersion);
    }
}

}  // namespace android