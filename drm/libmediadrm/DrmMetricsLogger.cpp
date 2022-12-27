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

DrmMetricsLogger::DrmMetricsLogger() {
    mImpl = sp<DrmHal>::make();
    mObjNonceMsb = getrandom((void*)msbObjBuffer, 8, GRND_NONBLOCK);
    mObjNonceLsb = getrandom((void*)lsbObjBuffer, 8, GRND_NONBLOCK);
}

DrmMetricsLogger::~DrmMetricsLogger() {}

DrmStatus DrmMetricsLogger::initCheck() const {
    return mImpl->initCheck();
}

DrmStatus DrmMetricsLogger::isCryptoSchemeSupported(const uint8_t uuid[16], const String8& mimeType,
                                                    DrmPlugin::SecurityLevel securityLevel,
                                                    bool* result) {
    return mImpl->isCryptoSchemeSupported(uuid, mimeType, securityLevel, result);
}

DrmStatus DrmMetricsLogger::createPlugin(const uint8_t uuid[16], const String8& appPackageName,
                                   int32_t platform) {
    DrmStatus status = mImpl->createPlugin(uuid, appPackageName);
    if (status == OK) {
        reportFrameworkMetrics("mediadrm_new", uuid);
        mPlatform = platform;
    }
    return status;
}

DrmStatus DrmMetricsLogger::destroyPlugin() {
    return mImpl->destroyPlugin();
}

DrmStatus DrmMetricsLogger::openSession(DrmPlugin::SecurityLevel securityLevel,
                                        Vector<uint8_t>& sessionId) {
    return mImpl->openSession(securityLevel, sessionId);
}

DrmStatus DrmMetricsLogger::closeSession(Vector<uint8_t> const& sessionId) {
    return mImpl->closeSession(sessionId);
}

DrmStatus DrmMetricsLogger::getKeyRequest(Vector<uint8_t> const& sessionId,
                                          Vector<uint8_t> const& initData, String8 const& mimeType,
                                          DrmPlugin::KeyType keyType,
                                          KeyedVector<String8, String8> const& optionalParameters,
                                          Vector<uint8_t>& request, String8& defaultUrl,
                                          DrmPlugin::KeyRequestType* keyRequestType) {
    return mImpl->getKeyRequest(sessionId, initData, mimeType, keyType, optionalParameters, request,
                                defaultUrl, keyRequestType);
}

DrmStatus DrmMetricsLogger::provideKeyResponse(Vector<uint8_t> const& sessionId,
                                               Vector<uint8_t> const& response,
                                               Vector<uint8_t>& keySetId) {
    return mImpl->provideKeyResponse(sessionId, response, keySetId);
}

DrmStatus DrmMetricsLogger::removeKeys(Vector<uint8_t> const& keySetId) {
    return mImpl->removeKeys(keySetId);
}

DrmStatus DrmMetricsLogger::restoreKeys(Vector<uint8_t> const& sessionId,
                                        Vector<uint8_t> const& keySetId) {
    return mImpl->restoreKeys(sessionId, keySetId);
}

DrmStatus DrmMetricsLogger::queryKeyStatus(Vector<uint8_t> const& sessionId,
                                           KeyedVector<String8, String8>& infoMap) const {
    return mImpl->queryKeyStatus(sessionId, infoMap);
}

DrmStatus DrmMetricsLogger::getProvisionRequest(String8 const& certType,
                                                String8 const& certAuthority,
                                                Vector<uint8_t>& request, String8& defaultUrl) {
    return mImpl->getProvisionRequest(certType, certAuthority, request, defaultUrl);
}

DrmStatus DrmMetricsLogger::provideProvisionResponse(Vector<uint8_t> const& response,
                                                     Vector<uint8_t>& certificate,
                                                     Vector<uint8_t>& wrappedKey) {
    return mImpl->provideProvisionResponse(response, certificate, wrappedKey);
}

DrmStatus DrmMetricsLogger::getSecureStops(List<Vector<uint8_t>>& secureStops) {
    return mImpl->getSecureStops(secureStops);
}
DrmStatus DrmMetricsLogger::getSecureStopIds(List<Vector<uint8_t>>& secureStopIds) {
    return mImpl->getSecureStopIds(secureStopIds);
}
DrmStatus DrmMetricsLogger::getSecureStop(Vector<uint8_t> const& ssid,
                                          Vector<uint8_t>& secureStop) {
    return mImpl->getSecureStop(ssid, secureStop);
}

DrmStatus DrmMetricsLogger::releaseSecureStops(Vector<uint8_t> const& ssRelease) {
    return mImpl->releaseSecureStops(ssRelease);
}
DrmStatus DrmMetricsLogger::removeSecureStop(Vector<uint8_t> const& ssid) {
    return mImpl->removeSecureStop(ssid);
}
DrmStatus DrmMetricsLogger::removeAllSecureStops() {
    return mImpl->removeAllSecureStops();
}

DrmStatus DrmMetricsLogger::getHdcpLevels(DrmPlugin::HdcpLevel* connectedLevel,
                                          DrmPlugin::HdcpLevel* maxLevel) const {
    return mImpl->getHdcpLevels(connectedLevel, maxLevel);
}
DrmStatus DrmMetricsLogger::getNumberOfSessions(uint32_t* currentSessions, uint32_t* maxSessions) const {
    return mImpl->getNumberOfSessions(currentSessions, maxSessions);
}
DrmStatus DrmMetricsLogger::getSecurityLevel(Vector<uint8_t> const& sessionId,
                                             DrmPlugin::SecurityLevel* level) const {
    return mImpl->getSecurityLevel(sessionId, level);
}

DrmStatus DrmMetricsLogger::getOfflineLicenseKeySetIds(List<Vector<uint8_t>>& keySetIds) const {
    return mImpl->getOfflineLicenseKeySetIds(keySetIds);
}
DrmStatus DrmMetricsLogger::removeOfflineLicense(Vector<uint8_t> const& keySetId) {
    return mImpl->removeOfflineLicense(keySetId);
}
DrmStatus DrmMetricsLogger::getOfflineLicenseState(Vector<uint8_t> const& keySetId,
                                                   DrmPlugin::OfflineLicenseState* licenseState) const {
    return mImpl->getOfflineLicenseState(keySetId, licenseState);
}

DrmStatus DrmMetricsLogger::getPropertyString(String8 const& name, String8& value) const {
    return mImpl->getPropertyString(name, value);
}
DrmStatus DrmMetricsLogger::getPropertyByteArray(String8 const& name, Vector<uint8_t>& value) const {
    return mImpl->getPropertyByteArray(name, value);
}
DrmStatus DrmMetricsLogger::setPropertyString(String8 const& name, String8 const& value) const {
    return mImpl->setPropertyString(name, value);
}
DrmStatus DrmMetricsLogger::setPropertyByteArray(String8 const& name,
                                                 Vector<uint8_t> const& value) const {
    return mImpl->setPropertyByteArray(name, value);
}

DrmStatus DrmMetricsLogger::getMetrics(const sp<IDrmMetricsConsumer>& consumer) {
    return mImpl->getMetrics(consumer);
}

DrmStatus DrmMetricsLogger::setCipherAlgorithm(Vector<uint8_t> const& sessionId,
                                               String8 const& algorithm) {
    return mImpl->setCipherAlgorithm(sessionId, algorithm);
}

DrmStatus DrmMetricsLogger::setMacAlgorithm(Vector<uint8_t> const& sessionId,
                                            String8 const& algorithm) {
    return mImpl->setMacAlgorithm(sessionId, algorithm);
}

DrmStatus DrmMetricsLogger::encrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    return mImpl->encrypt(sessionId, keyId, input, iv, output);
}

DrmStatus DrmMetricsLogger::decrypt(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                    Vector<uint8_t> const& input, Vector<uint8_t> const& iv,
                                    Vector<uint8_t>& output) {
    return mImpl->decrypt(sessionId, keyId, input, iv, output);
}

DrmStatus DrmMetricsLogger::sign(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                 Vector<uint8_t> const& message, Vector<uint8_t>& signature) {
    return mImpl->sign(sessionId, keyId, message, signature);
}

DrmStatus DrmMetricsLogger::verify(Vector<uint8_t> const& sessionId, Vector<uint8_t> const& keyId,
                                   Vector<uint8_t> const& message, Vector<uint8_t> const& signature,
                                   bool& match) {
    return mImpl->verify(sessionId, keyId, message, signature, match);
}

DrmStatus DrmMetricsLogger::signRSA(Vector<uint8_t> const& sessionId, String8 const& algorithm,
                                    Vector<uint8_t> const& message,
                                    Vector<uint8_t> const& wrappedKey, Vector<uint8_t>& signature) {
    return mImpl->signRSA(sessionId, algorithm, message, wrappedKey, signature);
}

DrmStatus DrmMetricsLogger::setListener(const sp<IDrmClient>& listener) {
    return mImpl->setListener(listener);
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime, bool* required) const {
    return mImpl->requiresSecureDecoder(mime, required);
}

DrmStatus DrmMetricsLogger::requiresSecureDecoder(const char* mime,
                                                  DrmPlugin::SecurityLevel securityLevel,
                                                  bool* required) const {
    return mImpl->requiresSecureDecoder(mime, securityLevel, required);
}

DrmStatus DrmMetricsLogger::setPlaybackId(Vector<uint8_t> const& sessionId,
                                          const char* playbackId) {
    return mImpl->setPlaybackId(sessionId, playbackId);
}

DrmStatus DrmMetricsLogger::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    return mImpl->getLogMessages(logs);
}

DrmStatus DrmMetricsLogger::getSupportedSchemes(std::vector<uint8_t>& schemes) const {
    return mImpl->getSupportedSchemes(schemes);
}

void DrmMetricsLogger::reportFrameworkMetrics(const std::string& pluginMetrics,
                                         const uint8_t uuid[16]) const {
    if (pluginMetrics == "mediadrm_new") {
        mediametrics_handle_t handle(mediametrics_create("mediadrm_new"));
        mediametrics_setInt64(handle, "obj_nonce_msb", mObjNonceMsb);
        mediametrics_setInt64(handle, "obj_nonce_lsb", mObjNonceLsb);
        uint64_t uuid2[2] = {};
        std::memcpy(uuid2, uuid, sizeof(uuid2));
        mediametrics_setInt64(handle, "uuid_msb", uuid2[0]);
        mediametrics_setInt64(handle, "uuid_lsb", uuid2[1]);
        mediametrics_setInt32(handle, "platform", mPlatform);
        mediametrics_delete(handle);
    }
}

}  // namespace android