
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
#define LOG_TAG "CryptoMetricsLogger"

#include <mediadrm/CryptoHal.h>
#include <mediadrm/CryptoMetricsLogger.h>
#include <mediadrm/DrmUtils.h>

namespace android {

namespace {

std::vector<uint8_t> toStdVec(Vector<uint8_t> const& sessionId) {
    auto sessionKey = sessionId.array();
    std::vector<uint8_t> vec(sessionKey, sessionKey + sessionId.size());
    return vec;
}

}  // namespace
CryptoMetricsLogger::CryptoMetricsLogger(IDrmFrontend frontend)
    : mCryptoHal(sp<CryptoHal>::make()), mFrontend(frontend) {}
CryptoMetricsLogger::~CryptoMetricsLogger() {}

status_t CryptoMetricsLogger::initCheck() const {
    return mCryptoHal->initCheck();
}

bool CryptoMetricsLogger::isCryptoSchemeSupported(const uint8_t uuid[16]) {
    return mCryptoHal->isCryptoSchemeSupported(uuid);
}

status_t CryptoMetricsLogger::createPlugin(const uint8_t uuid[16], const void* data, size_t size) {
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
    return mCryptoHal->createPlugin(uuid, data, size);
}

status_t CryptoMetricsLogger::destroyPlugin() {
    // const std::lock_guard<std::mutex> lock(mUuidSessionMapMutex);
    // mUuidSessionMap.erase(mUuid);
    return mCryptoHal->destroyPlugin();
}

bool CryptoMetricsLogger::requiresSecureDecoderComponent(const char* mime) const {
    return mCryptoHal->requiresSecureDecoderComponent(mime);
}

void CryptoMetricsLogger::notifyResolution(uint32_t width, uint32_t height) {
    return mCryptoHal->notifyResolution(width, height);
}

DrmStatus CryptoMetricsLogger::setMediaDrmSession(const Vector<uint8_t>& sessionId) {
    mMetricsError.reportMediaDrmErrored("mediadrm.cryptoerrored", ERROR_DRM_UNKNOWN, __func__,
                                        mScheme, mUuid, mFrontend, mObjNonce);
    SessionContext ctx{};
    if (mMetricsError.generateNonce(&ctx.mNonce, kNonceSize, __func__, mScheme, mUuid, mFrontend) != OK) {
        return ERROR_DRM_RESOURCE_BUSY;
    }
    ctx.mObjNonce = mObjNonce;
    DrmStatus status = mCryptoHal->setMediaDrmSession(sessionId);
    if (status == OK) {
        std::map<std::vector<uint8_t>, std::weak_ptr<SessionContext>> sessionMap;
        std::vector<uint8_t> sessionKey = toStdVec(sessionId);
        const std::lock_guard<std::mutex> lock(mUuidSessionMapMutex);
        auto sharedPtr = std::make_shared<SessionContext>(ctx);
        std::weak_ptr<SessionContext> weakPtr(sharedPtr);
        sessionMap.insert({sessionKey, weakPtr});
        mUuidSessionMap[mUuid] = sessionMap;
    } else {
        mMetricsError.reportMediaDrmErrored("mediadrm.cryptoerrored", status, __func__, mScheme, mUuid, mFrontend,
                                               mObjNonce, "", ctx.mNonce);
    }
    return status;
}

ssize_t CryptoMetricsLogger::decrypt(
        const uint8_t key[16], const uint8_t iv[16], CryptoPlugin::Mode mode,
        const CryptoPlugin::Pattern& pattern, const ::SharedBuffer& source, size_t offset,
        const CryptoPlugin::SubSample* subSamples, size_t numSubSamples,
        const drm::V1_0::DestinationBuffer& destination, AString* errorDetailMsg) {
    DrmStatus status = mCryptoHal->decrypt(key, iv, mode, pattern, source, offset, subSamples,
                                           numSubSamples, destination, errorDetailMsg);
    if (status != OK) {
        mMetricsError.reportMediaDrmErrored("mediadrm.cryptoerrored", status, __func__, mScheme, mUuid, mFrontend,
                                               mObjNonce);
    }
    return status;
}

int32_t CryptoMetricsLogger::setHeap(const sp<HidlMemory>& heap) {
    return mCryptoHal->setHeap(heap);
}

void CryptoMetricsLogger::unsetHeap(int32_t seqNum) {
    return mCryptoHal->unsetHeap(seqNum);
}

status_t CryptoMetricsLogger::getLogMessages(Vector<drm::V1_4::LogMessage>& logs) const {
    return mCryptoHal->getLogMessages(logs);
}
}  // namespace android
