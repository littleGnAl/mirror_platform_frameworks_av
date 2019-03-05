/*
 * Copyright (C) 2014 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "NdkMediaDescrambler"

#include <media/NdkMediaDescrambler.h>
#include <media/NdkMediaCrypto.h>

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <gui/Surface.h>

#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <utils/List.h>
#include <media/stagefright/MediaErrors.h>
#include <binder/IServiceManager.h>
#include <NdkMediaDescramblerPriv.h>

#include <android/hardware/cas/1.0/IMediaCasService.h>
#include <hidlmemory/FrameworkUtils.h>

using android::hardware::hidl_vec;
using android::hardware::hidl_string;
using android::hardware::fromHeap;
using namespace hardware::cas::V1_0;

typedef hardware::hidl_vec<uint8_t> idvec_t;

extern "C" {

AMediaDescrambler::~AMediaDescrambler() {
    mDescrambler.clear();
    mMem.clear();
    mDealer.clear();
    mHidlMemory.clear();
}

static media_status_t translateStatus(Status status) {
    media_status_t result = AMEDIA_ERROR_UNKNOWN;

    switch (status) {
        case hardware::cas::V1_0::Status::OK :
            result = AMEDIA_OK;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_NO_LICENSE :
            result = AMEDIA_CAS_NO_LICENSE;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_LICENSE_EXPIRED :
            result = AMEDIA_CAS_LICENSE_EXPIRED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_SESSION_NOT_OPENED :
            result = AMEDIA_CAS_SESSION_NOT_OPENED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_CANNOT_HANDLE :
            result = AMEDIA_CAS_CANNOT_HANDLE;
            break;
        case hardware::cas::V1_0::Status::BAD_VALUE :
            result = AMEDIA_CAS_BAD_VALUE;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_INVALID_STATE :
            result = AMEDIA_CAS_INVALID_STATE;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_NOT_PROVISIONED :
            result = AMEDIA_CAS_NOT_PROVISIONED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_RESOURCE_BUSY :
            result = AMEDIA_CAS_RESOURCE_BUSY;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_INSUFFICIENT_OUTPUT_PROTECTION :
            result = AMEDIA_CAS_INSUFFICIENT_OUTPUT_PROTECTION;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_TAMPER_DETECTED :
            result = AMEDIA_CAS_TAMPER_DETECTED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_DEVICE_REVOKED :
            result = AMEDIA_CAS_DEVICE_REVOKED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_DECRYPT_UNIT_NOT_INITIALIZED :
            result = AMEDIA_CAS_DECRYPT_UNIT_NOT_INITIALIZED;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_DECRYPT :
            result = AMEDIA_CAS_DECRYPT_ERROR;
            break;
        case hardware::cas::V1_0::Status::ERROR_CAS_UNKNOWN :
            result = AMEDIA_CAS_UNKNOWN;
            break;
    }

    return result;
}

static sp<IDescrambler> CreateDescramblerFromID(const int32_t id) {

    sp<IMediaCasService> casService = IMediaCasService::getService("default");
    if (casService == NULL) {
        return NULL;
    }

    sp<IDescramblerBase> descramblerBase = casService->createDescrambler(id);
    if (descramblerBase == NULL) {
        ALOGE("Failed to create descramblerBase");
        return NULL;
    }

    sp<IDescrambler> descrambler = IDescrambler::castFrom(descramblerBase);
    if (descrambler == NULL) {
        ALOGE("Failed to create descrambler");
    }

    return descrambler;
}

EXPORT
AMediaDescrambler* AMediaDescrambler_create(const int32_t id) {
    ALOGV("%s", __FUNCTION__);
    AMediaDescrambler *mObj = new AMediaDescrambler();
    mObj->mDescrambler = CreateDescramblerFromID(id);

    if (mObj->mDescrambler == NULL)
    {
        return NULL;
    }

    mObj->mMem                  = NULL;
    mObj->mDealer               = NULL;
    mObj->mHidlMemory           = NULL;

    return mObj;
}

EXPORT
void AMediaDescrambler_release(AMediaDescrambler *mObj) {
    if(mObj)
        delete mObj;
}

EXPORT
media_status_t AMediaDescrambler_setMediaCasSession(AMediaDescrambler *mObj, AMediaCasSessionId *sessionId) {
    ALOGV("%s", __FUNCTION__);
    Status status = Status::OK;

    if (!mObj || mObj->mDescrambler == NULL) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }

    if (!sessionId) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    idvec_t vSessionId;
    vSessionId.setToExternal((uint8_t*)sessionId->ptr, sessionId->length);
    status = mObj->mDescrambler->setMediaCasSession(vSessionId);

    return translateStatus(status);
}

EXPORT
media_status_t AMediaDescrambler_requiresSecureDecoderComponent(AMediaDescrambler *mObj, const char *mime, int *success) {
    ALOGV("%s", __FUNCTION__);
    if (!mObj || mObj->mDescrambler == NULL) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }

    if (!mime || !success) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    bool doesRequireSecureDecoder = mObj->mDescrambler->requiresSecureDecoderComponent(hidl_string(mime));

    *success = doesRequireSecureDecoder;

    return AMEDIA_OK;
}

static ssize_t getSubSampleSizeInfo(size_t numSubSamples, size_t* numClearData, size_t* numEncryptData, hidl_vec<SubSample> *outSubSamples) {

    if (numSubSamples <= 0 ||
        numSubSamples >= (signed)(INT32_MAX / sizeof(SubSample))) {
        // subSamples array may silently overflow if number of samples are
        // too large.  Use INT32_MAX as maximum allocation size may be less
        // than SIZE_MAX on some platforms.
        ALOGE("numSubSamples is invalid!");
        return -1;
    }

    ssize_t totalSize = 0;

    outSubSamples->resize(numSubSamples);
    SubSample *subSamplesPtr = outSubSamples->data();
    if (subSamplesPtr == NULL) {
        ALOGE("Failed to allocate SubSample array!");
        return -1;
    }

    for(size_t i = 0; i < numSubSamples; ++i) {
        subSamplesPtr[i].numBytesOfClearData     = numClearData[i];
        subSamplesPtr[i].numBytesOfEncryptedData = numEncryptData[i];
        totalSize += subSamplesPtr[i].numBytesOfClearData + subSamplesPtr[i].numBytesOfEncryptedData;
    }

    if (totalSize < 0) {
        return -1;
    }
    return totalSize;
}

bool ensureBufferCapacity(AMediaDescrambler *mObj, size_t neededSize) {
    if (mObj->mMem != NULL && mObj->mMem->size() >= neededSize) {
        return true;
    }

    ALOGV("ensureBufferCapacity: current size %zu, new size %zu",
            mObj->mMem == NULL ? 0 : mObj->mMem->size(), neededSize);

    size_t alignment = MemoryDealer::getAllocationAlignment();
    neededSize = (neededSize + (alignment - 1)) & ~(alignment - 1);
    // Align to multiples of 64K.
    neededSize = (neededSize + 65535) & ~65535;
    mObj->mDealer = new MemoryDealer(neededSize, "JDescrambler");
    mObj->mMem = mObj->mDealer->allocate(neededSize);

    ssize_t offset;
    size_t size;
    sp<IMemoryHeap> heap = mObj->mMem->getMemory(&offset, &size);
    if (heap == NULL) {
        return false;
    }

    mObj->mHidlMemory = fromHeap(heap);
    mObj->mDescramblerSrcBuffer.heapBase = *(mObj->mHidlMemory);
    mObj->mDescramblerSrcBuffer.offset = (uint64_t) offset;
    mObj->mDescramblerSrcBuffer.size = (uint64_t) size;
    return true;
}

EXPORT
media_status_t AMediaDescrambler_descramble(AMediaDescrambler *mObj,
                                            const void *srcPtr,
                                            int32_t srcOffset,
                                            void *dstPtr,
                                            int32_t dstOffset,
                                            AMediaCodecCryptoInfo* cryptoInfo,
                                            uint32_t *bytesWritten)
{
    ALOGV("%s", __FUNCTION__);
    if (!mObj || mObj->mDescrambler == NULL) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }

    if (cryptoInfo      == NULL ||
        srcPtr          == NULL ||
        dstPtr          == NULL ||
        bytesWritten    == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }

    media_status_t returnStatus = AMEDIA_OK;
    DestinationBuffer dstBuffer;
    Status status = Status::OK;
    hidl_string hidlDetailedError;

    uint8_t cryptoKey[16];
    AMediaCodecCryptoInfo_getKey(cryptoInfo, cryptoKey);
    uint8_t key = cryptoKey[0];
    uint8_t flags = cryptoKey[1];

    size_t  numSubSamples = AMediaCodecCryptoInfo_getNumSubSamples(cryptoInfo);
    size_t* numClearData = new size_t[numSubSamples];
    size_t* numEncryptData = new size_t[numSubSamples];

    AMediaCodecCryptoInfo_getClearBytes(cryptoInfo, numClearData);
    AMediaCodecCryptoInfo_getEncryptedBytes(cryptoInfo, numEncryptData);

    uint32_t scramblingControl = key;

    hidl_vec<SubSample> subSamplesVec;
    ssize_t totalLength = getSubSampleSizeInfo(numSubSamples, numClearData, numEncryptData, &subSamplesVec);
    if (totalLength <= 0) {
        ALOGE("%s: SubSamples size is invalid!", __FUNCTION__);
        returnStatus = AMEDIA_ERROR_INVALID_PARAMETER;
        goto clean_up;
    }

    if (flags & SCRAMBLE_FLAG_PES_HEADER) {
        scramblingControl |= kAMediaDescrambler_Scrambling_Flag_PesHeader;
    }

    if (!ensureBufferCapacity(mObj, totalLength)) {
        returnStatus = AMEDIACODEC_ERROR_INSUFFICIENT_RESOURCE;
    } else {
        memcpy(mObj->mMem->pointer(), (const void*)((const uint8_t*)srcPtr + srcOffset), totalLength);

        dstBuffer.type = BufferType::SHARED_MEMORY;
        dstBuffer.nonsecureMemory = mObj->mDescramblerSrcBuffer;

        auto err = mObj->mDescrambler->descramble(
                (ScramblingControl)scramblingControl,
                subSamplesVec,
                mObj->mDescramblerSrcBuffer,
                0,
                dstBuffer,
                0,
                [&status, &bytesWritten, &hidlDetailedError] (
                        Status _status, uint32_t _bytesWritten,
                        const hidl_string& _detailedError) {
                    status = _status;
                    *bytesWritten = _bytesWritten;
                    hidlDetailedError = _detailedError;
                });

        if (!err.isOk()) {
            ALOGE("%s: %s!", __FUNCTION__, hidlDetailedError.c_str());
            returnStatus = AMEDIA_CAS_DECRYPT_ERROR;
            goto clean_up;
        }

        if (status == Status::OK) {
            if (*bytesWritten > 0 && (ssize_t) *bytesWritten <= totalLength) {
                memcpy((void*)((uint8_t*)dstPtr + dstOffset), mObj->mMem->pointer(), *bytesWritten);
            } else {
                // status seems OK but bytesWritten is invalid, we really
                // have no idea what is wrong.
                ALOGE("%s: Mismatch of number of bytes written and what was expected!", __FUNCTION__);
                status = Status::ERROR_CAS_UNKNOWN;
            }
        }
        returnStatus = translateStatus(status);
    }
    clean_up:
        delete[] numClearData;
        delete[] numEncryptData;
        return returnStatus;
}

} // extern "C"
