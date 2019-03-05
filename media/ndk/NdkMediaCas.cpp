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
#define LOG_TAG "NdkMediaCas"

#include <media/NdkMediaCas.h>

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/StrongPointer.h>
#include <gui/Surface.h>

#include <utils/List.h>
#include <media/stagefright/MediaErrors.h>
#include <binder/IServiceManager.h>
#include <media/NdkMediaCrypto.h>

#include "NdkMediaCasPriv.h"

using namespace android;
using hardware::hidl_vec;
using hardware::Return;
using ::android::hardware::Void;
using namespace hardware::cas::V1_0;

extern "C" {

sp<IMediaCasService> AMediaCas::mCasService = NULL;

void AMediaCas::BlockingQueue::push(AMediaCas::CasEventMsg const& value) {
    {
        std::unique_lock<std::mutex> lock(this->d_mutex);
        d_queue.push_front(value);
    }
    this->d_condition.notify_one();
}

AMediaCas::CasEventMsg AMediaCas::BlockingQueue::pop() {
    std::unique_lock<std::mutex> lock(this->d_mutex);
    this->d_condition.wait(lock, [=]{ return !this->d_queue.empty(); });
    AMediaCas::CasEventMsg rc(std::move(this->d_queue.back()));
    this->d_queue.pop_back();
    return rc;
}

int AMediaCas::BlockingQueue::size() {
    return d_queue.size();
}

AMediaCas::AMediaCas(const int32_t CA_system_id) : mListener(NULL), mEventHandler(NULL), mCasClient(new NdkMediaCasListener(this)), mValidity(true) {
    if (mCasService == NULL) {
        sp<IMediaCasService> casService = IMediaCasService::getService("default");
        if (casService == NULL) {
            ALOGE("%s: Default MediaCasService not available!", __FUNCTION__);
             mValidity = false;
             return;
        } else {
            mCasService = casService;
        }
    }

    mCas = mCasService->createPlugin(CA_system_id, mCasClient );
    if(mCas == NULL) {
        mValidity = false;
        ALOGE("%s: Failed to create plugin, unsupported CA system id!", __FUNCTION__);
    }

}

AMediaCas::~AMediaCas() {
    mValidity = false;
    if (mCas != NULL) {
//      mCas->destroyPlugin(); There is no implementation
        mCas.clear();
    }

    mListener = NULL;

    CasEventMsg msg;
    msg.event = -1;
    msg.arg   = -1;
    msg.data  = NULL;
    mBlockingQueue.push(msg);

    mEventHandler->join();
    delete mEventHandler;
    mEventHandler = NULL;
}

Return<void> AMediaCas::NdkMediaCasListener::onEvent(int32_t event, int32_t arg, const hidl_vec<uint8_t>& data) {
    CasEventMsg msg;
    msg.event = event;
    msg.arg   = arg;
    msg.data  = data;

    mMediaCas->mBlockingQueue.push(msg);

    return Void();
}

bool AMediaCas::findId(const AMediaCasByteArray &id, List<hidl_vec<uint8_t>>::iterator &iter) {
    for (iter = mIds.begin(); iter != mIds.end(); ++iter) {
        if (iter->data() == id.ptr && iter->size() == id.length) {
            return true;
        }
    }
    return false;
}

void AMediaCas::eventHandlerFct() {
    AMediaCasByteArray CasArray;

    while(true) {
        CasEventMsg msg = mBlockingQueue.pop();
        if (msg.arg == -1 && msg.event == -1) break;

        if (mListener) {
            CasArray.ptr = msg.data.data();
            CasArray.length = msg.data.size();
            mListener->onCasEvent(msg.event, &CasArray);
        }
    }
}

bool AMediaCas::isSystemIdSupported(const int32_t CA_system_id) {
    if (mCasService == NULL) {
        sp<IMediaCasService> casService = IMediaCasService::getService("default");
        if (casService == NULL) {
            ALOGE("%s: Default MediaCasService not available!", __FUNCTION__);
            return false;
        } else {
            mCasService = casService;
        }
    }
    return mCasService->isSystemIdSupported(CA_system_id);
}

hidl_vec<HidlCasPluginDescriptor> AMediaCas::enumeratePlugins() {
    hidl_vec<HidlCasPluginDescriptor> vCasPluginDescs;

    if (mCasService == NULL) {
        sp<IMediaCasService> casService = IMediaCasService::getService("default");
        if (casService == NULL) {
            ALOGE("%s: Default MediaCasService not available!", __FUNCTION__);
            return false;
        } else {
            mCasService = casService;
        }
    }

    auto returnVoid = mCasService->enumeratePlugins(
    [&vCasPluginDescs] (const hidl_vec<HidlCasPluginDescriptor>& _casPluginDescs) {
                vCasPluginDescs = _casPluginDescs;
            });

    return vCasPluginDescs;
}

media_status_t AMediaCas::setListener(AMediaCas_EventListener *listener) {
    mListener = listener;

    if (mEventHandler == NULL) {
        mEventHandler = new std::thread(&AMediaCas::eventHandlerFct, this);
        if (mEventHandler == NULL) {
            return AMEDIA_ERROR_UNKNOWN;
        }
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::setPrivateData(const AMediaCasData* privateData) {
    hidl_vec<uint8_t> vPrivData;
    vPrivData.setToExternal((uint8_t*)privateData->ptr, privateData->length);
    Status status = mCas->setPrivateData(vPrivData);
    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::openSession(AMediaCasSessionId *sessionId) {
    Status status;
    hidl_vec<uint8_t> vSessionId;

    auto returnVoid = mCas->openSession(
    [&status, &vSessionId] (Status _status, const hidl_vec<uint8_t>& _sessionId) {
                status = _status;
                vSessionId = _sessionId;
            });

    if (!returnVoid.isOk() || status != Status::OK) {
        return AMEDIA_ERROR_UNKNOWN;
    }

    mIds.push_front(vSessionId);
    List<hidl_vec<uint8_t>>::iterator iter = mIds.begin();
    sessionId->ptr = iter->data();
    sessionId->length = iter->size();

    return AMEDIA_OK;
}

media_status_t AMediaCas::closeSession(const AMediaCasSessionId* sessionId) {
    Status status;
    List<hidl_vec<uint8_t>>::iterator iter;

    if (!findId(*sessionId, iter)) {
        return AMEDIA_DRM_SESSION_NOT_OPENED;
    }
    status = mCas->closeSession(*iter);
    mIds.erase(iter);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::setSessionPrivateData(const AMediaCasSessionId* sessionId, const AMediaCasData* privateData) {
    Status status;
    List<hidl_vec<uint8_t>>::iterator iter;

    if (!findId(*sessionId, iter)) {
        return AMEDIA_DRM_SESSION_NOT_OPENED;
    }

    hidl_vec<uint8_t> vPrivData;
    vPrivData.setToExternal((uint8_t*)privateData->ptr, privateData->length);
    status = mCas->setSessionPrivateData(*iter, vPrivData);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::processEcm(const AMediaCasSessionId* sessionId, const AMediaCasEcm* ecm) {
    Status status;
    List<hidl_vec<uint8_t>>::iterator iter;

    if (!findId(*sessionId, iter)) {
        return AMEDIA_DRM_SESSION_NOT_OPENED;
    }

    hidl_vec<uint8_t> vEcm;
    vEcm.setToExternal((uint8_t*)ecm->ptr, ecm->length);
    status = mCas->processEcm(*iter, vEcm);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::processEmm(const AMediaCasEmm* emm) {
    Status status;
    hidl_vec<uint8_t> vEmm;

    vEmm.setToExternal((uint8_t*)emm->ptr, emm->length);
    status = mCas->processEmm(vEmm);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::sendEvent(int32_t event, int32_t arg, const AMediaCasData* eventData) {
    Status status;
    hidl_vec<uint8_t> vEventData;

    vEventData.setToExternal((uint8_t*)eventData->ptr, eventData->length);
    status = mCas->sendEvent(event, arg, vEventData);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::provision(const char* provisionString) {
    Status status;

    status = mCas->provision(android::hardware::hidl_string(provisionString));

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

media_status_t AMediaCas::refreshEntitlements(int32_t refreshType, const AMediaCasData* refreshData) {
    Status status;
    hidl_vec<uint8_t> vRefreshData;

    vRefreshData.setToExternal((uint8_t*)refreshData->ptr, refreshData->length);
    status = mCas->refreshEntitlements(refreshType, vRefreshData);

    if(status != Status::OK)
    {
        return AMEDIA_ERROR_UNKNOWN;
    }
    return AMEDIA_OK;
}

EXPORT
const AMediaCasPluginDescriptorArray* AMediaCas_enumeratePlugins(void) {
    ALOGV("%s", __FUNCTION__);
    hidl_vec<HidlCasPluginDescriptor> hidlPluginArray = AMediaCas::enumeratePlugins();

    if (hidlPluginArray.size() == 0) {
        return NULL;
    }

    AMediaCasPluginDescriptorArray* retArray = new AMediaCasPluginDescriptorArray();
    AMediaCasPluginDescriptor* descriptors = new AMediaCasPluginDescriptor[hidlPluginArray.size()];

    retArray->descriptors = descriptors;
    retArray->length      = hidlPluginArray.size();

    for (uint32_t i = 0; i < hidlPluginArray.size(); ++i) {
        descriptors[i].CA_system_name = (char*)malloc(strlen(hidlPluginArray[i].name.c_str()));
        memcpy(descriptors[i].CA_system_name, (const void*)hidlPluginArray[i].name.c_str(), strlen(hidlPluginArray[i].name.c_str()));

        descriptors[i].CA_system_id = hidlPluginArray[i].caSystemId;
    }
    return retArray;
}

EXPORT
void AMediaCas_releasePluginsArray(const AMediaCasPluginDescriptorArray* mediaArray) {
    ALOGV("%s", __FUNCTION__);
    if (mediaArray == NULL) {
        return;
    }
    AMediaCasPluginDescriptorArray* array = (AMediaCasPluginDescriptorArray*)mediaArray;
    if (array->descriptors != NULL) {
        for (uint32_t i = 0; i < array->length; ++i) {
            if (array->descriptors[i].CA_system_name != NULL) {
                free(array->descriptors[i].CA_system_name);
                array->descriptors[i].CA_system_name = NULL;
            }
            array->descriptors[i].CA_system_id = -1;
        }
        free(array->descriptors);
        array->descriptors = NULL;
        array->length = 0;
    }
}


EXPORT
bool AMediaCas_isSystemIdSupported(const int32_t CA_system_id) {
    ALOGV("%s", __FUNCTION__);  
    return AMediaCas::isSystemIdSupported(CA_system_id);
}

EXPORT
media_status_t AMediaCas_setEventListener(AMediaCas* mediaCas, AMediaCas_EventListener* listener) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || listener == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->setListener(listener);
}

EXPORT
AMediaCas* AMediaCas_createByID(const int32_t CA_system_id) {
    ALOGV("%s", __FUNCTION__);
    AMediaCas* mediaCas = new AMediaCas(CA_system_id);
    if (mediaCas->isValid()) {
        return mediaCas;
    } else {
        return NULL;
    }
}

EXPORT
media_status_t AMediaCas_close(AMediaCas* mediaCas) {
    ALOGV("%s", __FUNCTION__);
    if(mediaCas == NULL) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    delete mediaCas;
    return AMEDIA_OK;
}

EXPORT
media_status_t AMediaCas_setPrivateData(AMediaCas* mediaCas, const AMediaCasData* privateData) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (privateData == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->setPrivateData(privateData);
}

EXPORT
media_status_t AMediaCas_openSession(AMediaCas* mediaCas, /*out*/AMediaCasSessionId *sessionId) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (sessionId == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->openSession(sessionId);
}

EXPORT
media_status_t AMediaCas_closeSession(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (sessionId == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->closeSession(sessionId);
}

EXPORT
media_status_t AMediaCas_setSessionPrivateData(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId, const AMediaCasData* privateData) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (sessionId == NULL || privateData == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->setSessionPrivateData(sessionId, privateData);
}

EXPORT
media_status_t AMediaCas_processEcm(AMediaCas* mediaCas, const AMediaCasSessionId* sessionId, const AMediaCasEcm* ecm) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (sessionId == NULL || ecm == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->processEcm(sessionId, ecm);
}

EXPORT
media_status_t AMediaCas_processEmm(AMediaCas *mediaCas, const AMediaCasEmm* emm) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (emm == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->processEmm(emm);
}

EXPORT
media_status_t AMediaCas_sendEvent(AMediaCas *mediaCas, int32_t event, int32_t arg, const AMediaCasData* eventData) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (eventData == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->sendEvent(event, arg, eventData);
}

EXPORT
media_status_t AMediaCas_provision(AMediaCas *mediaCas, const char* provisionString) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (provisionString == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->provision(provisionString);
}

EXPORT
media_status_t AMediaCas_refreshEntitlements(AMediaCas *mediaCas, int32_t refreshType, const AMediaCasData* refreshData) {
    ALOGV("%s", __FUNCTION__);
    if (mediaCas == NULL || !mediaCas->isValid()) {
        return AMEDIA_ERROR_INVALID_OBJECT;
    }
    if (refreshData == NULL) {
        return AMEDIA_ERROR_INVALID_PARAMETER;
    }
    return mediaCas->refreshEntitlements(refreshType, refreshData);
}

} // extern "C"
