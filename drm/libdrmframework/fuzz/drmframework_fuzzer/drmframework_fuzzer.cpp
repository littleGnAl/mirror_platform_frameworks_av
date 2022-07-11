/******************************************************************************
 *
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
*/
#include <fuzzer/FuzzedDataProvider.h>
#include <binder/IMemory.h>
#include <utils/threads.h>
#include <drm/DrmManagerClient.h>
#include <string>


#include <drm/DrmInfo.h>
#include "IDrmManagerService.h"
#include "DrmManagerClientImpl.h"
#include <drm/DrmConstraints.h>
#include <drm/DrmMetadata.h>
#include <drm/DrmRights.h>
#include <drm/DrmInfoStatus.h>
#include <drm/DrmConvertedStatus.h>
#include <drm/DrmInfoRequest.h>
#include <drm/DrmSupportInfo.h>
#include <drm/DrmInfoEvent.h>


using namespace android;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int uniqueId = fdp.ConsumeIntegral<int>();
    int action = fdp.ConsumeIntegral<int>();
    String8 path(fdp.ConsumeRandomLengthString().c_str());
    String8 mimeType(fdp.ConsumeRandomLengthString().c_str());
    
    sp<DrmManagerClientImpl> drmManager = DrmManagerClientImpl::create(&uniqueId, fdp.ConsumeBool());
    drmManager->getMetadata(uniqueId, &path);
    
    drmManager->remove(uniqueId);
    
    drmManager->addClient(uniqueId);
    drmManager->removeClient(uniqueId);
    
    sp<DrmManagerClient::OnInfoListener> listener;
    drmManager->setOnInfoListener(uniqueId, listener);
    drmManager->getConstraints(uniqueId, &path, action);
    drmManager->canHandle(uniqueId, path, mimeType);
    
    
    int length = fdp.ConsumeIntegral<int>();
    int infoType = fdp.ConsumeIntegral<int>();
    
    const int Size = fdp.ConsumeIntegralInRange<uint32_t>(4, 2048);
    char* Data = (char*)malloc(Size);
    if (!Data) {
        return 0;
    }
    
    String8 key(fdp.ConsumeRandomLengthString().c_str());
    String8 value(fdp.ConsumeRandomLengthString().c_str());
    
    DrmInfoRequest* drmInfoRequest = new DrmInfoRequest(infoType, mimeType);
    drmInfoRequest->put(key, value);
    drmManager->acquireDrmInfo(uniqueId, drmInfoRequest);
    
    DrmInfo* drmInfo = new DrmInfo(infoType, DrmBuffer(Data, Size), mimeType);
    drmInfo->put(key, value);
    drmManager->processDrmInfo(uniqueId,  drmInfo);
    
    int fd = fdp.ConsumeIntegral<int>();
    drmManager->getOriginalMimeType(uniqueId, path, fd);
    drmManager->getDrmObjectType(uniqueId, path, mimeType);
    drmManager->checkRightsStatus(uniqueId, path, action);
    
    sp<DecryptHandle> handle = new DecryptHandle();
    bool reserve = fdp.ConsumeBool();
    drmManager->consumeRights(uniqueId, handle, action, reserve);
    
    int playbackStatus = fdp.ConsumeIntegral<int>();
    int64_t position = fdp.ConsumeIntegral<int64_t>();
    drmManager->setPlaybackStatus(uniqueId, handle, playbackStatus, position);
    drmManager->validateAction(uniqueId, path, action,  ActionDescription(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>()));
    
    DrmBuffer* drmBuffer = new DrmBuffer(Data, Size);
    String8 rightsPath(fdp.ConsumeRandomLengthString().c_str());
    String8 contentPath(fdp.ConsumeRandomLengthString().c_str());
    String8 accountId(fdp.ConsumeRandomLengthString().c_str());
    String8 subscriptionId(fdp.ConsumeRandomLengthString().c_str());
    
    drmManager->saveRights(uniqueId, DrmRights(*drmBuffer, mimeType), rightsPath, contentPath);
    drmManager->removeRights(uniqueId, path);
    drmManager->removeAllRights(uniqueId);
    drmManager->openConvertSession(uniqueId, mimeType);
    drmManager->convertData(uniqueId, fdp.ConsumeIntegral<int>(), drmBuffer);
    drmManager->closeConvertSession(fdp.ConsumeIntegral<int>(), fdp.ConsumeIntegral<int>());
    
    DrmSupportInfo* drmSupportInfo = new DrmSupportInfo();
    drmSupportInfo->addMimeType(mimeType);
    drmManager->getAllSupportInfo(uniqueId, &length, &drmSupportInfo);
    
    off64_t offset = fdp.ConsumeIntegral<off64_t>();
    std::string mime = fdp.ConsumeRandomLengthString();
    std::string uri = fdp.ConsumeRandomLengthString();
    off64_t len = fdp.ConsumeIntegral<off64_t>();
    drmManager->openDecryptSession(uniqueId, fd, offset, len, mime.c_str());
    drmManager->openDecryptSession(uniqueId, uri.c_str(), mime.c_str());
    sp<DecryptHandle> decryptHandle = drmManager->openDecryptSession(uniqueId, DrmBuffer(Data, Size), mimeType);
    drmManager->closeDecryptSession(uniqueId, decryptHandle);
    int decryptUnitId = fdp.ConsumeIntegral<int>();
    drmManager->initializeDecryptUnit(uniqueId, decryptHandle, decryptUnitId, drmBuffer);
    DrmBuffer* encBuffer = new DrmBuffer(Data, Size);
    DrmBuffer* decBuffer = new DrmBuffer(Data, Size);
    drmManager->decrypt(uniqueId, decryptHandle, decryptUnitId, encBuffer, &decBuffer, drmBuffer);
    drmManager->finalizeDecryptUnit(uniqueId, decryptHandle, decryptUnitId);
    ssize_t numBytes = fdp.ConsumeIntegral<ssize_t>();
    drmManager->pread(uniqueId, decryptHandle, NULL, numBytes, offset);
    String8 message(fdp.ConsumeRandomLengthString().c_str());
    drmManager->notify(DrmInfoEvent(uniqueId, fdp.ConsumeIntegral<int>(), message));
    
    return 0;
}

