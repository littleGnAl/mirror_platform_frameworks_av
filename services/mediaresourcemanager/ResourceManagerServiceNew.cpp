/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerServiceNew"
#include <utils/Log.h>
#include <binder/IPCThreadState.h>
#include <mediautils/ProcessInfo.h>

#include "DefaultResourceModel.h"
#include "ResourceManagerServiceNew.h"
#include "ResourceTracker.h"
#include "ServiceLog.h"

namespace android {

ResourceManagerServiceNew::ResourceManagerServiceNew(
        const sp<ProcessInfoInterface>& processInfo,
        const sp<SystemCallbackInterface>& systemResource) :
  ResourceManagerService(processInfo, systemResource) {}

ResourceManagerServiceNew::~ResourceManagerServiceNew() {}

void ResourceManagerServiceNew::init() {
    // Create the Resource Tracker
    mResourceTracker = std::make_shared<ResourceTracker>(ref<ResourceManagerServiceNew>(),
                                                         mProcessInfo);
    setUpResourceModels();
}

void ResourceManagerServiceNew::setUpResourceModels() {
    // Create/Configure the default resource model.
    if (mDefaultResourceModel == nullptr) {
        mDefaultResourceModel = std::make_unique<DefaultResourceModel>(
                mResourceTracker,
                mSupportsMultipleSecureCodecs,
                mSupportsSecureWithNonSecureCodec);
    } else {
        DefaultResourceModel* resourceModel =
            static_cast<DefaultResourceModel*>(mDefaultResourceModel.get());
        resourceModel->config(mSupportsMultipleSecureCodecs, mSupportsSecureWithNonSecureCodec);
    }
}

Status ResourceManagerServiceNew::config(const std::vector<MediaResourcePolicyParcel>& policies) {
    Status status = ResourceManagerService::config(policies);
    // Change in the config dictates update to the resource model.
    setUpResourceModels();
    return status;
}

void ResourceManagerServiceNew::setObserverService(
        const std::shared_ptr<ResourceObserverService>& observerService) {
    ResourceManagerService::setObserverService(observerService);
    mResourceTracker->setResourceObserverService(observerService);
}

Status ResourceManagerServiceNew::addResource(
        const ClientInfoParcel& clientInfo,
        const std::shared_ptr<IResourceManagerClient>& client,
        const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("addResource(pid %d, uid %d clientId %lld, resources %s)",
            pid, uid, (long long) clientId, getString(resources).c_str());
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    mResourceTracker->addResource(clientInfo, client, resources);
    notifyResourceGranted(pid, resources);

    return Status::ok();
}

Status ResourceManagerServiceNew::removeResource(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("removeResource(pid %d, uid %d clientId %lld, resources %s)",
            pid, uid, (long long) clientId, getString(resources).c_str());
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    mResourceTracker->removeResource(clientInfo, resources);
    return Status::ok();
}

Status ResourceManagerServiceNew::removeClient(const ClientInfoParcel& clientInfo) {
    removeResource(clientInfo, true /*checkValid*/);
    return Status::ok();
}

Status ResourceManagerServiceNew::removeResource(const ClientInfoParcel& clientInfo,
                                                 bool checkValid) {
    int32_t pid = clientInfo.pid;
    int32_t uid = clientInfo.uid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format("removeResource(pid %d, uid %d clientId %lld)",
            pid, uid, (long long) clientId);
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    if (mResourceTracker->removeResource(clientInfo, checkValid)) {
        notifyClientReleased(clientInfo);
    }
    return Status::ok();
}

Status ResourceManagerServiceNew::reclaimResource(
        const ClientInfoParcel& clientInfo,
        const std::vector<MediaResourceParcel>& resources,
        bool* _aidl_return) {
    return ResourceManagerService::reclaimResource(clientInfo, resources, _aidl_return);
}

bool ResourceManagerServiceNew::overridePid_l(int32_t originalPid, int32_t newPid) {
    return mResourceTracker->overridePid(originalPid, newPid);
}

Status ResourceManagerServiceNew::overridePid(int originalPid, int newPid) {
    return ResourceManagerService::overridePid(originalPid, newPid);
}

bool ResourceManagerServiceNew::overrideProcessInfo_l(
        const std::shared_ptr<IResourceManagerClient>& client,
        int pid,
        int procState,
        int oomScore) {
    return mResourceTracker->overrideProcessInfo(client, pid, procState, oomScore);
}

Status ResourceManagerServiceNew::overrideProcessInfo(
        const std::shared_ptr<IResourceManagerClient>& client,
        int pid,
        int procState,
        int oomScore) {
    return ResourceManagerService::overrideProcessInfo(client, pid, procState, oomScore);
}

void ResourceManagerServiceNew::removeProcessInfoOverride(int pid) {
    std::scoped_lock lock{mLock};

    mResourceTracker->removeProcessInfoOverride(pid);
}

Status ResourceManagerServiceNew::markClientForPendingRemoval(const ClientInfoParcel& clientInfo) {
    int32_t pid = clientInfo.pid;
    int64_t clientId = clientInfo.id;
    String8 log = String8::format(
            "markClientForPendingRemoval(pid %d, clientId %lld)",
            pid, (long long) clientId);
    mServiceLog->add(log);

    std::scoped_lock lock{mLock};
    mResourceTracker->markClientForPendingRemoval(clientInfo);
    return Status::ok();
}

Status ResourceManagerServiceNew::reclaimResourcesFromClientsPendingRemoval(int32_t pid) {
    String8 log = String8::format("reclaimResourcesFromClientsPendingRemoval(pid %d)", pid);
    mServiceLog->add(log);

    std::vector<ClientInfo> targetClients;
    {
        std::scoped_lock lock{mLock};
        mResourceTracker->getClientsMarkedPendingRemoval(pid, targetClients);
    }

    if (!targetClients.empty()) {
        reclaimUnconditionallyFrom(targetClients);
    }
    return Status::ok();
}

Status ResourceManagerServiceNew::notifyClientCreated(const ClientInfoParcel& clientInfo) {
    return ResourceManagerService::notifyClientCreated(clientInfo);
}

Status ResourceManagerServiceNew::notifyClientStarted(const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientStarted(clientConfig);
}

Status ResourceManagerServiceNew::notifyClientStopped(const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientStopped(clientConfig);
}

Status ResourceManagerServiceNew::notifyClientConfigChanged(
        const ClientConfigParcel& clientConfig) {
    return ResourceManagerService::notifyClientConfigChanged(clientConfig);
}

void ResourceManagerServiceNew::getResourceDump(std::string& resourceLog) const {
    std::scoped_lock lock{mLock};
    mResourceTracker->dump(resourceLog);
}

binder_status_t ResourceManagerServiceNew::dump(int fd, const char** args, uint32_t numArgs) {
    return ResourceManagerService::dump(fd, args, numArgs);
}

bool ResourceManagerServiceNew::getTargetClients(
        int callingPid,
        const std::vector<MediaResourceParcel>& resources,
        std::vector<ClientInfo>& targetClients) {
    std::scoped_lock lock{mLock};
    if (!mProcessInfo->isPidTrusted(callingPid)) {
        pid_t actualCallingPid = IPCThreadState::self()->getCallingPid();
        ALOGW("%s called with untrusted pid %d, using actual calling pid %d", __FUNCTION__,
                callingPid, actualCallingPid);
        callingPid = actualCallingPid;
    }

    // Use the Resource Model to get a list of all the clients that hold the
    // needed/requested resources.
    ReclaimRequestInfo reclaimRequestInfo{callingPid, resources};
    std::vector<ClientInfo> clients;
    if (!mDefaultResourceModel->getAllClients(reclaimRequestInfo, clients)) {
        if (clients.empty()) {
            ALOGI("%s: There aren't any clients with given resources. Nothing to reclaim",
                  __func__);
            return false;
        }
        // Since there was a conflict, we need to reclaim all elements.
        targetClients = std::move(clients);
    } else {
        getClientForResource_l(reclaimRequestInfo, clients, targetClients);
    }
    return !targetClients.empty();
}

void ResourceManagerServiceNew::getClientForResource_l(
        const ReclaimRequestInfo& reclaimRequestInfo,
        const std::vector<ClientInfo>& clients,
        std::vector<ClientInfo>& targetClients) {
    int callingPid = reclaimRequestInfo.mCallingPid;

    // Before looking into other processes, check if we have clients marked for
    // pending removal in the same process.
    ClientInfo targetClient;
    for (const MediaResourceParcel& resource : reclaimRequestInfo.mResources) {
        if (mResourceTracker->getBiggestClientPendingRemoval(callingPid, resource.type,
                                                             resource.subType, targetClient)) {
            targetClients.emplace_back(targetClient);
            return;
        }
    }

    // Now find client(s) from a lowest priority process that has needed resources.
    ResourceRequestInfo resourceRequestInfo {callingPid, nullptr};
    for (const MediaResourceParcel& resource : reclaimRequestInfo.mResources) {
        resourceRequestInfo.mResource = &resource;
        if (getLowestPriorityBiggestClient_l(resourceRequestInfo, clients, targetClient)) {
            targetClients.emplace_back(targetClient);
            return;
        }
    }
}

// Process priority (oom score) based reclaim:
//   - Find a process with lowest priority (than that of calling process).
//   - Find the bigegst client (with required resources) from that process.
bool ResourceManagerServiceNew::getLowestPriorityBiggestClient_l(
        const ResourceRequestInfo& resourceRequestInfo,
        const std::vector<ClientInfo>& clients,
        ClientInfo& clientInfo) {
    int callingPid = resourceRequestInfo.mCallingPid;
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    MediaResource::SubType subType = resourceRequestInfo.mResource->subType;
    int lowestPriorityPid;
    int lowestPriority;
    int callingPriority;

    if (!mResourceTracker->getPriority(callingPid, &callingPriority)) {
        ALOGE("%s: can't get process priority for pid %d", __func__, callingPid);
        return false;
    }

    // Find the lowest priority process among all the clients.
    if (!mResourceTracker->getLowestPriorityPid(clients, lowestPriorityPid, lowestPriority)) {
        ALOGE("%s: can't find a process with lower priority than that of the process[%d:%d]",
              __func__, callingPid, callingPriority);
        return false;
    }

    if (lowestPriority <= callingPriority) {
        ALOGE("%s: lowest priority %d vs caller priority %d",
              __func__, lowestPriority, callingPriority);
        return false;
    }

    // Get the biggest client from this process.
    if (!mResourceTracker->getBiggestClient(lowestPriorityPid, type, subType, clientInfo)) {
        return false;
    }

    ALOGI("%s: CallingProcess(%d:%d) will reclaim from the lowestPriorityProcess(%d:%d)",
          __func__, callingPid, callingPriority, lowestPriorityPid, lowestPriority);
    return true;
}

bool ResourceManagerServiceNew::getLowestPriorityBiggestClient_l(
        const ResourceRequestInfo& resourceRequestInfo,
        ClientInfo& clientInfo) {
    //NOTE: This function is used only by the test: ResourceManagerServiceTest
    if (resourceRequestInfo.mResource == nullptr) {
        return false;
    }
    std::vector<MediaResourceParcel> resources{*resourceRequestInfo.mResource};
    ReclaimRequestInfo reclaimRequestInfo{resourceRequestInfo.mCallingPid, resources};
    std::vector<ClientInfo> clients;
    mDefaultResourceModel->getAllClients(reclaimRequestInfo, clients);
    return getLowestPriorityBiggestClient_l(resourceRequestInfo, clients, clientInfo);
}

bool ResourceManagerServiceNew::getPriority_l(int pid, int* priority) const {
    return mResourceTracker->getPriority(pid, priority);
}

bool ResourceManagerServiceNew::getLowestPriorityPid_l(
        MediaResource::Type type, MediaResource::SubType subType,
        int* lowestPriorityPid, int* lowestPriority) {
    //NOTE: This function is used only by the test: ResourceManagerServiceTest
    return mResourceTracker->getLowestPriorityPid(type, subType,
                                                  *lowestPriorityPid,
                                                  *lowestPriority);
}

bool ResourceManagerServiceNew::getAllClients_l(
        const ResourceRequestInfo& resourceRequestInfo,
        std::vector<ClientInfo>& clientsInfo) {
    //NOTE: This function is used only by the test: ResourceManagerServiceTest
    MediaResource::Type type = resourceRequestInfo.mResource->type;
    // Get the list of all clients that has requested resources.
    std::vector<ClientInfo> clients;
    mResourceTracker->getAllClients(resourceRequestInfo, clients);

    // Check is there any high priority process holding up the resources already.
    for (const ClientInfo& info : clients) {
        if (!isCallingPriorityHigher_l(resourceRequestInfo.mCallingPid, info.mPid)) {
            // some higher/equal priority process owns the resource,
            // this request can't be fulfilled.
            ALOGE("%s: can't reclaim resource %s from pid %d", __func__, asString(type), info.mPid);
            return false;
        }
        clientsInfo.emplace_back(info);
    }
    if (clientsInfo.size() == 0) {
        ALOGV("%s: didn't find any resource %s", __func__, asString(type));
    }
    return true;
}

std::shared_ptr<IResourceManagerClient> ResourceManagerServiceNew::getClient(
        int pid, const int64_t& clientId) const {
    return mResourceTracker->getClient(pid, clientId);
}

bool ResourceManagerServiceNew::removeClient(int pid, const int64_t& clientId) {
    return mResourceTracker->removeClient(pid, clientId);
}

const std::map<int, ResourceInfos>& ResourceManagerServiceNew::getResourceMap() const {
    return mResourceTracker->getResourceMap();
}

} // namespace android
