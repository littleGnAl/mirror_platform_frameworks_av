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

#ifndef ANDROID_MEDIA_RESOURCETRACKER_H_
#define ANDROID_MEDIA_RESOURCETRACKER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <media/MediaResource.h>
#include <aidl/android/media/ClientInfoParcel.h>
#include <aidl/android/media/IResourceManagerClient.h>
#include <aidl/android/media/MediaResourceParcel.h>

#include "ResourceManagerServiceUtils.h"

namespace android {

class DeathNotifier;
class ResourceManagerServiceNew;
class ResourceObserverService;
struct ProcessInfoInterface;
struct ResourceRequestInfo;
struct ClientInfo;

/*
 * ResourceTracker abstracts the resources managed nby the ResourceManager.
 * It keeps track of the resource used by the clients (clientid) and by the process (pid)
 */
class ResourceTracker {
public:
    ResourceTracker(const std::shared_ptr<ResourceManagerServiceNew>& service,
                    const sp<ProcessInfoInterface>& processInfo);
    ~ResourceTracker();

    // Add a set of resources to the given client.
    // returns true on success, false otherwise.
    bool addResource(const aidl::android::media::ClientInfoParcel& clientInfo,
                     const std::shared_ptr<::aidl::android::media::IResourceManagerClient>& client,
                     const std::vector<::aidl::android::media::MediaResourceParcel>& resources);

    // Remove a set of resources from the given client.
    // returns true on success, false otherwise.
    bool removeResource(const aidl::android::media::ClientInfoParcel& clientInfo,
                        const std::vector<::aidl::android::media::MediaResourceParcel>& resources);

    // Remove all the resources from the given client.
    // returns true on success, false otherwise.
    bool removeResource(const aidl::android::media::ClientInfoParcel& clientInfo, bool checkValid);

    // Mark the client for pending removal.
    // Such clients are primary candidate for reclaim.
    // returns true on success, false otherwise.
    bool markClientForPendingRemoval(const aidl::android::media::ClientInfoParcel& clientInfo);

    // Get a list of clients that belong to process with given pid and are maked to be
    // pending removal by markClientForPendingRemoval.
    // returns true on success, false otherwise.
    bool getClientsMarkedPendingRemoval(int32_t pid, std::vector<ClientInfo>& targetClients);

    // Override the pid of originalPid with newPid
    // To remove the pid entry from the override list, set newPid as -1
    // returns true on successful override, false otherwise.
    bool overridePid(int originalPid, int newPid);

    // Override the process info {state, oom score} of the process with pid.
    // returns true on success, false otherwise.
    bool overrideProcessInfo(
        const std::shared_ptr<aidl::android::media::IResourceManagerClient>& client,
        int pid, int procState, int oomScore);

    // Remove the overridden process info.
    void removeProcessInfoOverride(int pid);

    // Find all clients that have given resources.
    // returns true on success, false otherwise.
    bool getAllClients(const ResourceRequestInfo& resourceRequestInfo,
                       std::vector<ClientInfo>& clients);

    // Look for the lowest priority process with the given resources
    // returns true on success, false otherwise.
    bool getLowestPriorityPid(MediaResource::Type type, MediaResource::SubType subType,
                              int& lowestPriorityPid, int& lowestPriority);

    // Find the biggest client of the given process with given resources.
    // returns true on success, false otherwise.
    bool getBiggestClient(int pid, MediaResource::Type type, MediaResource::SubType subType,
                          ClientInfo& clientInfo, bool pendingRemovalOnly = false);

    // Find the client that belongs to given process(pid) and with the given clientId.
    std::shared_ptr<::aidl::android::media::IResourceManagerClient> getClient(
        int pid, const int64_t& clientId) const;

    // Removes the client from the given process(pid) with the given clientId.
    // returns true on success, false otherwise.
    bool removeClient(int pid, const int64_t& clientId);

    // Set the resource observer service, to which to notify when the resources
    // are added and removed.
    void setResourceObserverService(
        const std::shared_ptr<ResourceObserverService>& observerService);

    // Dump all the resource allocations for all the processes into a given string
    void dump(std::string& resourceLogs);

    // get the priority of the process.
    bool getPriority(int pid, int* priority);

    // Check if the given resource request has a conflicting clients.
    // If they can be successfully resolved, add them to the list of clients
    // Else, return false.
    bool getNonConflictingClients(const ResourceRequestInfo& resourceRequestInfo,
                                  std::vector<ClientInfo>& clients);

    // Returns unmodifiable reference to the resource map.
    const std::map<int, ResourceInfos>& getResourceMap() const {
        return mMap;
    }

private:
    // Create/Get ResourceInfos associated with the given process.
    ResourceInfos& getResourceInfosForEdit(int pid);

    // A helper function that returns true if the callingPid has higher priority than pid.
    // Returns false otherwise.
    bool isCallingPriorityHigher(int callingPid, int pid);

    // Notify when a resource is added for the first time.
    void onFirstAdded(const MediaResourceParcel& resource, uid_t uid);
    // Notify when a resource is removed for the last time.
    void onLastRemoved(const MediaResourceParcel& resource, uid_t uid);

private:
    // Structure that defines process info that needs to be overridden.
    struct ProcessInfoOverride {
        std::shared_ptr<DeathNotifier> deathNotifier = nullptr;
        std::shared_ptr<::aidl::android::media::IResourceManagerClient> client;
    };

    // Map of Resource information indexed through the process id.
    std::map<int, ResourceInfos> mMap;
    // A weak reference (to avoid cyclic dependency) to the ResourceManagerService.
    // ResourceTracker uses this to communicate back with the ResourceManagerService.
    std::weak_ptr<ResourceManagerServiceNew> mService;
    // To notify the ResourceObserverService abour resources are added or removed.
    std::shared_ptr<ResourceObserverService> mObserverService;
    // Map of pid and their overrided id.
    std::map<int, int> mOverridePidMap;
    // Map of pid and their overridden process info.
    std::map<pid_t, ProcessInfoOverride> mProcessInfoOverrideMap;
    // Interface that gets process specific information.
    sp<ProcessInfoInterface> mProcessInfo;
};

} // namespace android

#endif // ANDROID_MEDIA_RESOURCETRACKER_H_
