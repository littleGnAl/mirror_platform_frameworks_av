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

#include "CommonResourceModel.h"
#include "ResourceManagerServiceUtils.h"

namespace android {

bool CommonResourceModel::getClients(
    const ReclaimRequestInfo& requestInfo,
    std::vector<std::pair<int32_t, uid_t>>* idVector,
    std::vector<std::shared_ptr<IResourceManagerClient>>* clients) {

    ResourceRequestInfo resourceInfo{requestInfo.mCallingPid,
                                     nullptr};

    if (requestInfo.mResources.size() > 1) {
        // No secure/non-secure codec conflict, run second pass to handle other resources.
        MediaResourceParcel mediaResource{.type = requestInfo.mResources[1].type,
                                          .subType = requestInfo.mResources[1].subType};
        resourceInfo.mResource = &mediaResource;
        mService->getClientForResource_l(resourceInfo, idVector, clients);
    }
    if (clients->empty()) {
        // Since we couldn't find the client to reclaim from, free one codec with the same type.
        MediaResourceParcel mediaResource{.type = requestInfo.mResources[0].type,
                                          .subType = requestInfo.mResources[0].subType};
        resourceInfo.mResource = &mediaResource;
        mService->getClientForResource_l(resourceInfo, idVector, clients);
    }

    if (clients->empty()) {
        // Since we couldn't find the client to reclaim from, free one codec with
        // the different type.
        MediaResourceType otherType =
            (requestInfo.mResources[0].type == MediaResource::Type::kSecureCodec) ?
            MediaResource::Type::kNonSecureCodec : MediaResource::Type::kSecureCodec;
        MediaResourceParcel mediaResource{.type = otherType,
                                          .subType = requestInfo.mResources[0].subType};
        resourceInfo.mResource = &mediaResource;
        mService->getClientForResource_l(resourceInfo, idVector, clients);
    }

    return !clients->empty();
}

} // namespace android
