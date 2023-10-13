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

#include "ResourceModelSecureCodecCoexistence.h"
#include "ResourceManagerServiceUtils.h"

namespace android {

bool ResourceModelSecureCodecCoexistence::getClients(
        const ReclaimRequestInfo& requestInfo,
        std::vector<std::pair<int32_t, uid_t>>* idVector,
        std::vector<std::shared_ptr<IResourceManagerClient>>* clients) {

    MediaResourceParcel mediaResource{.type = requestInfo.mResources[0].type,
                                      .subType = requestInfo.mResources[0].subType};
    ResourceRequestInfo resourceInfo{requestInfo.mCallingPid,
                                     &mediaResource};
    switch (requestInfo.mResources[0].type) {
    case MediaResource::Type::kSecureCodec:
        // Looking to start a secure codec.
        // #1. Make sure if multiple secure codecs can coexist
        if (!mSupportsMultipleSecureCodecs) {
            if (!mService->getAllClients_l(resourceInfo, idVector, clients)) {
                // A higher priority process owns an instance of a secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        // #2. Make sure a secure codec can coexist if there is an instance
        // of non-secure codec running already.
        if (!mSupportsSecureWithNonSecureCodec) {
            mediaResource.type = MediaResource::Type::kNonSecureCodec;
            if (!mService->getAllClients_l(resourceInfo, idVector, clients)) {
                // A higher priority process owns an instance of a non-secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        break;
    case MediaResource::Type::kNonSecureCodec:
        // Looking to start a non-secure codec.
        // Make sure a non-secure codec can coexist if there is an instance
        // of secure codec running already.
        if (!mSupportsSecureWithNonSecureCodec) {
            mediaResource.type = MediaResource::Type::kSecureCodec;
            if (!mService->getAllClients_l(resourceInfo, idVector, clients)) {
                // A higher priority process owns an instance of a secure codec.
                // So this request can't be fulfilled.
                return false;
            }
        }
        break;
    default:
        break;
    }

    return true;
}

} // namespace android
