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

#ifndef ANDROID_MEDIA_RESOURCEMODELSECURECODECCOEXISTENCE_H_
#define ANDROID_MEDIA_RESOURCEMODELSECURECODECCOEXISTENCE_H_

#include "ResourceManagerService.h"
#include "ResourceModelInterface.h"

namespace android {

/*
 * Implements the Resource Model that dictates the concurrent coexistance
 * of a secure codec with another instance of:
 *  - a secure codec
 *  - a non-secure codec instance
 *
 * An implementation may or may not allow this.
 */
class ResourceModelSecureCodecCoexistence : public ResourceModelInterface {
public:
    ResourceModelSecureCodecCoexistence(const std::shared_ptr<ResourceManagerService>& service,
                                        bool supportsMultipleSecureCodecs = true,
                                        bool supportsSecureWithNonSecureCodec = true) :
      mSupportsMultipleSecureCodecs(supportsMultipleSecureCodecs),
      mSupportsSecureWithNonSecureCodec(supportsSecureWithNonSecureCodec),
      mService(service) {}

    virtual ~ResourceModelSecureCodecCoexistence() {}

    /*
     * Based on the Resource Model, get a list of clients that satisfy
     * the resource reclaim request.
     *
     * @param[in]  requestInfo Information about the Reclaim request
     * @param[out] idVector list of {pid, uid} of the processes from which clients
     *             are selected
     * @param[out] clients list of clients selected (that satisfy the resource
     *             reclaim request)
     *
     * @return true on success, false otherwise
     */
    bool getClients(const ReclaimRequestInfo& requestInfo,
                    std::vector<std::pair<int32_t, uid_t>>* idVector,
                    std::vector<std::shared_ptr<IResourceManagerClient>>* clients) override;

    void config(bool supportsMultipleSecureCodecs, bool supportsSecureWithNonSecureCodec) {
        mSupportsMultipleSecureCodecs = supportsMultipleSecureCodecs;
        mSupportsSecureWithNonSecureCodec = supportsSecureWithNonSecureCodec;
    }

private:
    bool mSupportsMultipleSecureCodecs = true;
    bool mSupportsSecureWithNonSecureCodec = true;
    std::shared_ptr<ResourceManagerService> mService = nullptr;
};

} // namespace android

#endif  // ANDROID_MEDIA_RESOURCEMODELSECURECODECCOEXISTENCE_H_
