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

#ifndef ANDROID_MEDIA_RESOURCEMODELINTERFACE_H_
#define ANDROID_MEDIA_RESOURCEMODELINTERFACE_H_

#include <memory>
#include <vector>

#include <aidl/android/media/IResourceManagerClient.h>
#include <aidl/android/media/MediaResourceParcel.h>

namespace android {

/*
 * Resource Reclaim request info that encapsulates
 *  - the calling/requesting process pid.
 *  - the resources requesting (to be reclaimed from others)
 */
struct ReclaimRequestInfo {
    int mCallingPid = -1;
    const std::vector<::aidl::android::media::MediaResourceParcel>& mResources;
};

/*
 * Resource request info that encapsulates
 *  - the calling/requesting process pid.
 *  - the resource requesting (to be reclaimed from others)
 */
struct ResourceRequestInfo {
    int mCallingPid = -1;
    const ::aidl::android::media::MediaResourceParcel* mResource;
};

/*
 * Interface that defines Resource Model.
 *
 * This provides an interface to select/identify client(s) based on a specific
 * Resource Model.
 */
class ResourceModelInterface {
public:
    ResourceModelInterface() {}

    virtual ~ResourceModelInterface() {}

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
    virtual bool getClients(const ReclaimRequestInfo& requestInfo,
                            std::vector<std::pair<int32_t, uid_t>>* idVector,
                            std::vector<std::shared_ptr<::aidl::android::media::
                                        IResourceManagerClient>>* clients) = 0;
};

} // namespace android

#endif  // ANDROID_MEDIA_RESOURCEMODELINTERFACE_H_
